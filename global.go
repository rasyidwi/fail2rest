package main

import (
	"encoding/json"
	"net/http"

	"database/sql"

	"bytes"
	"errors"
	"net"

	"github.com/gorilla/mux"
	_ "github.com/mattn/go-sqlite3"
	"github.com/sean-der/fail2go"

	ogórek "github.com/kisielk/og-rek"
)

const END_COMMAND = "<F2B_END_COMMAND>"

func (conn *Conn) fail2banRequest(input []string) (interface{}, error) {
	c, err := net.Dial("unix", conn.Fail2banSocket)

	if err != nil {
		return nil, errors.New("Failed to contact fail2ban socket")
	}

	p := &bytes.Buffer{}
	ogórek.NewEncoder(p).Encode(input)
	c.Write(p.Bytes())
	c.Write([]byte(END_COMMAND))

	buf := make([]byte, 0)
	tmpBuf := make([]byte, 1)
	for {
		bufRead, err := c.Read(tmpBuf)

		if err != nil {
			return nil, errors.New("Failed to contact fail2ban socket")
		} else if bufRead != 0 {
			buf = append(buf, tmpBuf...)
			if bytes.HasSuffix(buf, []byte(END_COMMAND)) {
				c.Close()
				break
			}
		} else {
			break
		}

	}
	buf = buf[:len(buf)-len(END_COMMAND)]

	dec := ogórek.NewDecoder(bytes.NewBuffer(buf))
	fail2banOutput, err := dec.Decode()

	if fail2banOutput != nil && err == nil {
		fail2banOutput = fail2banOutput.(ogórek.Tuple)[1]

		switch fail2banOutput.(type) {
		case ogórek.Call:
			Call := fail2banOutput.(ogórek.Call)
			return nil, errors.New(Call.Callable.Name + ": " + Call.Args[0].(string))
		}
	}

	return fail2banOutput, err
}

func (conn *Conn) GlobalDBFile() (string, error) {
	output, err := conn.fail2banRequest([]string{"get", "dbfile"})
	if err != nil {
		return "", err
	}

	return output.(string), nil
}

type Ban struct {
	Jail, IP  string
	TimeOfBan int
	Data      BanData
}

type BanData struct {
	Matches  []string
	Failures int
}

func (conn *Conn) GlobalBans() (results []Ban, err error) {
	DBFile, err := conn.GlobalDBFile()
	if err != nil {
		return nil, err
	}

	dbConn, err := sql.Open("sqlite3", DBFile)
	if err != nil {
		return nil, err
	}
	rows, err := dbConn.Query("select jail, ip, timeofban, data from bips")
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	for rows.Next() {
		var ban Ban
		var data string
		rows.Scan(&ban.Jail, &ban.IP, &ban.TimeOfBan, &data)
		json.Unmarshal([]byte(data), &ban.Data)
		results = append(results, ban)
	}
	rows.Close()

	return results, nil
}

func globalStatusHandler(res http.ResponseWriter, req *http.Request, fail2goConn *fail2go.Conn) {
	globalStatus, err := fail2goConn.GlobalStatus()
	if err != nil {
		writeHTTPError(res, err)
		return
	}

	encodedOutput, _ := json.Marshal(globalStatus)
	res.Write(encodedOutput)
}

func globalPingHandler(res http.ResponseWriter, req *http.Request, fail2goConn *fail2go.Conn) {
	globalPing, err := fail2goConn.GlobalPing()
	if err != nil {
		writeHTTPError(res, err)
		return
	}

	encodedOutput, _ := json.Marshal(globalPing)
	res.Write(encodedOutput)
}

func globalBansHandler(res http.ResponseWriter, req *http.Request, fail2goConn *fail2go.Conn) {
	globalBans, err := fail2goConn.GlobalBans()
	if err != nil {
		writeHTTPError(res, err)
		return
	}

	encodedOutput, _ := json.Marshal(globalBans)
	res.Write(encodedOutput)
}

func globalHandler(globalRouter *mux.Router, fail2goConn *fail2go.Conn) {
	globalRouter.HandleFunc("/status", func(res http.ResponseWriter, req *http.Request) {
		globalStatusHandler(res, req, fail2goConn)
	}).Methods("GET")
	globalRouter.HandleFunc("/ping", func(res http.ResponseWriter, req *http.Request) {
		globalPingHandler(res, req, fail2goConn)
	}).Methods("GET")
	globalRouter.HandleFunc("/bans", func(res http.ResponseWriter, req *http.Request) {
		globalBansHandler(res, req, fail2goConn)
	}).Methods("GET")

}
