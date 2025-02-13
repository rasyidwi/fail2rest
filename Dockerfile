FROM golang:alpine AS builder

LABEL maintainer="Rasyid Dwi <rasyid at kasirpintar dot co dot id>"

# Install necessary dependencies
RUN apk add --no-cache git build-base

# Set working directory
WORKDIR /app

# Copy Go modules and download dependencies
COPY go.mod go.sum ./
RUN go mod tidy

# Copy the application source code
COPY . .

# Build the Go binary
RUN go build -o fail2rest .

# Use a minimal image for the final runtime
FROM alpine:latest
LABEL maintainer="Rasyid Dwi <rasyid at kasirpintar dot co dot id>"

# Install required dependencies
RUN apk add --no-cache ca-certificates

VOLUME /srv/fail2rest/ /var/run/fail2ban/

WORKDIR /app

COPY docker-entrypoint.sh /entrypoint.sh

# Copy the built binary from the builder stage
COPY --from=builder /app/fail2rest .
RUN ln -s /app/fail2rest /usr/bin/

# Ensure the binary is executable
RUN chmod +x /usr/bin/fail2rest

# Expose the application port
EXPOSE 5000

ENTRYPOINT ["/entrypoint.sh"]