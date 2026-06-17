FROM golang:1.22-alpine AS builder

RUN apk add --no-cache git ca-certificates

WORKDIR /src
COPY go.mod go.sum ./
RUN go mod download

COPY . .
RUN CGO_ENABLED=0 GOOS=linux go build -ldflags="-s -w" -o /honeypot ./cmd/honeypot/

FROM alpine:3.19

RUN apk add --no-cache ca-certificates tzdata && \
    adduser -D -h /app honeypot

COPY --from=builder /honeypot /app/honeypot
COPY config.yaml /app/config.yaml

USER honeypot
WORKDIR /app

EXPOSE 8080 8081 3306 6379 2222

ENTRYPOINT ["/app/honeypot"]
