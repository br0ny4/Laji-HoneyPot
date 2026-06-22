package redis

import (
	"bufio"
	"net"
	"strings"
	"testing"
	"time"

	"github.com/Laji-HoneyPot/honeypot/internal/core/log"
)

// helper: dial-and-handle — 启动 TCP 监听器，在 goroutine 中用 Handle 处理连接，返回客户端 conn
func dialAndHandle(t *testing.T) (*Server, net.Conn, func()) {
	t.Helper()

	logger := log.New("info")
	srv := New(logger)

	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}

	go func() {
		conn, err := ln.Accept()
		if err != nil {
			return
		}
		srv.Handle(conn)
	}()

	conn, err := net.DialTimeout("tcp", ln.Addr().String(), 3*time.Second)
	if err != nil {
		ln.Close()
		t.Fatalf("dial: %v", err)
	}

	cleanup := func() {
		conn.Close()
		ln.Close()
	}
	return srv, conn, cleanup
}

func TestRedisPING(t *testing.T) {
	_, conn, cleanup := dialAndHandle(t)
	defer cleanup()

	if _, err := conn.Write([]byte("*1\r\n$4\r\nPING\r\n")); err != nil {
		t.Fatalf("write PING: %v", err)
	}

	buf := make([]byte, 128)
	conn.SetReadDeadline(time.Now().Add(2 * time.Second))
	n, err := conn.Read(buf)
	if err != nil {
		t.Fatalf("read PONG: %v", err)
	}

	got := string(buf[:n])
	if got != "+PONG\r\n" {
		t.Errorf("expected +PONG\\r\\n, got %q", got)
	}
}

func TestRedisINFO(t *testing.T) {
	_, conn, cleanup := dialAndHandle(t)
	defer cleanup()

	if _, err := conn.Write([]byte("*1\r\n$4\r\nINFO\r\n")); err != nil {
		t.Fatalf("write INFO: %v", err)
	}

	buf := make([]byte, 4096)
	conn.SetReadDeadline(time.Now().Add(2 * time.Second))
	n, err := conn.Read(buf)
	if err != nil {
		t.Fatalf("read INFO response: %v", err)
	}

	resp := string(buf[:n])
	if !strings.HasPrefix(resp, "$") {
		t.Errorf("expected bulk string (starting with $), got %q", resp)
	}
	if !strings.Contains(resp, "redis_version:6.2.13") {
		t.Errorf("expected redis_version:6.2.13 in response, got %q", resp)
	}
}

func TestRedisAUTH(t *testing.T) {
	_, conn, cleanup := dialAndHandle(t)
	defer cleanup()

	if _, err := conn.Write([]byte("*2\r\n$4\r\nAUTH\r\n$8\r\npassword\r\n")); err != nil {
		t.Fatalf("write AUTH: %v", err)
	}

	buf := make([]byte, 128)
	conn.SetReadDeadline(time.Now().Add(2 * time.Second))
	n, err := conn.Read(buf)
	if err != nil {
		t.Fatalf("read AUTH response: %v", err)
	}

	got := strings.TrimSpace(string(buf[:n]))
	if got != "-ERR invalid password" {
		t.Errorf("expected -ERR invalid password, got %q", got)
	}
}

func TestRedisMultipleCommands(t *testing.T) {
	_, conn, cleanup := dialAndHandle(t)
	defer cleanup()

	buf := make([]byte, 4096)

	// 1. PING → PONG
	if _, err := conn.Write([]byte("*1\r\n$4\r\nPING\r\n")); err != nil {
		t.Fatalf("write PING: %v", err)
	}
	conn.SetReadDeadline(time.Now().Add(2 * time.Second))
	n, err := conn.Read(buf)
	if err != nil {
		t.Fatalf("read PONG: %v", err)
	}
	if string(buf[:n]) != "+PONG\r\n" {
		t.Errorf("PING: expected +PONG\\r\\n, got %q", string(buf[:n]))
	}

	// 2. CONFIG GET → fake config (RESP array)
	if _, err := conn.Write([]byte("*3\r\n$6\r\nCONFIG\r\n$3\r\nGET\r\n$3\r\ndir\r\n")); err != nil {
		t.Fatalf("write CONFIG GET: %v", err)
	}
	conn.SetReadDeadline(time.Now().Add(2 * time.Second))
	n, err = conn.Read(buf)
	if err != nil {
		t.Fatalf("read CONFIG GET response: %v", err)
	}
	configResp := string(buf[:n])
	if !strings.HasPrefix(configResp, "*") {
		t.Errorf("CONFIG GET: expected array response (starting with *), got %q", configResp)
	}

	// 3. FOO (unknown command) → error
	if _, err := conn.Write([]byte("*1\r\n$3\r\nFOO\r\n")); err != nil {
		t.Fatalf("write FOO: %v", err)
	}
	conn.SetReadDeadline(time.Now().Add(2 * time.Second))
	n, err = conn.Read(buf)
	if err != nil {
		t.Fatalf("read FOO response: %v", err)
	}
	fooResp := strings.TrimSpace(string(buf[:n]))
	if !strings.Contains(fooResp, "-ERR unknown command") {
		t.Errorf("FOO: expected -ERR unknown command, got %q", fooResp)
	}
}

func TestRedisRESPParsing(t *testing.T) {
	logger := log.New("info")
	srv := New(logger)

	data := "*3\r\n$3\r\nSET\r\n$3\r\nkey\r\n$5\r\nvalue\r\n"
	reader := bufio.NewReader(strings.NewReader(data))

	firstLine, err := reader.ReadString('\n')
	if err != nil {
		t.Fatalf("read first line: %v", err)
	}
	firstLine = strings.TrimSpace(firstLine)

	args := srv.readRESP(reader, firstLine)

	if len(args) != 3 {
		t.Fatalf("expected 3 args, got %d: %v", len(args), args)
	}
	if args[0] != "SET" {
		t.Errorf("args[0]: expected SET, got %q", args[0])
	}
	if args[1] != "key" {
		t.Errorf("args[1]: expected key, got %q", args[1])
	}
	if args[2] != "value" {
		t.Errorf("args[2]: expected value, got %q", args[2])
	}
}
