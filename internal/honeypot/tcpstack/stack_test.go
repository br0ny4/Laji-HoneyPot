package tcpstack

import (
	"net"
	"testing"
	"time"

	"github.com/Laji-HoneyPot/honeypot/internal/core/log"
)

func TestListenAndConnect(t *testing.T) {
	logger := log.New("debug")
	stack := New(logger)

	done := make(chan struct{})
	stack.Listen(19999, func(conn net.Conn) {
		defer conn.Close()
		buf := make([]byte, 1024)
		n, _ := conn.Read(buf)
		conn.Write([]byte("echo:" + string(buf[:n])))
		close(done)
	})
	defer stack.CloseAll()

	time.Sleep(50 * time.Millisecond)

	conn, err := net.Dial("tcp", "127.0.0.1:19999")
	if err != nil {
		t.Fatalf("dial failed: %v", err)
	}
	defer conn.Close()

	conn.Write([]byte("hello"))
	buf := make([]byte, 1024)
	n, err := conn.Read(buf)
	if err != nil {
		t.Fatalf("read failed: %v", err)
	}
	resp := string(buf[:n])
	if resp != "echo:hello" {
		t.Errorf("expected 'echo:hello', got '%s'", resp)
	}

	select {
	case <-done:
	case <-time.After(time.Second):
		t.Error("handler not called within timeout")
	}
}

func TestDuplicateListen(t *testing.T) {
	logger := log.New("info")
	stack := New(logger)

	stack.Listen(19998, func(conn net.Conn) { conn.Close() })
	defer stack.CloseAll()

	time.Sleep(30 * time.Millisecond)

	err := stack.Listen(19998, func(conn net.Conn) { conn.Close() })
	if err == nil {
		t.Error("expected error for duplicate listen")
	}
}
