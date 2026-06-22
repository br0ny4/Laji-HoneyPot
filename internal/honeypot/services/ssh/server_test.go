package ssh

import (
	"bufio"
	"net"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/Laji-HoneyPot/honeypot/internal/core/log"
)

func TestSSHBanner(t *testing.T) {
	logger := log.New("error")
	server := New(logger)

	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("failed to listen: %v", err)
	}
	defer ln.Close()

	go func() {
		conn, err := ln.Accept()
		if err != nil {
			return
		}
		server.Handle(conn)
	}()

	conn, err := net.DialTimeout("tcp", ln.Addr().String(), 2*time.Second)
	if err != nil {
		t.Fatalf("failed to dial: %v", err)
	}
	defer conn.Close()

	reader := bufio.NewReader(conn)
	banner, err := reader.ReadString('\n')
	if err != nil {
		t.Fatalf("failed to read banner: %v", err)
	}

	if !strings.Contains(banner, "OpenSSH_9.3") {
		t.Errorf("expected banner to contain OpenSSH_9.3, got: %q", banner)
	}
}

func TestSSHClientBannerCapture(t *testing.T) {
	logger := log.New("error")
	server := New(logger)

	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("failed to listen: %v", err)
	}
	defer ln.Close()

	go func() {
		conn, err := ln.Accept()
		if err != nil {
			return
		}
		server.Handle(conn)
	}()

	conn, err := net.DialTimeout("tcp", ln.Addr().String(), 2*time.Second)
	if err != nil {
		t.Fatalf("failed to dial: %v", err)
	}
	defer conn.Close()

	reader := bufio.NewReader(conn)

	// Read server banner first
	_, err = reader.ReadString('\n')
	if err != nil {
		t.Fatalf("failed to read server banner: %v", err)
	}

	// Send fake client banner
	clientBanner := "SSH-2.0-OpenSSH_8.9p1 Ubuntu-3\r\n"
	_, err = conn.Write([]byte(clientBanner))
	if err != nil {
		t.Fatalf("failed to send client banner: %v", err)
	}

	// Read the "Protocol mismatch" response to confirm Handle processed the connection
	_, err = reader.ReadString('\n')
	if err != nil {
		t.Fatalf("failed to read protocol mismatch response: %v", err)
	}
}

func TestSSHMultipleConnections(t *testing.T) {
	logger := log.New("error")
	server := New(logger)

	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("failed to listen: %v", err)
	}
	defer ln.Close()

	// Goroutine to accept connections
	go func() {
		for i := 0; i < 3; i++ {
			conn, err := ln.Accept()
			if err != nil {
				return
			}
			go server.Handle(conn)
		}
	}()

	var wg sync.WaitGroup
	addr := ln.Addr().String()

	for i := 0; i < 3; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()

			conn, err := net.DialTimeout("tcp", addr, 2*time.Second)
			if err != nil {
				t.Errorf("failed to dial: %v", err)
				return
			}
			defer conn.Close()

			reader := bufio.NewReader(conn)

			// Read server banner
			_, err = reader.ReadString('\n')
			if err != nil {
				t.Errorf("failed to read server banner: %v", err)
				return
			}

			// Send client banner
			_, err = conn.Write([]byte("SSH-2.0-OpenSSH_8.9p1 Ubuntu-3\r\n"))
			if err != nil {
				t.Errorf("failed to send client banner: %v", err)
				return
			}

			// Read "Protocol mismatch" response
			resp, err := reader.ReadString('\n')
			if err != nil {
				t.Errorf("failed to read response: %v", err)
				return
			}

			if !strings.Contains(resp, "Protocol mismatch") {
				t.Errorf("expected Protocol mismatch, got: %q", resp)
			}
		}()
	}

	wg.Wait()
}
