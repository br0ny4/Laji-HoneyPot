package http

import (
	"io"
	"net"
	"net/http"
	"testing"
	"time"

	"github.com/Laji-HoneyPot/honeypot/internal/core/log"
)

func TestHTTPHoneypotRoot(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:18999")
	if err != nil {
		t.Fatalf("listen failed: %v", err)
	}
	defer ln.Close()

	logger := log.New("debug")
	srv := New(logger)

	go func() {
		conn, _ := ln.Accept()
		srv.Handle(conn, nil)
	}()

	time.Sleep(30 * time.Millisecond)

	resp, err := http.Get("http://127.0.0.1:18999/")
	if err != nil {
		t.Fatalf("http get failed: %v", err)
	}
	defer resp.Body.Close()

	body, _ := io.ReadAll(resp.Body)
	if resp.StatusCode != 200 {
		t.Errorf("expected 200, got %d", resp.StatusCode)
	}
	if resp.Header.Get("Server") != "nginx/1.24.0" {
		t.Errorf("expected nginx server header, got %s", resp.Header.Get("Server"))
	}
	if !contains(string(body), "Welcome to Nginx") {
		t.Errorf("unexpected body: %s", string(body))
	}
}

func TestAdminLoginPage(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:18998")
	if err != nil {
		t.Fatalf("listen failed: %v", err)
	}
	defer ln.Close()

	logger := log.New("debug")
	srv := New(logger)

	go func() {
		conn, _ := ln.Accept()
		srv.Handle(conn, nil)
	}()

	time.Sleep(30 * time.Millisecond)

	resp, err := http.Get("http://127.0.0.1:18998/admin/login")
	if err != nil {
		t.Fatalf("http get failed: %v", err)
	}
	defer resp.Body.Close()

	body, _ := io.ReadAll(resp.Body)
	if !contains(string(body), "Administrator Login") {
		t.Errorf("unexpected body: %s", string(body))
	}
}

func TestBreadcrumbDetection(t *testing.T) {
	srv := New(log.New("debug"))
	if !srv.isBreadcrumb("/admin/config.php") {
		t.Error("expected /admin/config.php to be breadcrumb")
	}
	if !srv.isBreadcrumb("/.git/config") {
		t.Error("expected /.git/config to be breadcrumb")
	}
	if srv.isBreadcrumb("/") {
		t.Error("root should not be breadcrumb")
	}
	if srv.isBreadcrumb("/index.html") {
		t.Error("/index.html should not be breadcrumb")
	}
}

func contains(s, substr string) bool {
	for i := 0; i <= len(s)-len(substr); i++ {
		if s[i:i+len(substr)] == substr {
			return true
		}
	}
	return false
}
