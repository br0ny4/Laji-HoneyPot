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
	srv := New(logger, nil)

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
	srv := New(logger, nil)

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
	srv := New(log.New("debug"), nil)
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

func TestCountermeasureInjection(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:19999")
	if err != nil {
		t.Fatalf("listen failed: %v", err)
	}
	defer ln.Close()

	logger := log.New("debug")
	srv := New(logger, nil)

	// 注册反制回调
	triggered := false
	srv.SetCountermeasureCallback(func(path, userAgent, remoteIP string) string {
		triggered = true
		return "<script>console.log('counter')</script>"
	})

	bcCalled := false
	go func() {
		conn, _ := ln.Accept()
		srv.Handle(conn, func(remoteIP, path, userAgent string) {
			bcCalled = true
		})
	}()

	time.Sleep(30 * time.Millisecond)

	// 访问面包屑路径
	resp, err := http.Get("http://127.0.0.1:19999/admin/config.php")
	if err != nil {
		t.Fatalf("http get failed: %v", err)
	}
	defer resp.Body.Close()

	body, _ := io.ReadAll(resp.Body)
	bodyStr := string(body)

	// 面包屑回调应触发
	if !bcCalled {
		t.Error("expected breadcrumb callback to be called")
	}
	// 反制 Payload 应被注入
	if !triggered {
		t.Error("expected countermeasure callback to be called")
	}
	if !contains(bodyStr, "console.log('counter')") {
		t.Error("expected countermeasure script in response body")
	}
}

func TestNoCountermeasureOnNormalRequest(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:19998")
	if err != nil {
		t.Fatalf("listen failed: %v", err)
	}
	defer ln.Close()

	logger := log.New("debug")
	srv := New(logger, nil)
	srv.SetCountermeasureCallback(func(path, userAgent, remoteIP string) string {
		return "<script>should_not_appear</script>"
	})

	go func() {
		conn, _ := ln.Accept()
		srv.Handle(conn, nil)
	}()

	time.Sleep(30 * time.Millisecond)

	// 访问正常路径
	resp, err := http.Get("http://127.0.0.1:19998/")
	if err != nil {
		t.Fatalf("http get failed: %v", err)
	}
	defer resp.Body.Close()

	body, _ := io.ReadAll(resp.Body)
	bodyStr := string(body)

	if contains(bodyStr, "should_not_appear") {
		t.Error("countermeasure script should NOT appear on normal requests")
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
