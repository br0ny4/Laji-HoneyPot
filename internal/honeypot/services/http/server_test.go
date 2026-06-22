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

func TestActuatorEnvResponse(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:19997")
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

	resp, err := http.Get("http://127.0.0.1:19997/actuator/env")
	if err != nil {
		t.Fatalf("http get failed: %v", err)
	}
	defer resp.Body.Close()

	body, _ := io.ReadAll(resp.Body)
	bodyStr := string(body)

	if resp.StatusCode != 200 {
		t.Errorf("expected 200, got %d", resp.StatusCode)
	}
	ct := resp.Header.Get("Content-Type")
	if !contains(ct, "vnd.spring-boot.actuator") {
		t.Errorf("expected actuator content-type, got %s", ct)
	}
	if !contains(bodyStr, "spring.datasource.url") {
		t.Errorf("expected actuator env data in response, got: %s", truncate(bodyStr, 200))
	}
	if !contains(bodyStr, "AKIAIOSFODNN7EXAMPLE") {
		t.Error("expected fake AWS access key in actuator env response")
	}
}

func TestActuatorHeapdumpResponse(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:19996")
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

	resp, err := http.Get("http://127.0.0.1:19996/actuator/heapdump")
	if err != nil {
		t.Fatalf("http get failed: %v", err)
	}
	defer resp.Body.Close()

	body, _ := io.ReadAll(resp.Body)

	if resp.StatusCode != 200 {
		t.Errorf("expected 200, got %d", resp.StatusCode)
	}
	ct := resp.Header.Get("Content-Type")
	if !contains(ct, "application/octet-stream") {
		t.Errorf("expected octet-stream content-type, got %s", ct)
	}
	if !contains(string(body), "JAVA PROFILE") {
		t.Error("expected HPROF header in heapdump")
	}
	if !contains(string(body), "HoneyPot@2024") {
		t.Errorf("expected honeytoken in heapdump, got: %s", truncate(string(body), 200))
	}
}

func TestActuatorMappingsResponse(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:19995")
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

	resp, err := http.Get("http://127.0.0.1:19995/actuator/mappings")
	if err != nil {
		t.Fatalf("http get failed: %v", err)
	}
	defer resp.Body.Close()

	body, _ := io.ReadAll(resp.Body)
	bodyStr := string(body)

	if resp.StatusCode != 200 {
		t.Errorf("expected 200, got %d", resp.StatusCode)
	}
	if !contains(bodyStr, "AdminController#deleteUser") {
		t.Error("expected internal admin endpoints in mappings")
	}
	if !contains(bodyStr, "/api/internal/config/secrets") {
		t.Error("expected internal secrets endpoint in mappings")
	}
}

func TestSwaggerUIResponse(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:19994")
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

	resp, err := http.Get("http://127.0.0.1:19994/swagger-ui.html")
	if err != nil {
		t.Fatalf("http get failed: %v", err)
	}
	defer resp.Body.Close()

	body, _ := io.ReadAll(resp.Body)
	bodyStr := string(body)

	if resp.StatusCode != 200 {
		t.Errorf("expected 200, got %d", resp.StatusCode)
	}
	ct := resp.Header.Get("Content-Type")
	if !contains(ct, "text/html") {
		t.Errorf("expected text/html for swagger UI page, got %s", ct)
	}
	if !contains(bodyStr, "Swagger UI") {
		t.Error("expected Swagger UI in response")
	}
	if !contains(bodyStr, "Internal API Documentation") {
		t.Error("expected API documentation title")
	}
}

func TestSwaggerDocsResponse(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:19993")
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

	resp, err := http.Get("http://127.0.0.1:19993/v2/api-docs")
	if err != nil {
		t.Fatalf("http get failed: %v", err)
	}
	defer resp.Body.Close()

	body, _ := io.ReadAll(resp.Body)
	bodyStr := string(body)

	if resp.StatusCode != 200 {
		t.Errorf("expected 200, got %d", resp.StatusCode)
	}
	ct := resp.Header.Get("Content-Type")
	if !contains(ct, "application/json") {
		t.Errorf("expected application/json for swagger docs, got %s", ct)
	}
	if !contains(bodyStr, "Internal Service API") {
		t.Error("expected swagger API docs in response")
	}
	if !contains(bodyStr, "/api/internal/admin/users/delete") {
		t.Error("expected internal admin endpoint in swagger docs")
	}
}

func TestSwaggerResourcesResponse(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:19992")
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

	resp, err := http.Get("http://127.0.0.1:19992/swagger-resources")
	if err != nil {
		t.Fatalf("http get failed: %v", err)
	}
	defer resp.Body.Close()

	body, _ := io.ReadAll(resp.Body)
	bodyStr := string(body)

	if resp.StatusCode != 200 {
		t.Errorf("expected 200, got %d", resp.StatusCode)
	}
	if !contains(bodyStr, "default") {
		t.Error("expected default group in swagger-resources")
	}
	if !contains(bodyStr, "internal") {
		t.Error("expected internal group in swagger-resources")
	}
}

func TestNewBreadcrumbPaths(t *testing.T) {
	srv := New(log.New("debug"), nil)

	newPaths := []string{
		"/actuator/heapdump",
		"/actuator/mappings",
		"/actuator/beans",
		"/actuator/configprops",
		"/swagger-ui/index.html",
		"/v2/api-docs",
		"/swagger-resources",
	}
	for _, p := range newPaths {
		if !srv.isBreadcrumb(p) {
			t.Errorf("expected %s to be a breadcrumb", p)
		}
	}
	// sub-paths should also match
	if !srv.isBreadcrumb("/v2/api-docs?group=internal") {
		t.Error("expected /v2/api-docs?group=internal to be breadcrumb (prefix match)")
	}
}

func truncate(s string, maxLen int) string {
	if len(s) <= maxLen {
		return s
	}
	return s[:maxLen] + "..."
}
