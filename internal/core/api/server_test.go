package api

import (
	"encoding/json"
	"net/http/httptest"
	"testing"

	"github.com/Laji-HoneyPot/honeypot/internal/core/log"
	"github.com/Laji-HoneyPot/honeypot/internal/core/store"
	"github.com/Laji-HoneyPot/honeypot/internal/traceability/vulndb"
)

func TestAPIStats(t *testing.T) {
	st, err := store.New(":memory:")
	if err != nil {
		t.Fatalf("create store: %v", err)
	}
	defer st.Close()

	st.RecordConnection("10.0.0.1", 8081, "HTTP", "Mozilla/5.0")
	st.RecordConnection("10.0.0.2", 3306, "MySQL", "")

	vdb := vulndb.NewDB(log.New("info"))
	srv := NewServer(log.New("info"), st, vdb, nil)

	req := httptest.NewRequest("GET", "/api/stats", nil)
	w := httptest.NewRecorder()
	srv.Handler().ServeHTTP(w, req)

	if w.Code != 200 {
		t.Errorf("expected 200, got %d", w.Code)
	}

	var stats store.Stats
	json.Unmarshal(w.Body.Bytes(), &stats)
	if stats.TodayConns < 2 {
		t.Errorf("expected at least 2 connections, got %d", stats.TodayConns)
	}
}

func TestAPIConnections(t *testing.T) {
	st, err := store.New(":memory:")
	if err != nil {
		t.Fatalf("create store: %v", err)
	}
	defer st.Close()

	st.RecordConnection("10.0.0.1", 8081, "HTTP", "Go-http-client")
	vdb := vulndb.NewDB(log.New("info"))
	srv := NewServer(log.New("info"), st, vdb, nil)

	req := httptest.NewRequest("GET", "/api/connections?limit=10", nil)
	w := httptest.NewRecorder()
	srv.Handler().ServeHTTP(w, req)

	if w.Code != 200 {
		t.Errorf("expected 200, got %d", w.Code)
	}

	var resp struct {
		Total       int                `json:"total"`
		Connections []store.Connection `json:"connections"`
	}
	json.Unmarshal(w.Body.Bytes(), &resp)
	if resp.Total < 1 {
		t.Errorf("expected at least 1 connection, got %d", resp.Total)
	}
}

func TestAPIHealth(t *testing.T) {
	srv := NewServer(log.New("info"), nil, nil, nil)
	req := httptest.NewRequest("GET", "/healthz", nil)
	w := httptest.NewRecorder()
	srv.Handler().ServeHTTP(w, req)

	if w.Code != 200 {
		t.Errorf("expected 200, got %d", w.Code)
	}
}

func TestAPIVulns(t *testing.T) {
	vdb := vulndb.NewDB(log.New("info"))
	srv := NewServer(log.New("info"), nil, vdb, nil)

	req := httptest.NewRequest("GET", "/api/vulns", nil)
	w := httptest.NewRecorder()
	srv.Handler().ServeHTTP(w, req)

	if w.Code != 200 {
		t.Errorf("expected 200, got %d", w.Code)
	}

	var resp struct {
		Vulns []vulndb.VulnEntry `json:"vulns"`
	}
	json.Unmarshal(w.Body.Bytes(), &resp)
	if len(resp.Vulns) < 7 {
		t.Errorf("expected at least 7 vulns, got %d", len(resp.Vulns))
	}
}

func TestCORSHeaders(t *testing.T) {
	srv := NewServer(log.New("info"), nil, nil, nil)
	req := httptest.NewRequest("OPTIONS", "/api/stats", nil)
	w := httptest.NewRecorder()
	srv.Handler().ServeHTTP(w, req)

	if w.Header().Get("Access-Control-Allow-Origin") != "*" {
		t.Error("CORS header missing")
	}
}

// 确保 store.New 支持 :memory: 模式
func TestMemoryStore(t *testing.T) {
	st, err := store.New(":memory:")
	if err != nil {
		t.Fatalf("create memory store: %v", err)
	}
	defer st.Close()

	id, err := st.RecordConnection("1.2.3.4", 8080, "HTTP", "test")
	if err != nil {
		t.Fatalf("record connection: %v", err)
	}
	if id != 1 {
		t.Errorf("expected id 1, got %d", id)
	}

	_, err = st.RecordAttack("1.2.3.4", "/admin/config.php", "burpsuite", "scan")
	if err != nil {
		t.Fatalf("record attack: %v", err)
	}

	stats, _ := st.GetStats()
	if stats.TodayConns != 1 {
		t.Errorf("expected 1 conn, got %d", stats.TodayConns)
	}
	if stats.CounterHits != 1 {
		t.Errorf("expected 1 attack, got %d", stats.CounterHits)
	}
}

func TestQueryLimitClamp(t *testing.T) {
	st, _ := store.New(":memory:")
	defer st.Close()
	for i := 0; i < 5; i++ {
		st.RecordConnection("10.0.0.1", 80, "HTTP", "")
	}
	vdb := vulndb.NewDB(log.New("info"))
	srv := NewServer(log.New("info"), st, vdb, nil)

	// 请求超过上限的 limit
	req := httptest.NewRequest("GET", "/api/connections?limit=9999", nil)
	w := httptest.NewRecorder()
	srv.Handler().ServeHTTP(w, req)

	if w.Code != 200 {
		t.Errorf("expected 200, got %d", w.Code)
	}
}

func TestAPIErrorMasking(t *testing.T) {
	// API 不应该在正常响应中泄漏内部实现细节
	st, _ := store.New(":memory:")
	defer st.Close()
	vdb := vulndb.NewDB(log.New("info"))
	srv := NewServer(log.New("info"), st, vdb, nil)

	req := httptest.NewRequest("GET", "/api/stats", nil)
	w := httptest.NewRecorder()
	srv.Handler().ServeHTTP(w, req)

	if w.Code != 200 {
		t.Errorf("expected 200, got %d: %s", w.Code, w.Body.String())
	}
	// 正常响应不应包含 SQLite 内部信息
	if contains(w.Body.String(), "sqlite_master") {
		t.Error("response should not leak internal SQL details")
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
