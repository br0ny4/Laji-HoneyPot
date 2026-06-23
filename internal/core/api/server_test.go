package api

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
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
	srv := NewServer(log.New("info"), st, vdb, nil, "")

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
	srv := NewServer(log.New("info"), st, vdb, nil, "")

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
	srv := NewServer(log.New("info"), nil, nil, nil, "")
	req := httptest.NewRequest("GET", "/healthz", nil)
	w := httptest.NewRecorder()
	srv.Handler().ServeHTTP(w, req)

	if w.Code != 200 {
		t.Errorf("expected 200, got %d", w.Code)
	}
}

func TestAPIVulns(t *testing.T) {
	vdb := vulndb.NewDB(log.New("info"))
	srv := NewServer(log.New("info"), nil, vdb, nil, "")

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
	srv := NewServer(log.New("info"), nil, nil, nil, "")
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
	srv := NewServer(log.New("info"), st, vdb, nil, "")

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
	srv := NewServer(log.New("info"), st, vdb, nil, "")

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

func TestCollectEndpointGET(t *testing.T) {
	st, err := store.New(":memory:")
	if err != nil {
		t.Fatalf("create store: %v", err)
	}
	defer st.Close()

	vdb := vulndb.NewDB(log.New("info"))
	srv := NewServer(log.New("info"), st, vdb, nil, "")

	req := httptest.NewRequest("GET", "/api/collect?d=%7B%22screen%22%3A%221920x1080%22%7D", nil)
	req.Header.Set("User-Agent", "Mozilla/5.0 Test")
	w := httptest.NewRecorder()
	srv.Handler().ServeHTTP(w, req)

	if w.Code != 200 {
		t.Errorf("expected 200, got %d", w.Code)
	}

	// 响应应为透明 GIF
	contentType := w.Header().Get("Content-Type")
	if contentType != "image/gif" {
		t.Errorf("expected image/gif, got %s", contentType)
	}

	// 应设置追踪 Cookie
	cookies := w.Result().Cookies()
	found := false
	for _, c := range cookies {
		if c.Name == "_hp_track" {
			found = true
			if c.MaxAge != 365*24*3600 {
				t.Errorf("expected max-age 31536000, got %d", c.MaxAge)
			}
			if !c.HttpOnly {
				t.Error("tracking cookie should be HttpOnly")
			}
		}
	}
	if !found {
		t.Error("expected _hp_track cookie to be set")
	}

	// 验证指纹数据已持久化
	fps, err := st.GetFingerprints(10)
	if err != nil {
		t.Fatalf("get fingerprints: %v", err)
	}
	if len(fps) != 1 {
		t.Errorf("expected 1 fingerprint record, got %d", len(fps))
	}
}

func TestCollectEndpointPOST(t *testing.T) {
	st, err := store.New(":memory:")
	if err != nil {
		t.Fatalf("create store: %v", err)
	}
	defer st.Close()

	vdb := vulndb.NewDB(log.New("info"))
	srv := NewServer(log.New("info"), st, vdb, nil, "")

	body := strings.NewReader(`{"canvas":"abc123","gpu":"Intel","ip":"192.168.1.1"}`)
	req := httptest.NewRequest("POST", "/api/collect", body)
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("User-Agent", "Postman/1.0")
	w := httptest.NewRecorder()
	srv.Handler().ServeHTTP(w, req)

	if w.Code != 200 {
		t.Errorf("expected 200, got %d", w.Code)
	}
}

func TestCollectEndpointEmptyData(t *testing.T) {
	st, err := store.New(":memory:")
	if err != nil {
		t.Fatalf("create store: %v", err)
	}
	defer st.Close()

	vdb := vulndb.NewDB(log.New("info"))
	srv := NewServer(log.New("info"), st, vdb, nil, "")

	req := httptest.NewRequest("GET", "/api/collect", nil)
	w := httptest.NewRecorder()
	srv.Handler().ServeHTTP(w, req)

	if w.Code != 200 {
		t.Errorf("expected 200, got %d", w.Code)
	}

	// 无数据也应持久化一条空记录
	fps, err := st.GetFingerprints(10)
	if err != nil {
		t.Fatalf("get fingerprints: %v", err)
	}
	if len(fps) != 1 {
		t.Errorf("expected 1 fingerprint record (empty), got %d", len(fps))
	}
}

func TestCollectEndpointTrackCookieReuse(t *testing.T) {
	st, err := store.New(":memory:")
	if err != nil {
		t.Fatalf("create store: %v", err)
	}
	defer st.Close()

	vdb := vulndb.NewDB(log.New("info"))
	srv := NewServer(log.New("info"), st, vdb, nil, "")

	// 第一次请求设置 Cookie
	req1 := httptest.NewRequest("GET", "/api/collect?d=first", nil)
	w1 := httptest.NewRecorder()
	srv.Handler().ServeHTTP(w1, req1)

	// 提取 tracking ID
	var trackID string
	for _, c := range w1.Result().Cookies() {
		if c.Name == "_hp_track" {
			trackID = c.Value
			break
		}
	}
	if trackID == "" {
		t.Fatal("no tracking cookie set")
	}

	// 第二次请求携带相同 Cookie
	req2 := httptest.NewRequest("GET", "/api/collect?d=second", nil)
	req2.AddCookie(&http.Cookie{Name: "_hp_track", Value: trackID})
	w2 := httptest.NewRecorder()
	srv.Handler().ServeHTTP(w2, req2)

	// 验证两条记录共享同一 tracking_id
	fps, err := st.GetFingerprints(10)
	if err != nil {
		t.Fatalf("get fingerprints: %v", err)
	}
	if len(fps) != 2 {
		t.Fatalf("expected 2 fingerprints, got %d", len(fps))
	}
	if fps[0]["tracking_id"] != trackID {
		t.Errorf("expected tracking_id %s, got %v", trackID, fps[0]["tracking_id"])
	}
}

func TestAPIKeyAuthRequired(t *testing.T) {
	st, _ := store.New(":memory:")
	defer st.Close()
	vdb := vulndb.NewDB(log.New("info"))
	srv := NewServer(log.New("info"), st, vdb, nil, "secret-key")

	// 无 API Key → 401
	req := httptest.NewRequest("GET", "/api/stats", nil)
	w := httptest.NewRecorder()
	srv.Handler().ServeHTTP(w, req)

	if w.Code != 401 {
		t.Errorf("expected 401 without API key, got %d", w.Code)
	}
}

func TestAPIKeyAuthSuccess(t *testing.T) {
	st, _ := store.New(":memory:")
	defer st.Close()
	st.RecordConnection("10.0.0.1", 8081, "HTTP", "")

	vdb := vulndb.NewDB(log.New("info"))
	srv := NewServer(log.New("info"), st, vdb, nil, "secret-key")

	// 正确 API Key → 200
	req := httptest.NewRequest("GET", "/api/stats", nil)
	req.Header.Set("X-API-Key", "secret-key")
	w := httptest.NewRecorder()
	srv.Handler().ServeHTTP(w, req)

	if w.Code != 200 {
		t.Errorf("expected 200 with valid API key, got %d: %s", w.Code, w.Body.String())
	}
}

func TestAPIKeyAuthExemptEndpoints(t *testing.T) {
	vdb := vulndb.NewDB(log.New("info"))
	srv := NewServer(log.New("info"), nil, vdb, nil, "secret-key")

	// /healthz 无需 store 或 wsHub，应豁免认证
	exemptPaths := []string{"/healthz"}
	for _, path := range exemptPaths {
		req := httptest.NewRequest("GET", path, nil)
		w := httptest.NewRecorder()
		srv.Handler().ServeHTTP(w, req)

		if w.Code == 401 {
			t.Errorf("%s should be exempt from auth, got 401", path)
		}
	}
}

func TestAPIKeyAuthExemptCollect(t *testing.T) {
	st, _ := store.New(":memory:")
	defer st.Close()
	vdb := vulndb.NewDB(log.New("info"))
	srv := NewServer(log.New("info"), st, vdb, nil, "secret-key")

	// /api/collect 需要 store，但同样豁免认证
	req := httptest.NewRequest("GET", "/api/collect?d=test", nil)
	w := httptest.NewRecorder()
	srv.Handler().ServeHTTP(w, req)

	if w.Code == 401 {
		t.Error("/api/collect should be exempt from auth, got 401")
	}
}

func TestAPIKeyAuthDisabled(t *testing.T) {
	st, _ := store.New(":memory:")
	defer st.Close()
	st.RecordConnection("10.0.0.1", 8081, "HTTP", "")

	vdb := vulndb.NewDB(log.New("info"))
	// api_key 为空 → 认证禁用
	srv := NewServer(log.New("info"), st, vdb, nil, "")

	req := httptest.NewRequest("GET", "/api/stats", nil)
	w := httptest.NewRecorder()
	srv.Handler().ServeHTTP(w, req)

	if w.Code != 200 {
		t.Errorf("expected 200 when auth disabled, got %d", w.Code)
	}
}

func TestAPIKeyWrongKey(t *testing.T) {
	st, _ := store.New(":memory:")
	defer st.Close()
	vdb := vulndb.NewDB(log.New("info"))
	srv := NewServer(log.New("info"), st, vdb, nil, "secret-key")

	req := httptest.NewRequest("GET", "/api/stats", nil)
	req.Header.Set("X-API-Key", "wrong-key")
	w := httptest.NewRecorder()
	srv.Handler().ServeHTTP(w, req)

	if w.Code != 401 {
		t.Errorf("expected 401 with wrong API key, got %d", w.Code)
	}
}

func TestAPIKeyQueryParam(t *testing.T) {
	st, _ := store.New(":memory:")
	defer st.Close()
	st.RecordConnection("10.0.0.1", 8081, "HTTP", "")

	vdb := vulndb.NewDB(log.New("info"))
	srv := NewServer(log.New("info"), st, vdb, nil, "secret-key")

	// 通过查询参数传递 API Key
	req := httptest.NewRequest("GET", "/api/stats?api_key=secret-key", nil)
	w := httptest.NewRecorder()
	srv.Handler().ServeHTTP(w, req)

	if w.Code != 200 {
		t.Errorf("expected 200 with api_key query param, got %d: %s", w.Code, w.Body.String())
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
