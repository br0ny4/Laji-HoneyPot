package alerter

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"go.uber.org/zap/zaptest"
)

func TestBuildAlertEventBreadcrumb(t *testing.T) {
	payload := json.RawMessage(`{"remote_ip":"10.0.0.1","path":"/actuator/env","user_agent":"curl/7.88.1"}`)
	event := BuildAlertEvent("honeypot.breadcrumb", payload)
	if event == nil {
		t.Fatal("expected non-nil event")
	}
	if event.Type != "breadcrumb" {
		t.Errorf("Type: expected breadcrumb, got %s", event.Type)
	}
	if event.Level != "warn" {
		t.Errorf("Level: expected warn, got %s", event.Level)
	}
	if event.RemoteIP != "10.0.0.1" {
		t.Errorf("RemoteIP: expected 10.0.0.1, got %s", event.RemoteIP)
	}
	if event.Path != "/actuator/env" {
		t.Errorf("Path: expected /actuator/env, got %s", event.Path)
	}
	if !strings.Contains(event.Detail, "10.0.0.1") {
		t.Errorf("Detail should contain IP")
	}
	if !strings.Contains(event.Detail, "/actuator/env") {
		t.Errorf("Detail should contain path")
	}
}

func TestBuildAlertEventAttack(t *testing.T) {
	payload := json.RawMessage(`{"remote_ip":"192.168.1.100","path":"/admin/config.php","user_agent":"sqlmap/1.0"}`)
	event := BuildAlertEvent("honeypot.attack", payload)
	if event == nil {
		t.Fatal("expected non-nil event")
	}
	if event.Type != "attack" {
		t.Errorf("Type: expected attack, got %s", event.Type)
	}
	if event.Level != "critical" {
		t.Errorf("Level: expected critical, got %s", event.Level)
	}
	if !strings.Contains(event.Title, "攻击") {
		t.Errorf("Title should contain 攻击")
	}
}

func TestBuildAlertEventConnection(t *testing.T) {
	payload := json.RawMessage(`{"remote_ip":"1.2.3.4","service":"HTTP"}`)
	event := BuildAlertEvent("honeypot.connection", payload)
	if event == nil {
		t.Fatal("expected non-nil event")
	}
	if event.Type != "connection" {
		t.Errorf("Type: expected connection, got %s", event.Type)
	}
	if event.Level != "info" {
		t.Errorf("Level: expected info, got %s", event.Level)
	}
}

func TestBuildAlertEventPortScan(t *testing.T) {
	payload := json.RawMessage(`{"remote_ip":"5.5.5.5","ports":"80,443,8080","ports_count":3}`)
	event := BuildAlertEvent("honeypot.portscan", payload)
	if event == nil {
		t.Fatal("expected non-nil event")
	}
	if event.Type != "scan" {
		t.Errorf("Type: expected scan, got %s", event.Type)
	}
	if event.Level != "warn" {
		t.Errorf("Level: expected warn, got %s", event.Level)
	}
	if !strings.Contains(event.Title, "扫描") {
		t.Errorf("Title should contain 扫描")
	}
}

func TestBuildAlertEventUnknownTopic(t *testing.T) {
	payload := json.RawMessage(`{}`)
	event := BuildAlertEvent("unknown.topic", payload)
	if event != nil {
		t.Errorf("expected nil for unknown topic, got %+v", event)
	}
}

func TestWebhookSend(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			t.Errorf("expected POST, got %s", r.Method)
		}
		if r.Header.Get("Content-Type") != "application/json" {
			t.Errorf("expected application/json")
		}
		var body map[string]interface{}
		if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
			t.Errorf("decode body: %v", err)
		}
		if body["type"] != "attack" {
			t.Errorf("body type: expected attack, got %v", body["type"])
		}
		w.WriteHeader(200)
	}))
	defer server.Close()

	logger := zaptest.NewLogger(t).Sugar()
	a := New(logger, []ChannelConfig{
		{Type: ChannelWebhook, URL: server.URL, Enabled: true},
	})

	a.Send(AlertEvent{
		Type:      "attack",
		Title:     "Test Attack",
		RemoteIP:  "10.0.0.99",
		Level:     "critical",
		Timestamp: time.Now(),
	})
}

func TestDingTalkSendFormat(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var body map[string]interface{}
		json.NewDecoder(r.Body).Decode(&body)
		if body["msgtype"] != "markdown" {
			t.Errorf("msgtype: expected markdown, got %v", body["msgtype"])
		}
		md, ok := body["markdown"].(map[string]interface{})
		if !ok {
			t.Fatal("expected markdown content")
		}
		text, _ := md["text"].(string)
		if !strings.Contains(text, "Test") {
			t.Errorf("markdown text should contain Test")
		}
		w.Header().Set("Content-Type", "application/json")
		w.Write([]byte(`{"errcode":0,"errmsg":"ok"}`))
	}))
	defer server.Close()

	logger := zaptest.NewLogger(t).Sugar()
	a := New(logger, []ChannelConfig{
		{Type: ChannelDingTalk, URL: server.URL, Enabled: true},
	})

	a.Send(AlertEvent{
		Type:      "breadcrumb",
		Title:     "Test Breadcrumb",
		RemoteIP:  "10.0.0.1",
		Service:   "HTTP",
		Path:      "/admin/config.php",
		Level:     "warn",
		Timestamp: time.Now(),
	})
}

func TestFeishuSendFormat(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var body map[string]interface{}
		json.NewDecoder(r.Body).Decode(&body)
		if body["msg_type"] != "interactive" {
			t.Errorf("msg_type: expected interactive, got %v", body["msg_type"])
		}
		card, ok := body["card"].(map[string]interface{})
		if !ok {
			t.Fatal("expected card")
		}
		if _, ok := card["header"]; !ok {
			t.Error("expected header in card")
		}
		if _, ok := card["elements"]; !ok {
			t.Error("expected elements in card")
		}
		w.Header().Set("Content-Type", "application/json")
		w.Write([]byte(`{"code":0,"msg":"ok"}`))
	}))
	defer server.Close()

	logger := zaptest.NewLogger(t).Sugar()
	a := New(logger, []ChannelConfig{
		{Type: ChannelFeishu, URL: server.URL, Enabled: true},
	})

	a.Send(AlertEvent{
		Type:      "attack",
		Title:     "Test Attack",
		RemoteIP:  "192.168.1.1",
		Service:   "HTTP",
		Path:      "/.git/config",
		Level:     "critical",
		Timestamp: time.Now(),
	})
}

func TestChannelDisabled(t *testing.T) {
	called := false
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		called = true
		w.WriteHeader(200)
	}))
	defer server.Close()

	logger := zaptest.NewLogger(t).Sugar()
	a := New(logger, []ChannelConfig{
		{Type: ChannelWebhook, URL: server.URL, Enabled: false}, // disabled
	})

	a.Send(AlertEvent{
		Type:  "attack",
		Title: "Should not send",
		Level: "critical",
	})

	if called {
		t.Error("disabled channel should not be called")
	}
}

func TestEventFilter(t *testing.T) {
	called := false
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		called = true
		w.WriteHeader(200)
	}))
	defer server.Close()

	logger := zaptest.NewLogger(t).Sugar()
	a := New(logger, []ChannelConfig{
		{Type: ChannelWebhook, URL: server.URL, Enabled: true,
			EventFilter: []string{"breadcrumb"}}, // only breadcrumb
	})

	// 发送 attack 事件，应被过滤
	a.Send(AlertEvent{
		Type:  "attack",
		Title: "Should be filtered",
		Level: "warn",
	})

	if called {
		t.Error("attack event should be filtered out for breadcrumb-only channel")
	}

	// 发送 breadcrumb 事件，应通过
	a.Send(AlertEvent{
		Type:  "breadcrumb",
		Title: "Should pass",
		Level: "warn",
	})

	if !called {
		t.Error("breadcrumb event should pass through breadcrumb filter")
	}
}

func TestTruncate(t *testing.T) {
	tests := []struct {
		input  string
		maxLen int
		want   string
	}{
		{"short", 10, "short"},
		{"this is a very long string", 10, "this is a ..."},
		{"", 5, ""},
	}
	for _, tt := range tests {
		got := truncate(tt.input, tt.maxLen)
		if got != tt.want {
			t.Errorf("truncate(%q, %d) = %q, want %q", tt.input, tt.maxLen, got, tt.want)
		}
	}
}

func TestContains(t *testing.T) {
	if !contains([]string{"a", "b", "c"}, "b") {
		t.Error("expected to contain b")
	}
	if contains([]string{"a", "b"}, "c") {
		t.Error("should not contain c")
	}
	if contains(nil, "a") {
		t.Error("nil slice should not contain anything")
	}
	if contains([]string{}, "a") {
		t.Error("empty slice should not contain anything")
	}
}
