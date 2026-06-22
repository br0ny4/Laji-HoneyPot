package fingerprint

import (
	"encoding/json"
	"testing"

	"github.com/Laji-HoneyPot/honeypot/internal/core/log"
)

func TestCollectorRecordAndGet(t *testing.T) {
	logger := log.New("info")
	c := NewCollector(logger)

	c.RecordConnection("192.168.1.100:54321")
	c.RecordConnection("10.0.0.5:12345")

	fp1, ok := c.Get("192.168.1.100")
	if !ok {
		t.Fatal("expected fingerprint for 192.168.1.100")
	}
	if fp1.IP != "192.168.1.100" {
		t.Errorf("expected IP 192.168.1.100, got %s", fp1.IP)
	}
	if fp1.Port != 54321 {
		t.Errorf("expected port 54321, got %d", fp1.Port)
	}

	fp2, ok := c.Get("10.0.0.5")
	if !ok {
		t.Fatal("expected fingerprint for 10.0.0.5")
	}
	if fp2.IP != "10.0.0.5" {
		t.Errorf("expected IP 10.0.0.5, got %s", fp2.IP)
	}
}

func TestCollectorUpdate(t *testing.T) {
	logger := log.New("info")
	c := NewCollector(logger)

	c.RecordConnection("172.16.0.1:8080")

	c.Update("172.16.0.1", func(fp *AttackerFingerprint) {
		fp.UserAgent = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36"
	})

	fp, ok := c.Get("172.16.0.1")
	if !ok {
		t.Fatal("expected fingerprint for 172.16.0.1")
	}
	if fp.UserAgent != "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36" {
		t.Errorf("expected updated UserAgent, got %q", fp.UserAgent)
	}
}

func TestCollectorGetAll(t *testing.T) {
	logger := log.New("info")
	c := NewCollector(logger)

	c.RecordConnection("192.168.1.1:1111")
	c.RecordConnection("192.168.1.2:2222")
	c.RecordConnection("192.168.1.3:3333")

	all := c.GetAll()
	if len(all) != 3 {
		t.Errorf("expected 3 entries, got %d", len(all))
	}
}

func TestCollectorDetectTool(t *testing.T) {
	logger := log.New("info")
	c := NewCollector(logger)

	tests := []struct {
		name     string
		userAgent string
		expected string
	}{
		{"Burp Suite", "Burp Suite Professional", "burpsuite"},
		{"SQLMap", "sqlmap/1.6", "sqlmap"},
		{"Chrome browser", "Mozilla/5.0 Chrome/120", "chrome"},
		{"Firefox browser", "Mozilla/5.0 Firefox/121", "firefox"},
		{"Nuclei scanner", "Nuclei/v3.0", "nuclei"},
		{"Cobalt Strike", "Mozilla/4.0 (compatible; MSIE 6.0; Windows NT 5.1)", "cobaltstrike"},
		{"unknown tool", "curl/7.88.1", "unknown"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			fp := &AttackerFingerprint{UserAgent: tt.userAgent}
			got := c.DetectTool(fp)
			if got != tt.expected {
				t.Errorf("DetectTool(%q) = %q, want %q", tt.userAgent, got, tt.expected)
			}
		})
	}
}

func TestCollectorToJSON(t *testing.T) {
	fp := &AttackerFingerprint{
		IP:        "10.0.0.99",
		Port:      4444,
		UserAgent: "TestAgent/1.0",
		ToolName:  "testtool",
	}

	data, err := fp.ToJSON()
	if err != nil {
		t.Fatalf("ToJSON: %v", err)
	}

	var result map[string]interface{}
	if err := json.Unmarshal(data, &result); err != nil {
		t.Fatalf("unmarshal JSON: %v", err)
	}

	if result["ip"] != "10.0.0.99" {
		t.Errorf("expected ip 10.0.0.99, got %v", result["ip"])
	}
	if result["port"] != float64(4444) {
		t.Errorf("expected port 4444, got %v", result["port"])
	}
	if result["user_agent"] != "TestAgent/1.0" {
		t.Errorf("expected user_agent TestAgent/1.0, got %v", result["user_agent"])
	}
	if result["tool_name"] != "testtool" {
		t.Errorf("expected tool_name testtool, got %v", result["tool_name"])
	}
}
