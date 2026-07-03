package payload

import (
	"strings"
	"testing"

	"github.com/Laji-HoneyPot/honeypot/internal/core/log"
)

func TestGenerateBrowserFingerprint(t *testing.T) {
	logger := log.New("info")
	gen := NewGenerator(logger, "http://callback.example.com")

	result := gen.GenerateBrowserFingerprint()

	if result.Type != JSBrowser {
		t.Errorf("expected type JSBrowser, got %q", result.Type)
	}
	if !strings.Contains(result.Content, "canvas") {
		t.Error("expected content to contain 'canvas'")
	}
	if !strings.Contains(result.Content, "WebRTC") {
		t.Error("expected content to contain 'WebRTC'")
	}
	if !strings.Contains(result.Content, "Laji-HoneyPot") {
		t.Error("expected content to contain 'Laji-HoneyPot'")
	}
	// 验证新增字段
	for _, field := range []string{
		"audio",
		"mathPrecision",
		"hwConcurrency",
		"deviceMemory",
		"platform",
		"connectionType",
		"touchSupport",
		"maxTouchPoints",
		"adBlocker",
		"cookieEnabled",
		"doNotTrack",
	} {
		if !strings.Contains(result.Content, field) {
			t.Errorf("expected content to contain new field '%s'", field)
		}
	}
}

func TestGenerateBrowserExploitChrome(t *testing.T) {
	logger := log.New("info")
	gen := NewGenerator(logger, "http://callback.example.com")

	result := gen.GenerateBrowserExploit("chrome")

	if result.Type != JSBrowser {
		t.Errorf("expected type JSBrowser, got %q", result.Type)
	}
	if !strings.Contains(result.Content, "Chrome") {
		t.Error("expected content to contain 'Chrome'")
	}
	if !strings.Contains(result.Content, "hardwareConcurrency") {
		t.Error("expected content to contain 'hardwareConcurrency'")
	}
}

func TestGenerateBrowserExploitFirefox(t *testing.T) {
	logger := log.New("info")
	gen := NewGenerator(logger, "http://callback.example.com")

	result := gen.GenerateBrowserExploit("firefox")

	if result.Type != JSBrowser {
		t.Errorf("expected type JSBrowser, got %q", result.Type)
	}
	if !strings.Contains(result.Content, "Firefox") {
		t.Error("expected content to contain 'Firefox'")
	}
	if !strings.Contains(result.Content, "buildID") {
		t.Error("expected content to contain 'buildID'")
	}
}

func TestGenerateCSXSSPayload(t *testing.T) {
	logger := log.New("info")
	gen := NewGenerator(logger, "http://callback.example.com")

	payload := gen.GenerateCSXSSPayload()

	if !strings.Contains(payload, "<script>") {
		t.Error("expected payload to contain '<script>'")
	}
	if !strings.Contains(payload, "http://callback.example.com") {
		t.Error("expected payload to contain callback URL")
	}
}

func TestGenerateBehinderDecoy(t *testing.T) {
	logger := log.New("info")
	gen := NewGenerator(logger, "http://callback.example.com")

	payload := gen.GenerateBehinderDecoy()

	if !strings.Contains(payload, "hostname") {
		t.Error("expected payload to contain 'hostname'")
	}
	if !strings.Contains(payload, "java.version") {
		t.Error("expected payload to contain 'java.version'")
	}
	if !strings.Contains(payload, "<%@") {
		t.Error("expected payload to contain JSP markers '<%@'")
	}
}
