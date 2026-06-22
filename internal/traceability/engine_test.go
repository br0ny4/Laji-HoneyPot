package traceability

import (
	"strings"
	"testing"
	"time"

	"github.com/Laji-HoneyPot/honeypot/internal/core/bus"
	"github.com/Laji-HoneyPot/honeypot/internal/core/config"
	"github.com/Laji-HoneyPot/honeypot/internal/core/log"
)

func newTestEngine() *Engine {
	return NewEngine(log.New("debug"), bus.New())
}

func TestSelectPayloadChrome(t *testing.T) {
	e := newTestEngine()
	payload := e.SelectPayload("/", "Mozilla/5.0 Chrome/120.0", "10.0.0.1")
	if !strings.Contains(payload, "chrome_exploit") {
		t.Error("expected chrome payload for Chrome UA")
	}
}

func TestSelectPayloadFirefox(t *testing.T) {
	e := newTestEngine()
	payload := e.SelectPayload("/", "Mozilla/5.0 Firefox/121.0", "10.0.0.1")
	if !strings.Contains(payload, "firefox") && !strings.Contains(payload, "chrome_exploit") {
		t.Error("expected firefox payload for Firefox UA")
	}
}

func TestSelectPayloadCurl(t *testing.T) {
	e := newTestEngine()
	payload := e.SelectPayload("/api/test", "curl/7.88.1", "10.0.0.1")
	if !strings.Contains(payload, "api_honeytoken") {
		t.Error("expected api honeytoken payload for curl UA")
	}
}

func TestSelectPayloadActuator(t *testing.T) {
	e := newTestEngine()
	payload := e.SelectPayload("/actuator/env", "curl/7.88.1", "10.0.0.1")
	if !strings.Contains(payload, "springboot_honeytoken") {
		t.Error("expected springboot honeytoken payload for actuator path")
	}
}

func TestSelectPayloadSwagger(t *testing.T) {
	e := newTestEngine()
	payload := e.SelectPayload("/swagger-ui.html", "python-requests/2.31.0", "10.0.0.1")
	if !strings.Contains(payload, "swagger_honeytoken") {
		t.Errorf("expected swagger honeytoken payload for swagger path, got marker missing")
	}
}

func TestSelectPayloadApiDocs(t *testing.T) {
	e := newTestEngine()
	payload := e.SelectPayload("/v2/api-docs", "python-requests/2.31.0", "10.0.0.1")
	if !strings.Contains(payload, "swagger_honeytoken") {
		t.Error("expected swagger honeytoken for api-docs path")
	}
}

func TestSelectPayloadDefault(t *testing.T) {
	e := newTestEngine()
	payload := e.SelectPayload("/", "UnknownBot/1.0", "10.0.0.1")
	if !strings.Contains(payload, "enhanced") {
		t.Error("expected enhanced fingerprint payload for unknown UA")
	}
}

func TestSpringbootHoneytokenPayload(t *testing.T) {
	e := newTestEngine()
	payload := e.springbootHoneytokenPayload()

	if !strings.Contains(payload, "springboot_honeytoken") {
		t.Error("expected springboot_honeytoken marker")
	}
	if !strings.Contains(payload, "spring.datasource.url") {
		t.Error("expected datasource URL in springboot honeytoken")
	}
	if !strings.Contains(payload, "SpringBoot@Prod2024!") {
		t.Error("expected fake password in springboot honeytoken")
	}
	if !strings.Contains(payload, "Redis@Internal2024") {
		t.Error("expected fake redis password in springboot honeytoken")
	}
	if !strings.Contains(payload, "AKIAIOSFODNN7EXAMPLE") {
		t.Error("expected fake AWS access key in springboot honeytoken")
	}
	if !strings.Contains(payload, "management.endpoints.web.exposure.include=*") {
		t.Error("expected actuator exposure config in springboot honeytoken")
	}
	if !strings.Contains(payload, "/api/collect") {
		t.Error("expected fingerprint collection endpoint")
	}
}

func TestSwaggerHoneytokenPayload(t *testing.T) {
	e := newTestEngine()
	payload := e.swaggerHoneytokenPayload()

	if !strings.Contains(payload, "swagger_honeytoken") {
		t.Error("expected swagger_honeytoken marker")
	}
	if !strings.Contains(payload, "Internal Microservice API") {
		t.Error("expected API title in swagger honeytoken")
	}
	if !strings.Contains(payload, "swagger-internal-key-a1b2c3d4e5f6") {
		t.Error("expected fake API key in swagger honeytoken")
	}
	if !strings.Contains(payload, "hp_swagger_token") {
		t.Error("expected fake JWT token in swagger honeytoken")
	}
	if !strings.Contains(payload, "10.0.1.50:8080/api/internal/users") {
		t.Error("expected internal endpoint in swagger honeytoken")
	}
	if !strings.Contains(payload, "10.0.1.60:6379") {
		t.Error("expected internal Redis endpoint in swagger honeytoken")
	}
	if !strings.Contains(payload, "/api/collect") {
		t.Error("expected fingerprint collection endpoint")
	}
}

func TestActuatorPathPriorityOverApi(t *testing.T) {
	// actuator paths should match before generic api paths
	e := newTestEngine()
	payload := e.SelectPayload("/actuator/env", "python-requests/2.31.0", "10.0.0.1")
	if strings.Contains(payload, "api_honeytoken") && !strings.Contains(payload, "springboot_honeytoken") {
		t.Error("actuator path should match springboot payload before api payload")
	}
}

func TestSwaggerPathPriorityOverApi(t *testing.T) {
	// swagger paths should match before generic api paths
	e := newTestEngine()
	payload := e.SelectPayload("/swagger-ui/index.html", "python-requests/2.31.0", "10.0.0.1")
	if strings.Contains(payload, "api_honeytoken") && !strings.Contains(payload, "swagger_honeytoken") {
		t.Error("swagger path should match swagger payload before api payload")
	}
}

func TestAllPayloadsNonEmpty(t *testing.T) {
	e := newTestEngine()
	payloads := map[string]string{
		"chrome":     e.chromePayload(),
		"firefox":    e.firefoxPayload(),
		"api":        e.apiHoneytokenPayload("/test"),
		"admin":      e.adminHoneytokenPayload(),
		"springboot": e.springbootHoneytokenPayload(),
		"swagger":    e.swaggerHoneytokenPayload(),
		"sourceLeak": e.sourceLeakHoneytoken(),
		"enhanced":   e.enhancedFingerprintPayload(),
	}
	for name, p := range payloads {
		if len(p) == 0 {
			t.Errorf("%s payload is empty", name)
		}
		if !strings.Contains(p, "<script>") {
			t.Errorf("%s payload missing <script> tag", name)
		}
	}
}

func TestNVDUpdateIntervalInit(t *testing.T) {
	tests := []struct {
		name     string
		interval string
		expected time.Duration
	}{
		{"default 24h", "", 24 * time.Hour},
		{"explicit 24h", "24h", 24 * time.Hour},
		{"1 hour", "1h", 1 * time.Hour},
		{"6 hours", "6h", 6 * time.Hour},
		{"30 minutes", "30m", 30 * time.Minute},
		{"invalid falls back to 24h", "abc", 24 * time.Hour},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			e := newTestEngine()
			cfg := config.Section{}
			if tt.interval != "" {
				cfg["update_interval"] = tt.interval
			}
			if err := e.Init(cfg); err != nil {
				t.Fatalf("init failed: %v", err)
			}
			if e.updateInterval != tt.expected {
				t.Errorf("expected interval %v, got %v", tt.expected, e.updateInterval)
			}
			if e.stopCh == nil {
				t.Error("expected stopCh to be initialized")
			}
		})
	}
}

func TestNVDStopSignal(t *testing.T) {
	e := newTestEngine()
	cfg := config.Section{"update_interval": "1h"}
	if err := e.Init(cfg); err != nil {
		t.Fatalf("init failed: %v", err)
	}

	if e.stopCh == nil {
		t.Fatal("expected stopCh to be initialized")
	}

	// 验证 stopCh 可以正常关闭（不阻塞）
	if err := e.Stop(); err != nil {
		t.Fatalf("stop failed: %v", err)
	}

	// 验证关闭的 channel 可以读取到零值
	select {
	case _, ok := <-e.stopCh:
		if ok {
			t.Error("expected stopCh to be closed")
		}
	default:
		t.Error("expected stopCh to be readable after close")
	}
}
