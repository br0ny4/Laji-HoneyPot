package traps

import (
	"encoding/json"
	"testing"
)

func TestRegistry_WebScenario(t *testing.T) {
	r := New(ScenarioWeb, nil)

	if r.Scenario != ScenarioWeb {
		t.Errorf("expected scenario web, got %s", r.Scenario)
	}
	if !r.IsHTTPEnabled() {
		t.Error("expected HTTP to be enabled in web scenario")
	}
	if r.IsServiceEnabled("mysql") {
		t.Error("expected MySQL to be disabled in web scenario")
	}
	if r.IsServiceEnabled("ssh") {
		t.Error("expected SSH to be disabled in web scenario")
	}

	enabled := r.EnabledServices()
	if len(enabled) != 1 || enabled[0] != "http" {
		t.Errorf("expected [http], got %v", enabled)
	}
}

func TestRegistry_DatabaseScenario(t *testing.T) {
	r := New(ScenarioDatabase, nil)

	if r.IsHTTPEnabled() {
		t.Error("expected HTTP to be disabled in database scenario")
	}
	if !r.IsServiceEnabled("mysql") {
		t.Error("expected MySQL to be enabled in database scenario")
	}
	if !r.IsServiceEnabled("redis") {
		t.Error("expected Redis to be enabled in database scenario")
	}
	if r.IsServiceEnabled("ssh") {
		t.Error("expected SSH to be disabled in database scenario")
	}

	enabled := r.EnabledServices()
	if len(enabled) != 2 {
		t.Errorf("expected 2 services, got %d: %v", len(enabled), enabled)
	}
}

func TestRegistry_RemoteAccessScenario(t *testing.T) {
	r := New(ScenarioRemoteAccess, nil)

	if r.IsHTTPEnabled() {
		t.Error("expected HTTP to be disabled in remote_access scenario")
	}
	if !r.IsServiceEnabled("ssh") {
		t.Error("expected SSH to be enabled in remote_access scenario")
	}
	if !r.IsServiceEnabled("rdp") {
		t.Error("expected RDP to be enabled in remote_access scenario")
	}
	if !r.IsServiceEnabled("ftp") {
		t.Error("expected FTP to be enabled in remote_access scenario")
	}

	enabled := r.EnabledServices()
	if len(enabled) != 3 {
		t.Errorf("expected 3 services, got %d: %v", len(enabled), enabled)
	}
}

func TestRegistry_InfrastructureScenario(t *testing.T) {
	r := New(ScenarioInfrastructure, nil)

	if !r.IsServiceEnabled("dns") {
		t.Error("expected DNS to be enabled in infrastructure scenario")
	}
	if !r.IsServiceEnabled("ldap") {
		t.Error("expected LDAP to be enabled in infrastructure scenario")
	}
	if !r.IsServiceEnabled("smb") {
		t.Error("expected SMB to be enabled in infrastructure scenario")
	}
	if r.IsServiceEnabled("http") {
		t.Error("expected HTTP to be disabled in infrastructure scenario")
	}

	enabled := r.EnabledServices()
	if len(enabled) != 3 {
		t.Errorf("expected 3 services, got %d: %v", len(enabled), enabled)
	}
}

func TestRegistry_FullScenario(t *testing.T) {
	r := New(ScenarioFull, nil)

	for _, svc := range AllServices {
		if !r.IsServiceEnabled(svc) {
			t.Errorf("expected %s to be enabled in full scenario", svc)
		}
	}

	enabled := r.EnabledServices()
	if len(enabled) != len(AllServices) {
		t.Errorf("expected %d services, got %d: %v", len(AllServices), len(enabled), enabled)
	}
}

func TestRegistry_CustomScenario(t *testing.T) {
	r := New(ScenarioCustom, []string{"http", "ssh", "invalid_service"})

	if !r.IsServiceEnabled("http") {
		t.Error("expected HTTP to be enabled in custom")
	}
	if !r.IsServiceEnabled("ssh") {
		t.Error("expected SSH to be enabled in custom")
	}
	if r.IsServiceEnabled("mysql") {
		t.Error("expected MySQL to be disabled in custom")
	}
	if r.IsServiceEnabled("invalid_service") {
		t.Error("expected invalid_service to be filtered out")
	}

	enabled := r.EnabledServices()
	if len(enabled) != 2 {
		t.Errorf("expected 2 services, got %d: %v", len(enabled), enabled)
	}
}

func TestRegistry_InvalidScenario(t *testing.T) {
	// Invalid scenario should fallback to full
	r := New("invalid", nil)
	if r.Scenario != ScenarioFull {
		t.Errorf("expected fallback to full, got %s", r.Scenario)
	}
}

func TestRegistry_EmptyCustom(t *testing.T) {
	r := New(ScenarioCustom, nil)
	enabled := r.EnabledServices()
	if len(enabled) != 0 {
		t.Errorf("expected 0 services for empty custom, got %d", len(enabled))
	}
}

func TestParseScenario(t *testing.T) {
	tests := []struct {
		input    string
		expected TrapScenario
	}{
		{"web", ScenarioWeb},
		{"database", ScenarioDatabase},
		{"remote_access", ScenarioRemoteAccess},
		{"infrastructure", ScenarioInfrastructure},
		{"full", ScenarioFull},
		{"custom", ScenarioCustom},
		{"", ScenarioFull},
		{"unknown", ScenarioFull},
		{"Web", ScenarioFull}, // case sensitive
	}
	for _, tt := range tests {
		got := ParseScenario(tt.input)
		if got != tt.expected {
			t.Errorf("ParseScenario(%q) = %q, want %q", tt.input, got, tt.expected)
		}
	}
}

func TestGetScenarioInfo(t *testing.T) {
	infos := GetScenarioInfo()
	if len(infos) != len(AllScenarios) {
		t.Errorf("expected %d scenarios, got %d", len(AllScenarios), len(infos))
	}
	for _, info := range infos {
		if info.Key == "" || info.Description == "" {
			t.Errorf("scenario info %v has empty fields", info.Key)
		}
	}
}

func TestTrapConfigJSON(t *testing.T) {
	// Simulate what buildTrapConfigJSON does in main.go
	r := New(ScenarioWeb, nil)
	data := map[string]interface{}{
		"scenarios":        GetScenarioInfo(),
		"current_scenario": r.Scenario,
		"enabled_services": r.EnabledServices(),
		"all_services":     AllServices,
	}
	jsonData, err := json.Marshal(data)
	if err != nil {
		t.Fatalf("failed to marshal: %v", err)
	}

	var parsed map[string]interface{}
	if err := json.Unmarshal(jsonData, &parsed); err != nil {
		t.Fatalf("failed to unmarshal: %v", err)
	}

	if parsed["current_scenario"] != "web" {
		t.Errorf("expected current_scenario=web, got %v", parsed["current_scenario"])
	}
}

func TestRegistry_DisabledServiceNoResources(t *testing.T) {
	// In web scenario, only HTTP is enabled — all others should be disabled
	r := New(ScenarioWeb, nil)

	disabledServices := []string{"mysql", "redis", "ssh", "ftp", "ldap", "dns", "smb", "rdp"}
	for _, svc := range disabledServices {
		if r.IsServiceEnabled(svc) {
			t.Errorf("service %s should be disabled in web scenario (no wasted resources)", svc)
		}
	}

	// Verify only HTTP is enabled (1 out of 9 services)
	enabled := r.EnabledServices()
	if len(enabled) != 1 {
		t.Errorf("web scenario should only have 1 enabled service, got %d", len(enabled))
	}
}

func TestRegistry_AllScenariosUnique(t *testing.T) {
	// Each preset scenario should have a different set of services
	scenarios := []TrapScenario{ScenarioWeb, ScenarioDatabase, ScenarioRemoteAccess, ScenarioInfrastructure, ScenarioFull}
	seen := make(map[string]TrapScenario)
	for _, s := range scenarios {
		r := New(s, nil)
		key := fmtServicesKey(r.EnabledServices())
		if existing, ok := seen[key]; ok {
			t.Errorf("scenario %s has same services as %s: %v", s, existing, r.EnabledServices())
		}
		seen[key] = s
	}
}

func fmtServicesKey(svcs []string) string {
	return stringsJoin(svcs, ",")
}

// stringsJoin is a simple string joiner to avoid importing strings for just Join
func stringsJoin(elems []string, sep string) string {
	result := ""
	for i, s := range elems {
		if i > 0 {
			result += sep
		}
		result += s
	}
	return result
}
