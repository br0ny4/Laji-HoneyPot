package manager

import (
	"context"
	"encoding/json"
	"strings"
	"testing"

	"github.com/Laji-HoneyPot/honeypot/internal/core/log"
)

func TestValidateProfileImageRequired(t *testing.T) {
	m := NewManager(log.New("info"))
	err := m.ValidateProfile("test", &SecurityProfile{Image: ""})
	if err == nil {
		t.Fatal("expected error for empty image")
	}
	if !strings.Contains(err.Error(), "image is required") {
		t.Errorf("expected 'image is required', got: %s", err.Error())
	}
}

func TestValidateProfilePrivilegedForbidden(t *testing.T) {
	m := NewManager(log.New("info"))
	err := m.ValidateProfile("test", &SecurityProfile{
		Image:      "alpine:3.19",
		Privileged: true,
	})
	if err == nil {
		t.Fatal("expected error for privileged mode")
	}
	if !strings.Contains(err.Error(), "privileged mode is forbidden") {
		t.Errorf("expected 'privileged mode is forbidden', got: %s", err.Error())
	}
}

func TestValidateProfileValid(t *testing.T) {
	m := NewManager(log.New("info"))
	profile := &SecurityProfile{
		Image:     "alpine:3.19",
		ReadOnly:  true,
		NoNewPriv: true,
		CapDrop:   []string{"SYS_ADMIN"},
	}
	if err := m.ValidateProfile("test", profile); err != nil {
		t.Errorf("expected no error, got: %v", err)
	}
}

func TestRunHoneypotSuccess(t *testing.T) {
	m := NewManager(log.New("info"))
	ctx := context.Background()
	profile := &SecurityProfile{
		Image:     "alpine:3.19",
		ReadOnly:  true,
		NoNewPriv: true,
		CapDrop:   []string{"SYS_ADMIN"},
	}
	name, err := m.RunHoneypot(ctx, "http-hp", profile, nil)
	if err != nil {
		t.Fatalf("expected success, got: %v", err)
	}
	if name != "http-hp" {
		t.Errorf("expected name http-hp, got: %s", name)
	}
	if _, ok := m.profiles["http-hp"]; !ok {
		t.Error("profile not stored")
	}
}

func TestRunHoneypotValidationFail(t *testing.T) {
	m := NewManager(log.New("info"))
	ctx := context.Background()
	_, err := m.RunHoneypot(ctx, "bad", &SecurityProfile{Image: ""}, nil)
	if err == nil {
		t.Fatal("expected validation error")
	}
}

func TestDefaultHTTPProfile(t *testing.T) {
	p := DefaultHTTPProfile()
	if p.Image != "alpine:3.19" {
		t.Errorf("expected alpine:3.19, got: %s", p.Image)
	}
	if !p.ReadOnly {
		t.Error("expected ReadOnly=true")
	}
	if !p.NoNewPriv {
		t.Error("expected NoNewPriv=true")
	}
	if p.Privileged {
		t.Error("expected Privileged=false")
	}
	if p.Seccomp != "seccomp-default.json" {
		t.Errorf("expected seccomp-default.json, got: %s", p.Seccomp)
	}
	if len(p.CapDrop) < 3 {
		t.Errorf("expected at least 3 CapDrop entries, got: %d", len(p.CapDrop))
	}
	expectedDrops := []string{"SYS_ADMIN", "NET_ADMIN", "SYS_PTRACE"}
	for _, cap := range expectedDrops {
		found := false
		for _, c := range p.CapDrop {
			if c == cap {
				found = true
				break
			}
		}
		if !found {
			t.Errorf("expected CapDrop to contain %s", cap)
		}
	}
}

func TestDefaultMySQLProfile(t *testing.T) {
	p := DefaultMySQLProfile()
	if p.Image != "alpine:3.19" {
		t.Errorf("expected alpine:3.19, got: %s", p.Image)
	}
	if p.Seccomp != "seccomp-mysql.json" {
		t.Errorf("expected seccomp-mysql.json, got: %s", p.Seccomp)
	}
	if !p.NoNewPriv {
		t.Error("expected NoNewPriv=true")
	}
}

func TestHTTPAndMySQLProfilesAreDifferent(t *testing.T) {
	http := DefaultHTTPProfile()
	mysql := DefaultMySQLProfile()
	if http.Seccomp == mysql.Seccomp {
		t.Error("HTTP and MySQL profiles should have different seccomp profiles")
	}
}

func TestDefaultSeccompProfile(t *testing.T) {
	sp := DefaultSeccompProfile()

	var parsed map[string]interface{}
	if err := json.Unmarshal([]byte(sp), &parsed); err != nil {
		t.Fatalf("seccomp profile is not valid JSON: %v", err)
	}

	if defaultAction, ok := parsed["defaultAction"].(string); !ok || defaultAction != "SCMP_ACT_ERRNO" {
		t.Errorf("expected SCMP_ACT_ERRNO, got: %v", parsed["defaultAction"])
	}

	archs, ok := parsed["architectures"].([]interface{})
	if !ok || len(archs) < 2 {
		t.Error("expected at least 2 architectures")
	}

	syscalls, ok := parsed["syscalls"].([]interface{})
	if !ok || len(syscalls) < 1 {
		t.Error("expected syscalls array")
	}

	names := syscalls[0].(map[string]interface{})["names"].([]interface{})
	if len(names) < 20 {
		t.Errorf("expected at least 20 allowed syscalls, got: %d", len(names))
	}

	required := []string{"accept", "bind", "socket", "read", "write", "connect", "listen"}
	for _, name := range required {
		found := false
		for _, n := range names {
			if n.(string) == name {
				found = true
				break
			}
		}
		if !found {
			t.Errorf("expected syscall %s in whitelist", name)
		}
	}
}

func TestStop(t *testing.T) {
	m := NewManager(log.New("info"))
	ctx := context.Background()
	profile := &SecurityProfile{
		Image:   "alpine:3.19",
		CapDrop: []string{"SYS_ADMIN"},
	}
	m.RunHoneypot(ctx, "hp-1", profile, nil)
	m.RunHoneypot(ctx, "hp-2", profile, nil)

	m.Stop("hp-1")
	if _, ok := m.profiles["hp-1"]; ok {
		t.Error("hp-1 should be removed after stop")
	}
	if _, ok := m.profiles["hp-2"]; !ok {
		t.Error("hp-2 should still exist")
	}
}

func TestClose(t *testing.T) {
	m := NewManager(log.New("info"))
	ctx := context.Background()
	profile := &SecurityProfile{
		Image:   "alpine:3.19",
		CapDrop: []string{"SYS_ADMIN"},
	}
	m.RunHoneypot(ctx, "hp-1", profile, nil)
	m.RunHoneypot(ctx, "hp-2", profile, nil)

	if err := m.Close(); err != nil {
		t.Errorf("close should not error: %v", err)
	}
	if len(m.profiles) != 0 {
		t.Errorf("expected 0 profiles after close, got: %d", len(m.profiles))
	}
}
