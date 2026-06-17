package registry

import (
	"testing"

	"github.com/Laji-HoneyPot/honeypot/internal/core/config"
	"github.com/Laji-HoneyPot/honeypot/internal/core/log"
	"github.com/Laji-HoneyPot/honeypot/internal/plugin"
)

type mockPlugin struct {
	plugin.Base
	name    string
	version string
	inited  bool
	started bool
	stopped bool
}

func (m *mockPlugin) Name() string                  { return m.name }
func (m *mockPlugin) Version() string               { return m.version }
func (m *mockPlugin) Init(cfg config.Section) error { m.inited = true; return nil }
func (m *mockPlugin) Start() error                  { m.started = true; return nil }
func (m *mockPlugin) Stop() error                   { m.stopped = true; return nil }

func TestRegisterAndLifecycle(t *testing.T) {
	logger := log.New("info")
	cfg := &config.Config{Plugins: map[string]config.Section{}}
	reg := New(logger, cfg)

	p1 := &mockPlugin{name: "test-a", version: "1.0"}
	p2 := &mockPlugin{name: "test-b", version: "2.0"}

	if err := reg.Register(p1); err != nil {
		t.Fatalf("register p1: %v", err)
	}
	if err := reg.Register(p2); err != nil {
		t.Fatalf("register p2: %v", err)
	}

	// 重复注册应报错
	if err := reg.Register(p1); err == nil {
		t.Error("expected error for duplicate registration")
	}

	if err := reg.InitAll(); err != nil {
		t.Fatalf("initall: %v", err)
	}
	if !p1.inited || !p2.inited {
		t.Error("expected all plugins to be inited")
	}

	if err := reg.StartAll(); err != nil {
		t.Fatalf("startall: %v", err)
	}
	if !p1.started || !p2.started {
		t.Error("expected all plugins to be started")
	}

	reg.StopAll()
	if !p1.stopped || !p2.stopped {
		t.Error("expected all plugins to be stopped")
	}

	names := reg.List()
	if len(names) != 2 {
		t.Errorf("expected 2 plugins, got %d", len(names))
	}
}
