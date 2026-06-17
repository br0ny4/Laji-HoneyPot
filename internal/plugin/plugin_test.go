package plugin

import (
	"testing"
)

type testPlugin struct {
	Base
}

func (t testPlugin) Name() string    { return "test" }
func (t testPlugin) Version() string { return "0.1.0" }

func TestBaseImplementsPlugin(t *testing.T) {
	var p Plugin = &testPlugin{}
	if p.Name() != "test" {
		t.Errorf("expected 'test', got '%s'", p.Name())
	}
	if p.Version() != "0.1.0" {
		t.Errorf("expected '0.1.0', got '%s'", p.Version())
	}
}
