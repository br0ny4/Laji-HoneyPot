package config

import (
	"os"
	"testing"
)

func TestLoadDefaultConfig(t *testing.T) {
	cfg, err := Load("nonexistent.yaml")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if cfg.LogLevel != "info" {
		t.Errorf("expected 'info', got '%s'", cfg.LogLevel)
	}
	if cfg.APIAddr != ":8080" {
		t.Errorf("expected ':8080', got '%s'", cfg.APIAddr)
	}
}

func TestLoadWithEnvOverride(t *testing.T) {
	os.Setenv("HP_LOG_LEVEL", "debug")
	defer os.Unsetenv("HP_LOG_LEVEL")

	cfg, err := Load("nonexistent.yaml")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if cfg.LogLevel != "debug" {
		t.Errorf("expected 'debug', got '%s'", cfg.LogLevel)
	}
}

func TestSectionGet(t *testing.T) {
	s := Section{"port": 3306, "host": "localhost"}
	if s.Get("host") != "localhost" {
		t.Errorf("expected 'localhost', got '%s'", s.Get("host"))
	}
	if s.GetInt("port") != 3306 {
		t.Errorf("expected 3306, got %d", s.GetInt("port"))
	}
	if s.Get("missing") != "" {
		t.Errorf("expected '', got '%s'", s.Get("missing"))
	}
}
