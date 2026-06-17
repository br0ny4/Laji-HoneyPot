package log

import (
	"testing"
)

func TestNewLogger(t *testing.T) {
	logger := New("debug")
	if logger == nil {
		t.Fatal("expected non-nil logger")
	}
	logger.Info("test log message")
	logger.Debugw("debug message", "key", "value")
}

func TestNewLoggerDefaultLevel(t *testing.T) {
	logger := New("unknown")
	if logger == nil {
		t.Fatal("expected non-nil logger")
	}
	logger.Info("this should be info level")
}
