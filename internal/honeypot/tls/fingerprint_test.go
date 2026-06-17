package tls

import (
	"crypto/tls"
	"testing"
)

func TestPredefinedProfiles(t *testing.T) {
	profiles := []string{"nginx-1.24", "apache-2.4.37", "openssh-9.3"}
	for _, name := range profiles {
		fp, ok := Profile[name]
		if !ok {
			t.Errorf("profile %s not found", name)
			continue
		}
		cfg := Apply(fp)
		if cfg.MinVersion == 0 {
			t.Errorf("profile %s: MinVersion not set", name)
		}
		if len(cfg.CipherSuites) == 0 {
			t.Errorf("profile %s: CipherSuites empty", name)
		}
	}
}

func TestNginxConfig(t *testing.T) {
	fp := Profile["nginx-1.24"]
	cfg := Apply(fp)
	if cfg.MinVersion != tls.VersionTLS12 {
		t.Errorf("expected TLS 1.2 min, got %d", cfg.MinVersion)
	}
	if cfg.MaxVersion != tls.VersionTLS13 {
		t.Errorf("expected TLS 1.3 max, got %d", cfg.MaxVersion)
	}
}
