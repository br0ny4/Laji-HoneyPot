package vulndb

import (
	"testing"

	"github.com/Laji-HoneyPot/honeypot/internal/core/log"
)

func TestSeedAndQuery(t *testing.T) {
	logger := log.New("info")
	db := NewDB(logger)

	entries := db.FindByTool("cobaltstrike")
	if len(entries) != 1 {
		t.Errorf("expected 1 cobaltstrike entry, got %d", len(entries))
	}

	e, ok := db.Get("CVE-2022-39197")
	if !ok {
		t.Fatal("CVE-2022-39197 not found")
	}
	if e.Tool != "cobaltstrike" {
		t.Errorf("expected 'cobaltstrike', got '%s'", e.Tool)
	}

	if len(db.All()) < 3 {
		t.Errorf("expected at least 3 entries, got %d", len(db.All()))
	}
}

func TestBrowserVulnerabilities(t *testing.T) {
	logger := log.New("info")
	db := NewDB(logger)

	chromeEntries := db.FindByTool("chrome")
	if len(chromeEntries) == 0 {
		t.Error("expected chrome vulnerability entries")
	}

	for _, e := range chromeEntries {
		if e.Tool != "chrome" {
			t.Errorf("expected tool=chrome, got %s", e.Tool)
		}
	}
}

func TestDynamicAdd(t *testing.T) {
	logger := log.New("info")
	db := NewDB(logger)

	before := len(db.All())
	db.Add(&VulnEntry{
		ID:   "TEST-001",
		Tool: "nuclei",
	})
	if len(db.All()) != before+1 {
		t.Errorf("expected %d entries after add, got %d", before+1, len(db.All()))
	}

	// 重复添加应忽略
	db.Add(&VulnEntry{ID: "TEST-001", Tool: "nuclei"})
	if len(db.All()) != before+1 {
		t.Error("duplicate add should be ignored")
	}
}
