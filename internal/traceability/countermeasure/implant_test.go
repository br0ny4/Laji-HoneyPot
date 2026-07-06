package countermeasure

import (
	"testing"
)

func TestRandomID(t *testing.T) {
	for i := 0; i < 1000; i++ {
		id := randomID()
		if id < 100000 || id > 999999 {
			t.Errorf("randomID() = %d, want in range [100000, 999999]", id)
		}
	}
}

func TestRandomID_Unique(t *testing.T) {
	const n = 100
	seen := make(map[int64]bool, n)

	for i := 0; i < n; i++ {
		id := randomID()
		seen[id] = true
	}

	// Verify we get more than 1 distinct value. Since randomID() is based on
	// time.Now().UnixNano(), a tight loop may produce many duplicates — but it
	// should still yield at least a few different values across 100 iterations.
	unique := len(seen)
	if unique < 2 {
		t.Errorf("randomID() produced only %d unique value(s) across %d calls, expected at least 2", unique, n)
	}
}
