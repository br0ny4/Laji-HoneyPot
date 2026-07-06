// To compare CGO vs pure-Go SQLite performance:
// CGO:   go test -bench=. -count=5 ./internal/core/store/
// Pure:  go test -tags=noasm -bench=. -count=5 ./internal/core/store/

package store

import (
	"fmt"
	"sync"
	"testing"
)

func BenchmarkRecordConnection(b *testing.B) {
	st, err := New(":memory:")
	if err != nil {
		b.Fatalf("create store: %v", err)
	}
	defer st.Close()

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		ip := fmt.Sprintf("10.0.%d.%d", (i/256)%256, i%256)
		_, err := st.RecordConnection(ip, 8081, "HTTP", "Mozilla/5.0")
		if err != nil {
			b.Fatalf("record: %v", err)
		}
	}
}

func BenchmarkGetStats(b *testing.B) {
	st, err := New(":memory:")
	if err != nil {
		b.Fatalf("create store: %v", err)
	}
	defer st.Close()

	// Populate with data
	for i := 0; i < 200; i++ {
		ip := fmt.Sprintf("10.0.%d.%d", (i/256)%256, i%256)
		st.RecordConnection(ip, 8081, "HTTP", "")
	}
	for i := 0; i < 50; i++ {
		st.RecordAttack(fmt.Sprintf("10.0.%d.%d", i/10, i%10), "/admin/config.php", "curl", "")
	}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, err := st.GetStats()
		if err != nil {
			b.Fatalf("get stats: %v", err)
		}
	}
}

func BenchmarkGetFingerprints(b *testing.B) {
	st, err := New(":memory:")
	if err != nil {
		b.Fatalf("create store: %v", err)
	}
	defer st.Close()

	// Populate fingerprints
	for i := 0; i < 100; i++ {
		trackingID := fmt.Sprintf("track-%04d", i)
		rawData := fmt.Sprintf(`{"canvas":"hash-%d","screen":"1920x1080"}`, i)
		st.RecordFingerprint(trackingID, "10.0.0.1", "Chrome/120", rawData)
	}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, err := st.GetFingerprints(50)
		if err != nil {
			b.Fatalf("get fingerprints: %v", err)
		}
	}
}

func BenchmarkConcurrentWrites(b *testing.B) {
	st, err := New(":memory:")
	if err != nil {
		b.Fatalf("create store: %v", err)
	}
	defer st.Close()

	perGoroutine := b.N / 10
	if perGoroutine < 1 {
		perGoroutine = 1
	}

	b.ResetTimer()

	var wg sync.WaitGroup
	for g := 0; g < 10; g++ {
		wg.Add(1)
		go func(grp int) {
			defer wg.Done()
			for i := 0; i < perGoroutine; i++ {
				ip := fmt.Sprintf("10.%d.%d.%d", grp, (i/256)%256, i%256)
				st.RecordConnection(ip, 8081, "HTTP", "curl/8.0")
			}
		}(g)
	}
	wg.Wait()
}
