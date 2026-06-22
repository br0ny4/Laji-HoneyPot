package store

import (
	"os"
	"path/filepath"
	"testing"
)

func TestNewMemoryStore(t *testing.T) {
	st, err := New(":memory:")
	if err != nil {
		t.Fatalf("create memory store: %v", err)
	}
	defer st.Close()

	// 验证表已创建
	rows, err := st.db.Query("SELECT name FROM sqlite_master WHERE type='table'")
	if err != nil {
		t.Fatalf("query tables: %v", err)
	}
	defer rows.Close()

	var tables []string
	for rows.Next() {
		var name string
		rows.Scan(&name)
		tables = append(tables, name)
	}
	found := false
	for _, tbl := range tables {
		if tbl == "connections" {
			found = true
			break
		}
	}
	if !found {
		t.Error("connections table not created")
	}
}

func TestRecordConnection(t *testing.T) {
	st, err := New(":memory:")
	if err != nil {
		t.Fatalf("create store: %v", err)
	}
	defer st.Close()

	id, err := st.RecordConnection("10.0.0.1", 8081, "HTTP", "Mozilla/5.0")
	if err != nil {
		t.Fatalf("record: %v", err)
	}
	if id != 1 {
		t.Errorf("expected id=1, got %d", id)
	}

	id2, _ := st.RecordConnection("10.0.0.2", 3306, "MySQL", "")
	if id2 != 2 {
		t.Errorf("expected id=2, got %d", id2)
	}
}

func TestRecordAttack(t *testing.T) {
	st, err := New(":memory:")
	if err != nil {
		t.Fatalf("create store: %v", err)
	}
	defer st.Close()

	id, err := st.RecordAttack("10.0.0.1", "/admin/config.php", "burpsuite", "scan")
	if err != nil {
		t.Fatalf("record attack: %v", err)
	}
	if id != 1 {
		t.Errorf("expected id=1, got %d", id)
	}
}

func TestGetConnections(t *testing.T) {
	st, err := New(":memory:")
	if err != nil {
		t.Fatalf("create store: %v", err)
	}
	defer st.Close()

	st.RecordConnection("10.0.0.1", 80, "HTTP", "")
	st.RecordConnection("10.0.0.2", 443, "HTTPS", "curl")

	conns, err := st.GetConnections(10)
	if err != nil {
		t.Fatalf("get connections: %v", err)
	}
	if len(conns) != 2 {
		t.Errorf("expected 2 connections, got %d", len(conns))
	}
	if conns[0].RemoteIP != "10.0.0.2" {
		t.Errorf("expected most recent first, got %s", conns[0].RemoteIP)
	}
}

func TestGetConnectionsDefaultLimit(t *testing.T) {
	st, err := New(":memory:")
	if err != nil {
		t.Fatalf("create store: %v", err)
	}
	defer st.Close()

	conns, err := st.GetConnections(0)
	if err != nil {
		t.Fatalf("get connections: %v", err)
	}
	if len(conns) != 0 {
		t.Errorf("expected 0 connections, got %d", len(conns))
	}
}

func TestGetConnectionsNegativeLimit(t *testing.T) {
	st, err := New(":memory:")
	if err != nil {
		t.Fatalf("create store: %v", err)
	}
	defer st.Close()

	conns, err := st.GetConnections(-1)
	if err != nil {
		t.Fatalf("get connections: %v", err)
	}
	if len(conns) != 0 {
		t.Errorf("expected 0 connections, got %d", len(conns))
	}
}

func TestGetAttacks(t *testing.T) {
	st, err := New(":memory:")
	if err != nil {
		t.Fatalf("create store: %v", err)
	}
	defer st.Close()

	st.RecordAttack("10.0.0.1", "/admin/config.php", "burpsuite", "")
	st.RecordAttack("10.0.0.2", "/.git/config", "nuclei", "scan")

	attacks, err := st.GetAttacks(10)
	if err != nil {
		t.Fatalf("get attacks: %v", err)
	}
	if len(attacks) != 2 {
		t.Errorf("expected 2 attacks, got %d", len(attacks))
	}
}

func TestGetStats(t *testing.T) {
	st, err := New(":memory:")
	if err != nil {
		t.Fatalf("create store: %v", err)
	}
	defer st.Close()

	st.RecordConnection("10.0.0.1", 80, "HTTP", "")
	st.RecordConnection("10.0.0.2", 3306, "MySQL", "")
	st.RecordAttack("10.0.0.1", "/admin/config.php", "burpsuite", "")

	stats, err := st.GetStats()
	if err != nil {
		t.Fatalf("get stats: %v", err)
	}
	if stats.TodayConns != 2 {
		t.Errorf("expected 2 today_conns, got %d", stats.TodayConns)
	}
	if stats.Attackers != 2 {
		t.Errorf("expected 2 attackers, got %d", stats.Attackers)
	}
	if stats.CounterHits != 1 {
		t.Errorf("expected 1 counter_hits, got %d", stats.CounterHits)
	}
}

func TestGetStatsEmpty(t *testing.T) {
	st, err := New(":memory:")
	if err != nil {
		t.Fatalf("create store: %v", err)
	}
	defer st.Close()

	stats, err := st.GetStats()
	if err != nil {
		t.Fatalf("get stats: %v", err)
	}
	if stats.ActiveServices != 7 {
		t.Errorf("expected fallback 7 services, got %d", stats.ActiveServices)
	}
	if stats.TodayConns != 0 {
		t.Errorf("expected 0 conns, got %d", stats.TodayConns)
	}
}

func TestNewFileStore(t *testing.T) {
	dir := t.TempDir()
	dbPath := filepath.Join(dir, "honeypot.db")

	st, err := New(dir)
	if err != nil {
		t.Fatalf("create file store: %v", err)
	}
	defer st.Close()

	// 验证文件已创建
	if _, err := os.Stat(dbPath); os.IsNotExist(err) {
		t.Error("honeypot.db not created")
	}

	st.RecordConnection("10.0.0.1", 80, "HTTP", "")
	conns, _ := st.GetConnections(1)
	if len(conns) != 1 {
		t.Errorf("expected 1 connection in file store, got %d", len(conns))
	}
}

func TestRecordAttackEmptyPayload(t *testing.T) {
	st, err := New(":memory:")
	if err != nil {
		t.Fatalf("create store: %v", err)
	}
	defer st.Close()

	id, err := st.RecordAttack("10.0.0.1", "/", "unknown", "")
	if err != nil {
		t.Fatalf("record attack: %v", err)
	}
	if id == 0 {
		t.Error("expected non-zero id for attack with empty payload")
	}
}

func TestGetAttacksDefaultLimit(t *testing.T) {
	st, err := New(":memory:")
	if err != nil {
		t.Fatalf("create store: %v", err)
	}
	defer st.Close()

	attacks, err := st.GetAttacks(0)
	if err != nil {
		t.Fatalf("get attacks: %v", err)
	}
	if len(attacks) != 0 {
		t.Errorf("expected 0 attacks, got %d", len(attacks))
	}
}

func TestLargeConnectionBatch(t *testing.T) {
	st, err := New(":memory:")
	if err != nil {
		t.Fatalf("create store: %v", err)
	}
	defer st.Close()

	// 插入 100 条连接
	for i := 0; i < 100; i++ {
		st.RecordConnection("10.0.0.1", 80, "HTTP", "")
	}

	conns, err := st.GetConnections(50)
	if err != nil {
		t.Fatalf("get connections: %v", err)
	}
	if len(conns) != 50 {
		t.Errorf("expected 50 connections (limited), got %d", len(conns))
	}

	all, err := st.GetConnections(200)
	if err != nil {
		t.Fatalf("get all connections: %v", err)
	}
	if len(all) != 100 {
		t.Errorf("expected 100 connections, got %d", len(all))
	}
}
