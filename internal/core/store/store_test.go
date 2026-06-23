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
	if stats.ActiveServices != 9 {
		t.Errorf("expected fallback 9 services, got %d", stats.ActiveServices)
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

func TestRecordFingerprint(t *testing.T) {
	st, err := New(":memory:")
	if err != nil {
		t.Fatalf("create store: %v", err)
	}
	defer st.Close()

	id, err := st.RecordFingerprint("track-uuid-001", "10.0.0.1", "Chrome/120", `{"canvas":"hash","screen":"1920x1080"}`)
	if err != nil {
		t.Fatalf("record fingerprint: %v", err)
	}
	if id != 1 {
		t.Errorf("expected id=1, got %d", id)
	}
}

func TestGetFingerprints(t *testing.T) {
	st, err := New(":memory:")
	if err != nil {
		t.Fatalf("create store: %v", err)
	}
	defer st.Close()

	st.RecordFingerprint("track-001", "10.0.0.1", "Chrome/120", `{"screen":"1920x1080"}`)
	st.RecordFingerprint("track-002", "10.0.0.2", "Firefox/121", `{"screen":"2560x1440"}`)

	fps, err := st.GetFingerprints(10)
	if err != nil {
		t.Fatalf("get fingerprints: %v", err)
	}
	if len(fps) != 2 {
		t.Errorf("expected 2 fingerprints, got %d", len(fps))
	}
}

func TestGetFingerprintsDefaultLimit(t *testing.T) {
	st, err := New(":memory:")
	if err != nil {
		t.Fatalf("create store: %v", err)
	}
	defer st.Close()

	fps, err := st.GetFingerprints(0)
	if err != nil {
		t.Fatalf("get fingerprints: %v", err)
	}
	if len(fps) != 0 {
		t.Errorf("expected 0 fingerprints, got %d", len(fps))
	}
}

func TestFingerprintsTableExists(t *testing.T) {
	st, err := New(":memory:")
	if err != nil {
		t.Fatalf("create store: %v", err)
	}
	defer st.Close()

	rows, err := st.db.Query("SELECT name FROM sqlite_master WHERE type='table' AND name='fingerprints'")
	if err != nil {
		t.Fatalf("query tables: %v", err)
	}
	defer rows.Close()

	if !rows.Next() {
		t.Error("fingerprints table not created")
	}
}

func TestUpdateConnectionUA(t *testing.T) {
	st, err := New(":memory:")
	if err != nil {
		t.Fatalf("create store: %v", err)
	}
	defer st.Close()

	// 先创建一条 UA 为空的连接
	st.RecordConnection("10.111.31.241:52987", 8081, "HTTP", "")

	// 补录 UA
	err = st.UpdateConnectionUA("10.111.31.241:52987", "HTTP", "curl/8.7.1")
	if err != nil {
		t.Fatalf("update ua: %v", err)
	}

	// 验证 UA 已更新
	conns, err := st.GetConnections(10)
	if err != nil {
		t.Fatalf("get connections: %v", err)
	}
	if len(conns) != 1 {
		t.Fatalf("expected 1 connection, got %d", len(conns))
	}
	if conns[0].UserAgent != "curl/8.7.1" {
		t.Errorf("expected UA 'curl/8.7.1', got '%s'", conns[0].UserAgent)
	}
}

func TestUpdateConnectionUANoMatch(t *testing.T) {
	st, err := New(":memory:")
	if err != nil {
		t.Fatalf("create store: %v", err)
	}
	defer st.Close()

	// 无匹配记录，应无错误
	err = st.UpdateConnectionUA("10.0.0.1:12345", "HTTP", "Chrome/120")
	if err != nil {
		t.Errorf("expected no error for no match, got %v", err)
	}
}

func TestGetDetailedStats(t *testing.T) {
	st, err := New(":memory:")
	if err != nil {
		t.Fatalf("create store: %v", err)
	}
	defer st.Close()

	// 插入测试数据
	st.RecordConnection("192.168.1.100", 8081, "HTTP", "Mozilla/5.0 Chrome")
	st.RecordConnection("192.168.1.100", 3306, "MySQL", "mysql-connector")
	st.RecordConnection("10.0.0.50", 6379, "Redis", "redis-cli")
	st.RecordConnection("10.0.0.50", 2222, "SSH", "")

	// 插入攻击事件
	st.RecordAttack("192.168.1.100", "/admin/config.php", "curl", "")
	st.RecordAttack("192.168.1.100", "/actuator/env", "BurpSuite", "")

	// 插入指纹
	st.RecordFingerprint("trk-001", "192.168.1.100", "Chrome", `{"canvas":"abc"}`)

	stats, err := st.GetDetailedStats()
	if err != nil {
		t.Fatalf("GetDetailedStats: %v", err)
	}

	// 基本统计
	if stats.TotalConns != 4 {
		t.Errorf("expected total_conns=4, got %d", stats.TotalConns)
	}

	// 按服务分布
	if stats.ByService["HTTP"] != 1 || stats.ByService["MySQL"] != 1 ||
		stats.ByService["Redis"] != 1 || stats.ByService["SSH"] != 1 {
		t.Errorf("by_service mismatch: %v", stats.ByService)
	}

	// 按工具分布
	if stats.ByTool["curl"] != 1 || stats.ByTool["BurpSuite"] != 1 {
		t.Errorf("by_tool mismatch: %v", stats.ByTool)
	}

	// 指纹计数
	if stats.FingerprintCnt != 1 {
		t.Errorf("expected fingerprint_cnt=1, got %d", stats.FingerprintCnt)
	}

	// TOP 攻击者
	if len(stats.TopAttackers) != 2 {
		t.Errorf("expected 2 attackers, got %d", len(stats.TopAttackers))
	}
	// 192.168.1.100 应有最高攻击计数
	if stats.TopAttackers[0].RemoteIP == "192.168.1.100" {
		if stats.TopAttackers[0].ConnCnt != 2 {
			t.Errorf("expected attacker 192.168.1.100 has 2 conns, got %d", stats.TopAttackers[0].ConnCnt)
		}
	}
}

func TestGetDetailedStatsEmpty(t *testing.T) {
	st, err := New(":memory:")
	if err != nil {
		t.Fatalf("create store: %v", err)
	}
	defer st.Close()

	stats, err := st.GetDetailedStats()
	if err != nil {
		t.Fatalf("GetDetailedStats: %v", err)
	}

	if stats.ActiveServices != 9 {
		t.Errorf("expected fallback 9 active services, got %d", stats.ActiveServices)
	}
	if stats.TotalConns != 0 {
		t.Errorf("expected 0 total_conns, got %d", stats.TotalConns)
	}
	if len(stats.ByService) != 0 {
		t.Errorf("expected empty by_service, got %v", stats.ByService)
	}
	if len(stats.ByTool) != 0 {
		t.Errorf("expected empty by_tool, got %v", stats.ByTool)
	}
}

func TestGetTopologyData(t *testing.T) {
	st, err := New(":memory:")
	if err != nil {
		t.Fatalf("create store: %v", err)
	}
	defer st.Close()

	// 模拟攻击场景：两个攻击者访问不同服务
	st.RecordConnection("10.0.0.1", 8081, "HTTP", "Chrome")
	st.RecordConnection("10.0.0.1", 3306, "MySQL", "sqlmap")
	st.RecordConnection("10.0.0.2", 2222, "SSH", "")
	st.RecordConnection("10.0.0.2", 8081, "HTTP", "curl")

	// 面包屑触发 - 反制边
	st.RecordAttack("10.0.0.1", "/admin/config.php", "curl", "")
	st.RecordAttack("10.0.0.2", "/actuator/env", "python", "")

	td, err := st.GetTopologyData()
	if err != nil {
		t.Fatalf("GetTopologyData: %v", err)
	}

	// 节点: 攻击者(2) + 蜜罐(9) + 核心资产(3) = 14
	if len(td.Nodes) != 14 {
		t.Errorf("expected 14 nodes (2 attackers + 9 honeypot + 3 assets), got %d", len(td.Nodes))
	}

	// 验证攻击者节点
	attackerCount := 0
	for _, n := range td.Nodes {
		if n.Type == "attacker" {
			attackerCount++
		}
	}
	if attackerCount != 2 {
		t.Errorf("expected 2 attacker nodes, got %d", attackerCount)
	}

	// 验证蜜罐节点
	honeypotCount := 0
	for _, n := range td.Nodes {
		if n.Type == "honeypot" {
			honeypotCount++
		}
	}
	if honeypotCount != 9 {
		t.Errorf("expected 9 honeypot nodes, got %d", honeypotCount)
	}

	// 边: 攻击边(4条唯一) + 内部通路(5) + 反制边(2) = 11
	attackEdges := 0
	countermeasureEdges := 0
	internalEdges := 0
	for _, e := range td.Edges {
		switch e.EdgeType {
		case "attack":
			attackEdges++
		case "countermeasure":
			countermeasureEdges++
		case "internal":
			internalEdges++
		}
	}
	if attackEdges < 2 {
		t.Errorf("expected at least 2 attack edges, got %d", attackEdges)
	}
	if internalEdges != 5 {
		t.Errorf("expected 5 internal edges, got %d", internalEdges)
	}
	if countermeasureEdges != 2 {
		t.Errorf("expected 2 countermeasure edges, got %d", countermeasureEdges)
	}
}

func TestGetTopologyDataEmpty(t *testing.T) {
	st, err := New(":memory:")
	if err != nil {
		t.Fatalf("create store: %v", err)
	}
	defer st.Close()

	td, err := st.GetTopologyData()
	if err != nil {
		t.Fatalf("GetTopologyData: %v", err)
	}

	// 空数据库：9个蜜罐 + 3个核心资产 = 12个节点
	if len(td.Nodes) != 12 {
		t.Errorf("expected 12 nodes (9 honeypot + 3 assets), got %d", len(td.Nodes))
	}
	// 仅内部通路5条
	if len(td.Edges) != 5 {
		t.Errorf("expected 5 internal edges, got %d", len(td.Edges))
	}
}

func TestGetAttackers(t *testing.T) {
	st, err := New(":memory:")
	if err != nil {
		t.Fatalf("create store: %v", err)
	}
	defer st.Close()

	// 模拟多 IP 多服务攻击
	st.RecordConnection("10.0.0.1", 8081, "HTTP", "")
	st.RecordConnection("10.0.0.1", 3306, "MySQL", "")
	st.RecordConnection("10.0.0.1", 6379, "Redis", "")
	st.RecordConnection("10.0.0.2", 8081, "HTTP", "")
	st.RecordAttack("10.0.0.1", "/actuator/env", "Burp", "")
	st.RecordAttack("10.0.0.1", "/.git/config", "curl", "")
	st.RecordAttack("10.0.0.2", "/swagger-ui.html", "python", "")

	attackers, err := st.GetAttackers(2)
	if err != nil {
		t.Fatalf("GetAttackers: %v", err)
	}

	// 按连接数排序，10.0.0.1 应排第一
	if len(attackers) != 2 {
		t.Fatalf("expected 2 attackers (limit=2), got %d", len(attackers))
	}

	if attackers[0].RemoteIP != "10.0.0.1" {
		t.Errorf("expected 10.0.0.1 as top attacker, got %s", attackers[0].RemoteIP)
	}
	if attackers[0].ConnCnt != 3 {
		t.Errorf("expected 3 connections for 10.0.0.1, got %d", attackers[0].ConnCnt)
	}
	if attackers[0].BreadcrumbCnt != 2 {
		t.Errorf("expected 2 breadcrumb hits for 10.0.0.1, got %d", attackers[0].BreadcrumbCnt)
	}
	// Services 应包含 HTTP,MySQL,Redis
	if attackers[0].Services == "" {
		t.Error("expected non-empty services for attacker")
	}
}

func TestGetAttackersDefaultLimit(t *testing.T) {
	st, err := New(":memory:")
	if err != nil {
		t.Fatalf("create store: %v", err)
	}
	defer st.Close()

	// 插入 5 个不同 IP
	for i := 0; i < 5; i++ {
		ip := "10.0.0." + string(rune('1'+i))
		st.RecordConnection(ip, 8081, "HTTP", "")
	}

	// limit=0 应默认 50
	attackers, err := st.GetAttackers(0)
	if err != nil {
		t.Fatalf("GetAttackers: %v", err)
	}

	if len(attackers) != 5 {
		t.Errorf("expected 5 attackers, got %d", len(attackers))
	}
}

func TestDetailedStatsMultipleServices(t *testing.T) {
	st, err := New(":memory:")
	if err != nil {
		t.Fatalf("create store: %v", err)
	}
	defer st.Close()

	// 多种服务 + 多种工具
	svcIP := map[string]string{
		"HTTP":  "10.0.0.1",
		"MySQL": "10.0.0.2",
		"Redis": "10.0.0.3",
		"SSH":   "10.0.0.4",
		"FTP":   "10.0.0.5",
		"LDAP":  "10.0.0.6",
		"DNS":   "10.0.0.7",
		"SMB":   "10.0.0.8",
		"RDP":   "10.0.0.9",
	}
	for svc, ip := range svcIP {
		st.RecordConnection(ip, 0, svc, "")
	}
	st.RecordAttack("10.0.0.1", "/actuator/env", "nmap", "")
	st.RecordAttack("10.0.0.2", "/admin/config.php", "sqlmap", "")

	stats, err := st.GetDetailedStats()
	if err != nil {
		t.Fatalf("GetDetailedStats: %v", err)
	}

	if stats.ActiveServices != 9 {
		t.Errorf("expected 9 active services, got %d", stats.ActiveServices)
	}
	if len(stats.ByService) != 9 {
		t.Errorf("expected 9 services in by_service, got %d", len(stats.ByService))
	}
	if len(stats.ByTool) != 2 {
		t.Errorf("expected 2 tools in by_tool, got %d", len(stats.ByTool))
	}
}
