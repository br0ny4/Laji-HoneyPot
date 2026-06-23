package store

import (
	"database/sql"
	"fmt"
	"os"
	"path/filepath"
	"time"

	_ "github.com/mattn/go-sqlite3"
)

// Store SQLite 持久化层，存储蜜罐事件、攻击者指纹等核心数据
type Store struct {
	db *sql.DB
}

// Connection 一次连接记录
type Connection struct {
	ID        int64     `json:"id"`
	Timestamp time.Time `json:"timestamp"`
	RemoteIP  string    `json:"remote_ip"`
	Port      int       `json:"port"`
	Service   string    `json:"service"`
	UserAgent string    `json:"user_agent,omitempty"`
}

// AttackEvent 攻击事件（面包屑触发等）
type AttackEvent struct {
	ID        int64     `json:"id"`
	Timestamp time.Time `json:"timestamp"`
	RemoteIP  string    `json:"remote_ip"`
	Path      string    `json:"path"`
	ToolName  string    `json:"tool_name"`
	Payload   string    `json:"payload,omitempty"`
}

// Stats 仪表盘统计数据
type Stats struct {
	ActiveServices int `json:"active_services"`
	TodayConns     int `json:"today_conns"`
	Attackers      int `json:"attackers"`
	CounterHits    int `json:"counter_hits"`
}

// New 创建 Store，自动初始化数据库表。dataDir 为 ":memory:" 时使用内存数据库。
func New(dataDir string) (*Store, error) {
	var dbPath string
	if dataDir == ":memory:" {
		dbPath = ":memory:"
	} else {
		if err := os.MkdirAll(dataDir, 0755); err != nil {
			return nil, fmt.Errorf("create data dir: %w", err)
		}
		dbPath = filepath.Join(dataDir, "honeypot.db")
	}

	db, err := sql.Open("sqlite3", dbPath+"?_journal_mode=WAL&_busy_timeout=5000")
	if err != nil {
		return nil, fmt.Errorf("open db: %w", err)
	}

	if err := db.Ping(); err != nil {
		return nil, fmt.Errorf("ping db: %w", err)
	}

	s := &Store{db: db}
	if err := s.migrate(); err != nil {
		return nil, fmt.Errorf("migrate: %w", err)
	}
	return s, nil
}

func (s *Store) migrate() error {
	ddl := `
	CREATE TABLE IF NOT EXISTS connections (
		id INTEGER PRIMARY KEY AUTOINCREMENT,
		timestamp DATETIME DEFAULT CURRENT_TIMESTAMP,
		remote_ip TEXT NOT NULL,
		port INTEGER NOT NULL,
		service TEXT NOT NULL,
		user_agent TEXT DEFAULT ''
	);

	CREATE TABLE IF NOT EXISTS attack_events (
		id INTEGER PRIMARY KEY AUTOINCREMENT,
		timestamp DATETIME DEFAULT CURRENT_TIMESTAMP,
		remote_ip TEXT NOT NULL,
		path TEXT DEFAULT '',
		tool_name TEXT DEFAULT 'unknown',
		payload TEXT DEFAULT ''
	);

	CREATE INDEX IF NOT EXISTS idx_conn_ts ON connections(timestamp);
	CREATE INDEX IF NOT EXISTS idx_conn_ip ON connections(remote_ip);
	CREATE INDEX IF NOT EXISTS idx_attack_ts ON attack_events(timestamp);
	CREATE INDEX IF NOT EXISTS idx_attack_ip ON attack_events(remote_ip);

	CREATE TABLE IF NOT EXISTS fingerprints (
		id INTEGER PRIMARY KEY AUTOINCREMENT,
		timestamp DATETIME DEFAULT CURRENT_TIMESTAMP,
		tracking_id TEXT NOT NULL,
		remote_ip TEXT NOT NULL,
		user_agent TEXT DEFAULT '',
		raw_data TEXT DEFAULT '',
		created_at DATETIME DEFAULT CURRENT_TIMESTAMP
	);
	CREATE INDEX IF NOT EXISTS idx_fp_tracking ON fingerprints(tracking_id);

	CREATE TABLE IF NOT EXISTS countermeasure_events (
		id INTEGER PRIMARY KEY AUTOINCREMENT,
		timestamp DATETIME DEFAULT CURRENT_TIMESTAMP,
		remote_ip TEXT NOT NULL,
		trigger_path TEXT DEFAULT '',
		payload_type TEXT DEFAULT 'unknown',
		payload_preview TEXT DEFAULT '',
		user_agent TEXT DEFAULT '',
		effective INTEGER DEFAULT 0,
		related_attack_id INTEGER DEFAULT 0
	);
	CREATE INDEX IF NOT EXISTS idx_cm_ip ON countermeasure_events(remote_ip);
	CREATE INDEX IF NOT EXISTS idx_cm_ts ON countermeasure_events(timestamp);
	`
	_, err := s.db.Exec(ddl)
	return err
}

// RecordConnection 记录一次连接
func (s *Store) RecordConnection(remoteIP string, port int, service, userAgent string) (int64, error) {
	res, err := s.db.Exec(
		"INSERT INTO connections (remote_ip, port, service, user_agent) VALUES (?, ?, ?, ?)",
		remoteIP, port, service, userAgent,
	)
	if err != nil {
		return 0, err
	}
	return res.LastInsertId()
}

// UpdateConnectionUA 更新最近一条匹配连接的 User-Agent（按 remote_ip + service 匹配）
func (s *Store) UpdateConnectionUA(remoteIP, service, userAgent string) error {
	_, err := s.db.Exec(
		`UPDATE connections SET user_agent = ? 
		 WHERE id = (
		   SELECT id FROM connections 
		   WHERE remote_ip = ? AND service = ? 
		   ORDER BY timestamp DESC LIMIT 1
		 )`,
		userAgent, remoteIP, service,
	)
	return err
}

// RecordAttack 记录一次攻击事件
func (s *Store) RecordAttack(remoteIP, path, toolName, payload string) (int64, error) {
	res, err := s.db.Exec(
		"INSERT INTO attack_events (remote_ip, path, tool_name, payload) VALUES (?, ?, ?, ?)",
		remoteIP, path, toolName, payload,
	)
	if err != nil {
		return 0, err
	}
	return res.LastInsertId()
}

// GetStats 获取仪表盘统计
func (s *Store) GetStats() (*Stats, error) {
	stats := &Stats{}

	s.db.QueryRow("SELECT COUNT(DISTINCT service) FROM connections").Scan(&stats.ActiveServices)
	if stats.ActiveServices == 0 {
		stats.ActiveServices = 9 // HTTP/MySQL/Redis/SSH/FTP/LDAP/DNS/SMB/RDP
	}

	today := time.Now().Format("2006-01-02")
	s.db.QueryRow("SELECT COUNT(*) FROM connections WHERE timestamp >= ?", today).Scan(&stats.TodayConns)
	s.db.QueryRow("SELECT COUNT(DISTINCT remote_ip) FROM connections WHERE timestamp >= ?", today).Scan(&stats.Attackers)
	s.db.QueryRow("SELECT COUNT(*) FROM attack_events WHERE timestamp >= ?", today).Scan(&stats.CounterHits)

	return stats, nil
}

// GetConnections 获取最近连接列表
func (s *Store) GetConnections(limit int) ([]Connection, error) {
	if limit <= 0 {
		limit = 50
	}
	rows, err := s.db.Query(
		"SELECT id, timestamp, remote_ip, port, service, user_agent FROM connections ORDER BY timestamp DESC LIMIT ?",
		limit,
	)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var conns []Connection
	for rows.Next() {
		var c Connection
		if err := rows.Scan(&c.ID, &c.Timestamp, &c.RemoteIP, &c.Port, &c.Service, &c.UserAgent); err != nil {
			continue
		}
		conns = append(conns, c)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("scan connections: %w", err)
	}
	return conns, nil
}

// GetAttacks 获取最近攻击事件
func (s *Store) GetAttacks(limit int) ([]AttackEvent, error) {
	if limit <= 0 {
		limit = 50
	}
	rows, err := s.db.Query(
		"SELECT id, timestamp, remote_ip, path, tool_name, payload FROM attack_events ORDER BY timestamp DESC LIMIT ?",
		limit,
	)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var events []AttackEvent
	for rows.Next() {
		var e AttackEvent
		if err := rows.Scan(&e.ID, &e.Timestamp, &e.RemoteIP, &e.Path, &e.ToolName, &e.Payload); err != nil {
			continue
		}
		events = append(events, e)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("scan attacks: %w", err)
	}
	return events, nil
}

// RecordFingerprint 记录浏览器指纹采集数据
func (s *Store) RecordFingerprint(trackingID, remoteIP, userAgent, rawData string) (int64, error) {
	res, err := s.db.Exec(
		"INSERT INTO fingerprints (tracking_id, remote_ip, user_agent, raw_data) VALUES (?, ?, ?, ?)",
		trackingID, remoteIP, userAgent, rawData,
	)
	if err != nil {
		return 0, err
	}
	return res.LastInsertId()
}

// GetFingerprints 获取最近的指纹记录
func (s *Store) GetFingerprints(limit int) ([]map[string]interface{}, error) {
	if limit <= 0 {
		limit = 50
	}
	rows, err := s.db.Query(
		"SELECT id, timestamp, tracking_id, remote_ip, user_agent, raw_data, created_at FROM fingerprints ORDER BY timestamp DESC LIMIT ?",
		limit,
	)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var results []map[string]interface{}
	for rows.Next() {
		var id int64
		var timestamp, trackingID, remoteIP, userAgent, rawData, createdAt string
		if err := rows.Scan(&id, &timestamp, &trackingID, &remoteIP, &userAgent, &rawData, &createdAt); err != nil {
			continue
		}
		results = append(results, map[string]interface{}{
			"id":          id,
			"timestamp":   timestamp,
			"tracking_id": trackingID,
			"remote_ip":   remoteIP,
			"user_agent":  userAgent,
			"raw_data":    rawData,
			"created_at":  createdAt,
		})
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("scan fingerprints: %w", err)
	}
	return results, nil
}

// TopoNode 拓扑图节点
type TopoNode struct {
	ID     string                 `json:"id"`
	Label  string                 `json:"label"`
	Type   string                 `json:"type"` // attacker, honeypot, hop, asset
	IP     string                 `json:"ip"`
	Status string                 `json:"status,omitempty"`
	Data   map[string]interface{} `json:"data,omitempty"`
}

// TopoEdge 拓扑图边
type TopoEdge struct {
	Source   string                 `json:"source"`
	Target   string                 `json:"target"`
	Label    string                 `json:"label"`
	EdgeType string                 `json:"edgeType"` // attack, countermeasure
	Data     map[string]interface{} `json:"data,omitempty"`
}

// TopologyData 拓扑图完整数据
type TopologyData struct {
	Nodes []TopoNode `json:"nodes"`
	Edges []TopoEdge `json:"edges"`
}

// AttackerSummary 攻击者汇总
type AttackerSummary struct {
	RemoteIP      string `json:"remote_ip"`
	FirstSeen     string `json:"first_seen"`
	LastSeen      string `json:"last_seen"`
	AttackCnt     int    `json:"attack_cnt"`
	ConnCnt       int    `json:"conn_cnt"`
	Services      string `json:"services"` // 逗号分隔的服务列表
	BreadcrumbCnt int    `json:"breadcrumb_cnt"`
	UserAgents    string `json:"user_agents"` // 去重后逗号分隔
}

// DetailedStats 详细统计数据
type DetailedStats struct {
	ActiveServices int               `json:"active_services"`
	TodayConns     int               `json:"today_conns"`
	TotalConns     int               `json:"total_conns"`
	Attackers      int               `json:"attackers"`
	CounterHits    int               `json:"counter_hits"`
	FingerprintCnt int               `json:"fingerprint_cnt"`
	ByService      map[string]int    `json:"by_service"`
	ByTool         map[string]int    `json:"by_tool"`
	TopAttackers   []AttackerSummary `json:"top_attackers"`
}

// GetDetailedStats 获取详细统计数据
func (s *Store) GetDetailedStats() (*DetailedStats, error) {
	stats := &DetailedStats{
		ByService: make(map[string]int),
		ByTool:    make(map[string]int),
	}

	s.db.QueryRow("SELECT COUNT(DISTINCT service) FROM connections").Scan(&stats.ActiveServices)
	if stats.ActiveServices == 0 {
		stats.ActiveServices = 9
	}

	today := time.Now().Format("2006-01-02")
	s.db.QueryRow("SELECT COUNT(*) FROM connections WHERE timestamp >= ?", today).Scan(&stats.TodayConns)
	s.db.QueryRow("SELECT COUNT(*) FROM connections").Scan(&stats.TotalConns)
	s.db.QueryRow("SELECT COUNT(DISTINCT remote_ip) FROM connections WHERE timestamp >= ?", today).Scan(&stats.Attackers)
	s.db.QueryRow("SELECT COUNT(*) FROM attack_events WHERE timestamp >= ?", today).Scan(&stats.CounterHits)
	s.db.QueryRow("SELECT COUNT(*) FROM fingerprints").Scan(&stats.FingerprintCnt)

	// 按服务统计连接数
	rows, err := s.db.Query("SELECT service, COUNT(*) as cnt FROM connections GROUP BY service ORDER BY cnt DESC")
	if err == nil {
		defer rows.Close()
		for rows.Next() {
			var svc string
			var cnt int
			if rows.Scan(&svc, &cnt) == nil {
				stats.ByService[svc] = cnt
			}
		}
	}

	// 按工具统计攻击数
	rows2, err := s.db.Query("SELECT tool_name, COUNT(*) as cnt FROM attack_events GROUP BY tool_name ORDER BY cnt DESC")
	if err == nil {
		defer rows2.Close()
		for rows2.Next() {
			var tool string
			var cnt int
			if rows2.Scan(&tool, &cnt) == nil {
				stats.ByTool[tool] = cnt
			}
		}
	}

	// TOP 10 攻击者
	rows3, err := s.db.Query(`
		SELECT remote_ip, MIN(timestamp), MAX(timestamp), COUNT(*),
		       (SELECT COUNT(*) FROM attack_events WHERE remote_ip = c.remote_ip),
		       (SELECT GROUP_CONCAT(DISTINCT service) FROM connections WHERE remote_ip = c.remote_ip),
		       (SELECT GROUP_CONCAT(DISTINCT user_agent) FROM connections WHERE remote_ip = c.remote_ip AND user_agent != '')
		FROM connections c
		GROUP BY remote_ip
		ORDER BY COUNT(*) DESC LIMIT 10
	`)
	if err == nil {
		defer rows3.Close()
		for rows3.Next() {
			var a AttackerSummary
			var first, last string
			if rows3.Scan(&a.RemoteIP, &first, &last, &a.ConnCnt, &a.BreadcrumbCnt, &a.Services, &a.UserAgents) == nil {
				a.FirstSeen = first
				a.LastSeen = last
				a.AttackCnt = a.BreadcrumbCnt + a.ConnCnt
				stats.TopAttackers = append(stats.TopAttackers, a)
			}
		}
	}

	return stats, nil
}

// GetTopologyData 生成攻击路径拓扑数据
func (s *Store) GetTopologyData() (*TopologyData, error) {
	td := &TopologyData{
		Nodes: make([]TopoNode, 0),
		Edges: make([]TopoEdge, 0),
	}

	// 1. 攻击者节点 — 来自最近 200 条连接的独特 IP
	conns, err := s.GetConnections(200)
	if err != nil {
		return nil, err
	}
	ipSet := make(map[string]bool)
	ipServices := make(map[string]map[string]bool)
	for _, c := range conns {
		ipSet[c.RemoteIP] = true
		if ipServices[c.RemoteIP] == nil {
			ipServices[c.RemoteIP] = make(map[string]bool)
		}
		ipServices[c.RemoteIP][c.Service] = true
	}

	for ip := range ipSet {
		svcList := make([]string, 0)
		for svc := range ipServices[ip] {
			svcList = append(svcList, svc)
		}
		td.Nodes = append(td.Nodes, TopoNode{
			ID:    "attacker-" + ip,
			Label: ip,
			Type:  "attacker",
			IP:    ip,
			Data: map[string]interface{}{
				"services": svcList,
			},
		})
	}

	// 2. 蜜罐服务节点 — 9 个协议
	services := []string{"HTTP", "MySQL", "Redis", "SSH", "FTP", "LDAP", "DNS", "SMB", "RDP"}
	for _, svc := range services {
		td.Nodes = append(td.Nodes, TopoNode{
			ID:    "honeypot-" + svc,
			Label: svc + "蜜罐",
			Type:  "honeypot",
			IP:    "0.0.0.0",
			Data: map[string]interface{}{
				"service": svc,
			},
		})
	}

	// 3. 核心资产节点（虚拟）
	coreAssets := []struct {
		id, label string
	}{
		{"asset-core", "核心数据库"},
		{"asset-api", "API网关"},
		{"asset-admin", "管理后台"},
	}
	for _, a := range coreAssets {
		td.Nodes = append(td.Nodes, TopoNode{
			ID:     a.id,
			Label:  a.label,
			Type:   "asset",
			Status: "protected",
			Data: map[string]interface{}{
				"description": "内部核心资产",
			},
		})
	}

	// 4. 边 — 攻击者 ↔ 蜜罐（攻击路径）
	for _, c := range conns {
		attackerNodeID := "attacker-" + c.RemoteIP
		honeypotNodeID := "honeypot-" + c.Service
		dup := false
		for _, e := range td.Edges {
			if e.Source == attackerNodeID && e.Target == honeypotNodeID {
				dup = true
				break
			}
		}
		if !dup {
			td.Edges = append(td.Edges, TopoEdge{
				Source:   attackerNodeID,
				Target:   honeypotNodeID,
				Label:    c.Service,
				EdgeType: "attack",
				Data: map[string]interface{}{
					"last_time": c.Timestamp.Format("15:04:05"),
				},
			})
		}
	}

	// 5. 边 — 蜜罐 ↔ 核心资产（防守路径，虚线/浅色）
	assetLinks := []struct{ source, target, label string }{
		{"honeypot-HTTP", "asset-admin", "Web入口"},
		{"honeypot-MySQL", "asset-core", "数据库"},
		{"honeypot-Redis", "asset-core", "缓存"},
		{"honeypot-SSH", "asset-core", "运维"},
		{"honeypot-HTTP", "asset-api", "API"},
	}
	for _, al := range assetLinks {
		td.Edges = append(td.Edges, TopoEdge{
			Source:   al.source,
			Target:   al.target,
			Label:    al.label,
			EdgeType: "internal",
		})
	}

	// 6. 反制边 — 面包屑触发（蓝色）
	attacks, _ := s.GetAttacks(100)
	for _, a := range attacks {
		attackerNodeID := "attacker-" + a.RemoteIP
		// 根据路径确定目标服务
		svc := "HTTP" // 默认 HTTP
		honeypotNodeID := "honeypot-" + svc
		td.Edges = append(td.Edges, TopoEdge{
			Source:   honeypotNodeID,
			Target:   attackerNodeID,
			Label:    a.ToolName,
			EdgeType: "countermeasure",
			Data: map[string]interface{}{
				"path":      a.Path,
				"timestamp": a.Timestamp.Format("15:04:05"),
				"attack_id": a.ID,
			},
		})
	}

	return td, nil
}

// GetAttackers 获取攻击者列表（含统计汇总）
func (s *Store) GetAttackers(limit int) ([]AttackerSummary, error) {
	if limit <= 0 {
		limit = 50
	}
	rows, err := s.db.Query(`
		SELECT remote_ip, MIN(timestamp), MAX(timestamp), COUNT(*),
		       (SELECT COUNT(*) FROM attack_events WHERE remote_ip = c.remote_ip),
		       COALESCE((SELECT GROUP_CONCAT(DISTINCT service) FROM connections WHERE remote_ip = c.remote_ip), ''),
		       COALESCE((SELECT GROUP_CONCAT(DISTINCT user_agent) FROM connections WHERE remote_ip = c.remote_ip AND user_agent != ''), '')
		FROM connections c
		GROUP BY remote_ip
		ORDER BY COUNT(*) DESC LIMIT ?
	`, limit)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var results []AttackerSummary
	for rows.Next() {
		var a AttackerSummary
		var first, last string
		if err := rows.Scan(&a.RemoteIP, &first, &last, &a.ConnCnt, &a.BreadcrumbCnt, &a.Services, &a.UserAgents); err != nil {
			continue
		}
		a.FirstSeen = first
		a.LastSeen = last
		a.AttackCnt = a.ConnCnt + a.BreadcrumbCnt
		results = append(results, a)
	}
	return results, rows.Err()
}

// CountermeasureEvent 反制事件 — 记录每次对攻击者部署的反制手段
type CountermeasureEvent struct {
	ID              int64  `json:"id"`
	Timestamp       string `json:"timestamp"`
	RemoteIP        string `json:"remote_ip"`
	TriggerPath     string `json:"trigger_path"`    // 触发反制的面包屑路径
	PayloadType     string `json:"payload_type"`    // 反制载荷类型
	PayloadPreview  string `json:"payload_preview"` // 载荷摘要(前200字符)
	UserAgent       string `json:"user_agent"`
	Effective       bool   `json:"effective"` // 是否有效(攻击者后续是否再次触发面包屑)
	RelatedAttackID int64  `json:"related_attack_id"`
}

// CountermeasureStats 反制统计
type CountermeasureStats struct {
	TotalDeployed  int            `json:"total_deployed"`
	TotalEffective int            `json:"total_effective"`
	ByType         map[string]int `json:"by_type"`
	EffectRate     float64        `json:"effect_rate"`
}

// RecordCountermeasure 记录一次反制部署
func (s *Store) RecordCountermeasure(remoteIP, triggerPath, payloadType, payloadPreview, userAgent string, relatedAttackID int64) (int64, error) {
	res, err := s.db.Exec(
		`INSERT INTO countermeasure_events (remote_ip, trigger_path, payload_type, payload_preview, user_agent, related_attack_id)
		 VALUES (?, ?, ?, ?, ?, ?)`,
		remoteIP, triggerPath, payloadType, payloadPreview, userAgent, relatedAttackID,
	)
	if err != nil {
		return 0, err
	}
	return res.LastInsertId()
}

// GetCountermeasures 获取反制事件列表
func (s *Store) GetCountermeasures(limit int) ([]CountermeasureEvent, error) {
	if limit <= 0 {
		limit = 50
	}
	rows, err := s.db.Query(
		`SELECT id, timestamp, remote_ip, trigger_path, payload_type, payload_preview, user_agent, effective, related_attack_id
		 FROM countermeasure_events ORDER BY timestamp DESC LIMIT ?`,
		limit,
	)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var events []CountermeasureEvent
	for rows.Next() {
		var e CountermeasureEvent
		if err := rows.Scan(&e.ID, &e.Timestamp, &e.RemoteIP, &e.TriggerPath,
			&e.PayloadType, &e.PayloadPreview, &e.UserAgent, &e.Effective, &e.RelatedAttackID); err != nil {
			continue
		}
		events = append(events, e)
	}
	return events, rows.Err()
}

// GetCountermeasureStats 获取反制统计
func (s *Store) GetCountermeasureStats() (*CountermeasureStats, error) {
	cs := &CountermeasureStats{ByType: make(map[string]int)}

	s.db.QueryRow("SELECT COUNT(*) FROM countermeasure_events").Scan(&cs.TotalDeployed)
	s.db.QueryRow("SELECT COUNT(*) FROM countermeasure_events WHERE effective = 1").Scan(&cs.TotalEffective)

	if cs.TotalDeployed > 0 {
		cs.EffectRate = float64(cs.TotalEffective) / float64(cs.TotalDeployed) * 100
	}

	rows, err := s.db.Query("SELECT payload_type, COUNT(*) as cnt FROM countermeasure_events GROUP BY payload_type ORDER BY cnt DESC")
	if err == nil {
		defer rows.Close()
		for rows.Next() {
			var pt string
			var cnt int
			if rows.Scan(&pt, &cnt) == nil {
				cs.ByType[pt] = cnt
			}
		}
	}

	return cs, nil
}

// MarkCountermeasureEffective 标记反制措施为有效（攻击者后续触发面包屑）
func (s *Store) MarkCountermeasureEffective(remoteIP string) error {
	_, err := s.db.Exec(
		`UPDATE countermeasure_events SET effective = 1
		 WHERE remote_ip = ? AND effective = 0
		 ORDER BY timestamp DESC LIMIT 1`,
		remoteIP,
	)
	return err
}

// Close 关闭数据库连接
func (s *Store) Close() error {
	return s.db.Close()
}
