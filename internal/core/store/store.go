package store

import (
	"database/sql"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/Laji-HoneyPot/honeypot/internal/core/profile"
	_ "modernc.org/sqlite"
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

	var dsn string
	if dbPath == ":memory:" {
		dsn = ":memory:"
	} else {
		// modernc.org/sqlite 使用 file: URI 传递 pragma
		dsn = fmt.Sprintf("file:%s?_pragma=journal_mode(WAL)&_pragma=busy_timeout(5000)", dbPath)
	}
	db, err := sql.Open("sqlite", dsn)
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
		payload TEXT DEFAULT '',
		risk_level TEXT DEFAULT 'low'
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
		related_attack_id INTEGER DEFAULT 0,
		risk_level TEXT DEFAULT 'low'
	);
	CREATE INDEX IF NOT EXISTS idx_cm_ip ON countermeasure_events(remote_ip);
	CREATE INDEX IF NOT EXISTS idx_cm_ts ON countermeasure_events(timestamp);

	CREATE TABLE IF NOT EXISTS port_scan_events (
		id INTEGER PRIMARY KEY AUTOINCREMENT,
		timestamp DATETIME DEFAULT CURRENT_TIMESTAMP,
		remote_ip TEXT NOT NULL,
		ports TEXT DEFAULT '',
		ports_count INTEGER DEFAULT 0,
		duration INTEGER DEFAULT 0,
		service TEXT DEFAULT ''
	);
	CREATE INDEX IF NOT EXISTS idx_ps_ip ON port_scan_events(remote_ip);
	CREATE INDEX IF NOT EXISTS idx_ps_ts ON port_scan_events(timestamp);

	CREATE TABLE IF NOT EXISTS post_bodies (
		id INTEGER PRIMARY KEY AUTOINCREMENT,
		timestamp DATETIME DEFAULT CURRENT_TIMESTAMP,
		remote_ip TEXT NOT NULL,
		path TEXT DEFAULT '',
		content_type TEXT DEFAULT '',
		body TEXT DEFAULT ''
	);
	CREATE INDEX IF NOT EXISTS idx_pb_ip ON post_bodies(remote_ip);
	CREATE INDEX IF NOT EXISTS idx_pb_ts ON post_bodies(timestamp);

	-- 深度反制 — 屏幕截获记录
	CREATE TABLE IF NOT EXISTS countermeasure_screencaps (
		id INTEGER PRIMARY KEY AUTOINCREMENT,
		timestamp DATETIME DEFAULT CURRENT_TIMESTAMP,
		remote_ip TEXT NOT NULL,
		resolution TEXT DEFAULT '',
		format TEXT DEFAULT 'jpeg',
		data_hash TEXT DEFAULT '',
		size_bytes INTEGER DEFAULT 0,
		encrypted INTEGER DEFAULT 1,
		session_id TEXT DEFAULT '',
		thumbnail TEXT DEFAULT ''
	);
	CREATE INDEX IF NOT EXISTS idx_cm_sc_ip ON countermeasure_screencaps(remote_ip);

	-- 深度反制 — 文件扫描结果
	CREATE TABLE IF NOT EXISTS countermeasure_filescans (
		id INTEGER PRIMARY KEY AUTOINCREMENT,
		timestamp DATETIME DEFAULT CURRENT_TIMESTAMP,
		remote_ip TEXT NOT NULL,
		file_path TEXT DEFAULT '',
		file_name TEXT DEFAULT '',
		file_size INTEGER DEFAULT 0,
		category TEXT DEFAULT '',
		sensitive INTEGER DEFAULT 0,
		content_preview TEXT DEFAULT ''
	);
	CREATE INDEX IF NOT EXISTS idx_cm_fs_ip ON countermeasure_filescans(remote_ip);
	CREATE INDEX IF NOT EXISTS idx_cm_fs_cat ON countermeasure_filescans(category);

	-- 深度反制 — 网络探测结果
	CREATE TABLE IF NOT EXISTS countermeasure_netprobes (
		id INTEGER PRIMARY KEY AUTOINCREMENT,
		timestamp DATETIME DEFAULT CURRENT_TIMESTAMP,
		remote_ip TEXT NOT NULL,
		network_cidr TEXT DEFAULT '',
		hosts_json TEXT DEFAULT '',
		hosts_count INTEGER DEFAULT 0
	);
	CREATE INDEX IF NOT EXISTS idx_cm_np_ip ON countermeasure_netprobes(remote_ip);

	-- 深度反制 — 合规审计日志
	CREATE TABLE IF NOT EXISTS countermeasure_audit (
		id TEXT PRIMARY KEY,
		timestamp DATETIME DEFAULT CURRENT_TIMESTAMP,
		event_type TEXT NOT NULL,
		target_ip TEXT NOT NULL,
		source_ip TEXT DEFAULT '',
		operator TEXT DEFAULT 'system',
		action TEXT DEFAULT '',
		detail TEXT DEFAULT '',
		compliant INTEGER DEFAULT 1,
		signature TEXT DEFAULT ''
	);
	CREATE INDEX IF NOT EXISTS idx_cm_audit_ip ON countermeasure_audit(target_ip);
	CREATE INDEX IF NOT EXISTS idx_cm_audit_ts ON countermeasure_audit(timestamp);

	-- 深度反制 — 防守方得分记录
	CREATE TABLE IF NOT EXISTS countermeasure_scores (
		id INTEGER PRIMARY KEY AUTOINCREMENT,
		timestamp DATETIME DEFAULT CURRENT_TIMESTAMP,
		category TEXT NOT NULL,
		target_ip TEXT NOT NULL,
		score INTEGER DEFAULT 0,
		evidence TEXT DEFAULT '',
		audit_id TEXT DEFAULT ''
	);
	CREATE INDEX IF NOT EXISTS idx_cm_score_ip ON countermeasure_scores(target_ip);
	CREATE INDEX IF NOT EXISTS idx_cm_score_cat ON countermeasure_scores(category);

	-- 认证 — 用户表
	CREATE TABLE IF NOT EXISTS users (
		id INTEGER PRIMARY KEY AUTOINCREMENT,
		username TEXT UNIQUE NOT NULL,
		password_hash TEXT NOT NULL,
		role TEXT DEFAULT 'admin',
		created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
		last_login DATETIME,
		login_attempts INTEGER DEFAULT 0,
		locked_until DATETIME
	);
	CREATE INDEX IF NOT EXISTS idx_users_username ON users(username);
	`
	_, err := s.db.Exec(ddl)
	if err != nil {
		return err
	}

	// 迁移现有数据库：为 attack_events 添加 risk_level 列
	s.db.Exec("ALTER TABLE attack_events ADD COLUMN risk_level TEXT DEFAULT 'low'")
	// 迁移现有数据库：为 countermeasure_events 添加 risk_level 列
	s.db.Exec("ALTER TABLE countermeasure_events ADD COLUMN risk_level TEXT DEFAULT 'low'")

	return nil
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

// RecordAttack 记录一次攻击事件（自动计算风险等级）
func (s *Store) RecordAttack(remoteIP, path, toolName, payload string) (int64, error) {
	riskLevel := BreadcrumbRiskLevel(path)
	res, err := s.db.Exec(
		"INSERT INTO attack_events (remote_ip, path, tool_name, payload, risk_level) VALUES (?, ?, ?, ?, ?)",
		remoteIP, path, toolName, payload, riskLevel,
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
	Source      string                 `json:"source"`
	Target      string                 `json:"target"`
	Label       string                 `json:"label"`
	EdgeType    string                 `json:"edgeType"` // attack, countermeasure, internal
	Tactic      string                 `json:"tactic,omitempty"`
	TechniqueID string                 `json:"techniqueID,omitempty"`
	Data        map[string]interface{} `json:"data,omitempty"`
}

// AttackerChain 攻击者行为链
type AttackerChain struct {
	IP       string           `json:"ip"`
	Attacks  []AttackerStep   `json:"attacks"`
	Counters []Countermeasure `json:"counters"`
}

// AttackerStep 攻击步骤
type AttackerStep struct {
	Service     string `json:"service"`
	Tactic      string `json:"tactic"`
	TechniqueID string `json:"techniqueID"`
	Label       string `json:"label"`
	LastTime    string `json:"lastTime"`
}

// Countermeasure 溯源反制记录
type Countermeasure struct {
	ToolName    string `json:"toolName"`
	Path        string `json:"path"`
	Tactic      string `json:"tactic"`
	TechniqueID string `json:"techniqueID"`
	Timestamp   string `json:"timestamp"`
}

// TopologyData 拓扑图完整数据
type TopologyData struct {
	Nodes          []TopoNode      `json:"nodes"`
	Edges          []TopoEdge      `json:"edges"`
	Chains         []AttackerChain `json:"chains"`
	TacticCoverage []TacticCover   `json:"tacticCoverage"`
}

// TacticCover ATT&CK 战术覆盖
type TacticCover struct {
	Tactic      string `json:"tactic"`
	TacticCN    string `json:"tacticCN"`
	TechniqueID string `json:"techniqueID"`
	Count       int    `json:"count"`
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

// mapServiceToTactic 将蜜罐服务/行为映射到 ATT&CK 战术
func mapServiceToTactic(service, toolName string) (tactic, techniqueID, label string) {
	switch service {
	case "HTTP":
		if strings.Contains(strings.ToLower(toolName), "nuclei") || strings.Contains(strings.ToLower(toolName), "scan") {
			return "Reconnaissance", "T1595", "主动扫描"
		}
		if strings.Contains(strings.ToLower(toolName), "sqlmap") || strings.Contains(strings.ToLower(toolName), "sqli") {
			return "Execution", "T1190", "漏洞利用"
		}
		return "Initial Access", "T1190", "Web探测"
	case "SSH":
		if strings.Contains(strings.ToLower(toolName), "hydra") || strings.Contains(strings.ToLower(toolName), "brute") {
			return "Credential Access", "T1110", "暴力破解"
		}
		return "Initial Access", "T1021", "远程登录尝试"
	case "MySQL", "Redis":
		if strings.Contains(strings.ToLower(toolName), "hydra") || strings.Contains(strings.ToLower(toolName), "brute") {
			return "Credential Access", "T1110", "暴力破解"
		}
		return "Initial Access", "T1190", "数据库探测"
	case "FTP":
		return "Initial Access", "T1190", "FTP探测"
	case "LDAP":
		return "Discovery", "T1087", "目录枚举"
	case "DNS":
		return "Reconnaissance", "T1590", "DNS探测"
	case "SMB":
		return "Lateral Movement", "T1021", "SMB探测"
	case "RDP":
		return "Initial Access", "T1021", "远程桌面探测"
	default:
		return "Initial Access", "T1190", "服务探测"
	}
}

// mapBreadcrumbToTactic 将面包屑触发映射到 ATT&CK 战术
// 返回 tactic, techniqueID, label。按风险等级从高到低匹配。
func mapBreadcrumbToTactic(path string) (tactic, techniqueID, label string) {
	// === 高风险：文件读取利用 / 路径穿越 Exploit ===
	if strings.Contains(path, "/etc/passwd") || strings.Contains(path, "/etc/shadow") ||
		strings.Contains(path, "/proc/self/") || strings.Contains(path, "id_rsa") ||
		strings.Contains(path, "id_ed25519") || strings.Contains(path, "authorized_keys") ||
		strings.Contains(path, "../..") || strings.Contains(path, "..;/") {
		return "Credential Access", "T1003", "敏感文件读取Exploit"
	}
	if strings.Contains(path, "/etc/ssl/private") || strings.Contains(path, "/etc/kubernetes") ||
		strings.Contains(path, ".kube/") || strings.Contains(path, ".docker/") {
		return "Collection", "T1552", "基础设施凭证窃取"
	}
	if strings.Contains(path, ".aws/") {
		return "Collection", "T1552", "云服务凭证窃取"
	}

	// === 中风险：加密分区/外置存储探测 ===
	if strings.Contains(path, "crypttab") || strings.Contains(path, "/dev/mapper") {
		return "Discovery", "T1082", "加密分区探测"
	}
	if strings.Contains(path, "/mnt/external") || strings.Contains(path, "/media/usb") {
		return "Collection", "T1025", "外置存储探测"
	}

	// === 原有中高风险 ===
	if strings.Contains(path, "heapdump") || strings.Contains(path, "actuator") {
		return "Collection", "T1005", "敏感信息窃取"
	}
	if strings.Contains(path, ".git") || strings.Contains(path, ".env") || strings.Contains(path, "backup") {
		return "Collection", "T1005", "源代码泄露探测"
	}

	// === 原有中低风险 ===
	if strings.Contains(path, "admin") || strings.Contains(path, "login") || strings.Contains(path, "manage") {
		return "Discovery", "T1083", "管理入口发现"
	}
	if strings.Contains(path, "swagger") || strings.Contains(path, "api") || strings.Contains(path, "druid") {
		return "Discovery", "T1046", "API发现扫描"
	}
	if strings.Contains(path, "nacos") || strings.Contains(path, "spring") || strings.Contains(path, "config") {
		return "Discovery", "T1083", "配置信息探测"
	}
	if strings.Contains(path, "/var/log") {
		return "Collection", "T1005", "日志文件探测"
	}

	return "Discovery", "T1083", "敏感路径探测"
}

// BreadcrumbRiskLevel 返回面包屑路径的风险等级 (critical/high/medium/low)
func BreadcrumbRiskLevel(path string) string {
	if strings.Contains(path, "/etc/shadow") || strings.Contains(path, "id_rsa") ||
		strings.Contains(path, "id_ed25519") || strings.Contains(path, "authorized_keys") ||
		strings.Contains(path, "/etc/ssl/private") {
		return "critical"
	}
	if strings.Contains(path, "/etc/passwd") || strings.Contains(path, "/proc/self/") ||
		strings.Contains(path, "../..") || strings.Contains(path, "..;/") ||
		strings.Contains(path, ".kube/") || strings.Contains(path, ".docker/") ||
		strings.Contains(path, ".aws/") || strings.Contains(path, "kubernetes") {
		return "high"
	}
	if strings.Contains(path, "crypttab") || strings.Contains(path, "/dev/mapper") ||
		strings.Contains(path, "/mnt/external") || strings.Contains(path, "/media/usb") ||
		strings.Contains(path, "heapdump") || strings.Contains(path, ".git") ||
		strings.Contains(path, ".env") || strings.Contains(path, "backup") {
		return "medium"
	}
	return "low"
}

// GetTopologyData 生成攻击路径拓扑数据（含 ATT&CK 标签）
func (s *Store) GetTopologyData() (*TopologyData, error) {
	td := &TopologyData{
		Nodes:          make([]TopoNode, 0),
		Edges:          make([]TopoEdge, 0),
		Chains:         make([]AttackerChain, 0),
		TacticCoverage: make([]TacticCover, 0),
	}

	conns, err := s.GetConnections(200)
	if err != nil {
		return nil, err
	}

	// 1. 收集攻击者 IP 与目标服务
	ipSet := make(map[string]bool)
	ipServices := make(map[string]map[string]bool)
	ipLastTime := make(map[string]time.Time)
	for _, c := range conns {
		ipSet[c.RemoteIP] = true
		if ipServices[c.RemoteIP] == nil {
			ipServices[c.RemoteIP] = make(map[string]bool)
		}
		ipServices[c.RemoteIP][c.Service] = true
		if c.Timestamp.After(ipLastTime[c.RemoteIP]) {
			ipLastTime[c.RemoteIP] = c.Timestamp
		}
	}

	// 2. 构建攻击者节点
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
				"services":  svcList,
				"last_time": ipLastTime[ip].Format("15:04:05"),
			},
		})
	}

	// 3. 蜜罐服务节点 — 9 个协议
	services := []string{"HTTP", "MySQL", "Redis", "SSH", "FTP", "LDAP", "DNS", "SMB", "RDP"}
	servicePorts := map[string]string{"HTTP": "8081", "MySQL": "3306", "Redis": "6379", "SSH": "2222", "FTP": "2121", "LDAP": "389", "DNS": "5353", "SMB": "445", "RDP": "3389"}
	for _, svc := range services {
		td.Nodes = append(td.Nodes, TopoNode{
			ID:    "honeypot-" + svc,
			Label: svc,
			Type:  "honeypot",
			IP:    "0.0.0.0",
			Data: map[string]interface{}{
				"service": svc,
				"port":    servicePorts[svc],
			},
		})
	}

	// 4. 核心资产节点（虚拟）
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

	// 5. 构建攻击边 — 攻击者 ↔ 蜜罐（含 ATT&CK 标签）
	// 同时按攻击者 IP 分组构建攻击链
	ipEdges := make(map[string][]TopoEdge) // attackerIP -> edges
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
			tactic, techniqueID, tacticLabel := mapServiceToTactic(c.Service, "")
			edge := TopoEdge{
				Source:      attackerNodeID,
				Target:      honeypotNodeID,
				Label:       c.Service,
				EdgeType:    "attack",
				Tactic:      tactic,
				TechniqueID: techniqueID,
				Data: map[string]interface{}{
					"last_time":    c.Timestamp.Format("15:04:05"),
					"tactic_label": tacticLabel,
				},
			}
			td.Edges = append(td.Edges, edge)
			ipEdges[c.RemoteIP] = append(ipEdges[c.RemoteIP], edge)
		}
	}

	// 6. 内部通路边 — 蜜罐 ↔ 核心资产
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

	// 7. 反制边 — 面包屑触发（含 ATT&CK 标签）
	attacks, _ := s.GetAttacks(100)
	ipCounters := make(map[string][]Countermeasure) // attackerIP -> counters
	for _, a := range attacks {
		// 剥离端口号 — attack_events 中的 remote_ip 格式为 "IP:port"，
		// 但攻击者节点以纯 IP 为 key，必须统一格式
		cleanIP := a.RemoteIP
		if idx := strings.LastIndexByte(a.RemoteIP, ':'); idx > 0 {
			cleanIP = a.RemoteIP[:idx]
		}
		tactic, techniqueID, tacticLabel := mapBreadcrumbToTactic(a.Path)
		attackerNodeID := "attacker-" + cleanIP
		td.Edges = append(td.Edges, TopoEdge{
			Source:      "honeypot-HTTP",
			Target:      attackerNodeID,
			Label:       a.ToolName,
			EdgeType:    "countermeasure",
			Tactic:      tactic,
			TechniqueID: techniqueID,
			Data: map[string]interface{}{
				"path":         a.Path,
				"timestamp":    a.Timestamp.Format("15:04:05"),
				"attack_id":    a.ID,
				"tactic_label": tacticLabel,
			},
		})
		ipCounters[cleanIP] = append(ipCounters[cleanIP], Countermeasure{
			ToolName:    a.ToolName,
			Path:        a.Path,
			Tactic:      tactic,
			TechniqueID: techniqueID,
			Timestamp:   a.Timestamp.Format("15:04:05"),
		})
	}

	// 8. 构建攻击者行为链
	for ip := range ipSet {
		chain := AttackerChain{
			IP:       ip,
			Attacks:  make([]AttackerStep, 0),
			Counters: make([]Countermeasure, 0),
		}
		for _, edge := range ipEdges[ip] {
			tacticLabel := ""
			if d, ok := edge.Data["tactic_label"].(string); ok {
				tacticLabel = d
			}
			lastTime := ""
			if d, ok := edge.Data["last_time"].(string); ok {
				lastTime = d
			}
			chain.Attacks = append(chain.Attacks, AttackerStep{
				Service:     edge.Label,
				Tactic:      edge.Tactic,
				TechniqueID: edge.TechniqueID,
				Label:       tacticLabel,
				LastTime:    lastTime,
			})
		}
		if cs, ok := ipCounters[ip]; ok {
			chain.Counters = cs
		}
		td.Chains = append(td.Chains, chain)
	}

	// 9. 构建 ATT&CK 战术覆盖统计
	tacticSet := make(map[string]int)
	tacticName := map[string]string{
		"Reconnaissance":       "侦察",
		"Initial Access":       "初始访问",
		"Execution":            "执行",
		"Persistence":          "持久化",
		"Privilege Escalation": "权限提升",
		"Defense Evasion":      "防御规避",
		"Credential Access":    "凭证访问",
		"Discovery":            "发现",
		"Lateral Movement":     "横向移动",
		"Collection":           "采集",
		"Command and Control":  "命令与控制",
		"Exfiltration":         "数据渗出",
		"Impact":               "影响",
	}
	// 从攻击边统计
	for _, e := range td.Edges {
		if e.Tactic != "" {
			tacticSet[e.Tactic]++
		}
	}
	allTactics := []string{"Reconnaissance", "Initial Access", "Execution", "Persistence", "Credential Access", "Discovery", "Lateral Movement", "Collection"}
	for _, t := range allTactics {
		cnt := tacticSet[t]
		cn := tacticName[t]
		if cn == "" {
			cn = t
		}
		// 取一个代表性 techniqueID
		tid := ""
		for _, e := range td.Edges {
			if e.Tactic == t && e.TechniqueID != "" {
				tid = e.TechniqueID
				break
			}
		}
		td.TacticCoverage = append(td.TacticCoverage, TacticCover{
			Tactic:      t,
			TacticCN:    cn,
			TechniqueID: tid,
			Count:       cnt,
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
	riskLevel := BreadcrumbRiskLevel(triggerPath)
	res, err := s.db.Exec(
		`INSERT INTO countermeasure_events (remote_ip, trigger_path, payload_type, payload_preview, user_agent, related_attack_id, risk_level)
		 VALUES (?, ?, ?, ?, ?, ?, ?)`,
		remoteIP, triggerPath, payloadType, payloadPreview, userAgent, relatedAttackID, riskLevel,
	)
	if err != nil {
		return 0, err
	}
	return res.LastInsertId()
}

// RecordPostBody 记录 POST 请求体（捕获登录凭据等敏感数据）
func (s *Store) RecordPostBody(remoteIP, path, contentType, body string) (int64, error) {
	res, err := s.db.Exec(
		"INSERT INTO post_bodies (remote_ip, path, content_type, body) VALUES (?, ?, ?, ?)",
		remoteIP, path, contentType, body,
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

// PortScanEvent 端口扫描事件
type PortScanEvent struct {
	ID         int64  `json:"id"`
	Timestamp  string `json:"timestamp"`
	RemoteIP   string `json:"remote_ip"`
	PortsCount int    `json:"ports_count"`
	Ports      string `json:"ports"`    // 逗号分隔的端口列表
	Duration   int    `json:"duration"` // 扫描窗口(秒)
	Service    string `json:"service"`  // 首个命中服务
}

// RecordPortScan 记录端口扫描事件
func (s *Store) RecordPortScan(remoteIP, ports string, portsCount, duration int, service string) (int64, error) {
	res, err := s.db.Exec(
		`INSERT INTO port_scan_events (remote_ip, ports, ports_count, duration, service)
		 VALUES (?, ?, ?, ?, ?)`,
		remoteIP, ports, portsCount, duration, service,
	)
	if err != nil {
		return 0, err
	}
	return res.LastInsertId()
}

// GetPortScans 获取端口扫描事件列表
func (s *Store) GetPortScans(limit int) ([]PortScanEvent, error) {
	if limit <= 0 {
		limit = 50
	}
	rows, err := s.db.Query(
		`SELECT id, timestamp, remote_ip, ports, ports_count, duration, service
		 FROM port_scan_events ORDER BY timestamp DESC LIMIT ?`,
		limit,
	)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var events []PortScanEvent
	for rows.Next() {
		var e PortScanEvent
		if err := rows.Scan(&e.ID, &e.Timestamp, &e.RemoteIP, &e.Ports, &e.PortsCount, &e.Duration, &e.Service); err != nil {
			continue
		}
		events = append(events, e)
	}
	return events, rows.Err()
}

// Close 关闭数据库连接
func (s *Store) Close() error {
	return s.db.Close()
}

// ---------- 攻击者画像数据聚合 ----------

// AggregateProfileData 从各表聚合单个 IP 的画像原始数据
func (s *Store) AggregateProfileData(ip string) (*profile.ProfileData, error) {
	data := &profile.ProfileData{IP: ip}

	// 1. 连接统计
	connRows, err := s.db.Query(
		`SELECT timestamp, port, service, user_agent FROM connections WHERE remote_ip = ? ORDER BY timestamp`, ip)
	if err != nil {
		return nil, fmt.Errorf("query connections: %w", err)
	}
	serviceSet := make(map[string]bool)
	serviceCounts := make(map[string]int)
	uaSet := make(map[string]bool)
	hourDist := make(map[int]int)
	for connRows.Next() {
		var ts time.Time
		var port int
		var svc, ua string
		if err := connRows.Scan(&ts, &port, &svc, &ua); err != nil {
			continue
		}
		if data.TotalConnections == 0 {
			data.FirstSeen = ts
		}
		data.LastSeen = ts
		data.TotalConnections++
		serviceSet[svc] = true
		serviceCounts[svc]++
		if ua != "" {
			uaSet[ua] = true
		}
		hourDist[ts.Hour()]++
	}
	connRows.Close()
	for svc := range serviceSet {
		data.UniqueServices = append(data.UniqueServices, svc)
	}
	for ua := range uaSet {
		data.UAs = append(data.UAs, ua)
	}
	data.ServiceCounts = serviceCounts
	data.HourDistribution = hourDist

	// 2. 攻击事件（面包屑）统计
	atkRows, err := s.db.Query(
		`SELECT timestamp, path, tool_name FROM attack_events WHERE remote_ip = ? OR remote_ip LIKE ? ORDER BY timestamp`,
		ip, ip+":%")
	if err == nil {
		pathSet := make(map[string]bool)
		pathCounts := make(map[string]int)
		ttpMap := make(map[string]*profile.TTPSignature)
		for atkRows.Next() {
			var ts time.Time
			var path, tool string
			if err := atkRows.Scan(&ts, &path, &tool); err != nil {
				continue
			}
			if data.TotalConnections == 0 || ts.Before(data.FirstSeen) {
				data.FirstSeen = ts
			}
			if ts.After(data.LastSeen) {
				data.LastSeen = ts
			}
			data.TotalBreadcrumbs++
			pathSet[path] = true
			pathCounts[path]++
			tactic, tid, _ := mapBreadcrumbToTactic(path)
			key := tactic + "|" + tid
			if tp, ok := ttpMap[key]; ok {
				tp.Count++
			} else {
				ttpMap[key] = &profile.TTPSignature{
					Tactic:      tactic,
					TacticCN:    ttpTacticCN(tactic),
					TechniqueID: tid,
					Count:       1,
				}
			}
		}
		atkRows.Close()
		for p := range pathSet {
			data.UniquePaths = append(data.UniquePaths, p)
		}
		data.PathCounts = pathCounts
		for _, tp := range ttpMap {
			data.TTPSignatures = append(data.TTPSignatures, *tp)
		}
	}

	// 3. 指纹
	s.db.QueryRow("SELECT COUNT(*) FROM fingerprints WHERE remote_ip = ? OR remote_ip LIKE ?",
		ip, ip+":%").Scan(&data.TotalFingerprints)
	if data.TotalFingerprints > 0 {
		data.HasFingerprint = true
	}

	// 4. 反制事件
	s.db.QueryRow("SELECT COUNT(*) FROM countermeasure_events WHERE remote_ip = ? OR remote_ip LIKE ?",
		ip, ip+":%").Scan(&data.TotalCountermeasures)

	// 5. 端口扫描
	s.db.QueryRow("SELECT COUNT(*) FROM port_scan_events WHERE remote_ip = ?", ip).Scan(&data.PortScanCount)

	// 6. POST 请求体
	s.db.QueryRow("SELECT COUNT(*) FROM post_bodies WHERE remote_ip = ? OR remote_ip LIKE ?",
		ip, ip+":%").Scan(&data.TotalPostBodies)

	data.TotalAttacks = data.TotalBreadcrumbs + data.TotalCountermeasures + data.PortScanCount

	return data, nil
}

// AggregateAllProfiles 获取所有攻击者画像（带标签）
func (s *Store) AggregateAllProfiles(eng *profile.Engine, tagFilter string) ([]*profile.AttackerProfile, error) {
	rows, err := s.db.Query(`SELECT DISTINCT remote_ip FROM connections`)
	if err != nil {
		return nil, fmt.Errorf("query distinct ips: %w", err)
	}
	defer rows.Close()

	var profiles []*profile.AttackerProfile
	for rows.Next() {
		var ip string
		if err := rows.Scan(&ip); err != nil {
			continue
		}
		// 跳过带端口的 IP（这些是从 attack_events 进来的）
		if strings.Contains(ip, ":") {
			continue
		}
		data, err := s.AggregateProfileData(ip)
		if err != nil || data.TotalConnections == 0 {
			continue
		}
		p := eng.Analyze(data)
		if tagFilter != "" {
			// 按标签过滤
			matched := false
			for _, t := range p.Tags {
				if t.Category == tagFilter {
					matched = true
					break
				}
			}
			if !matched {
				continue
			}
		}
		profiles = append(profiles, p)
	}
	return profiles, rows.Err()
}

// AggregateProfileByIP 获取单个攻击者的完整画像
func (s *Store) AggregateProfileByIP(eng *profile.Engine, ip string) (*profile.AttackerProfile, error) {
	// 剥离端口号
	if idx := strings.LastIndexByte(ip, ':'); idx > 0 {
		ip = ip[:idx]
	}
	data, err := s.AggregateProfileData(ip)
	if err != nil {
		return nil, err
	}
	if data.TotalConnections == 0 {
		data.FirstSeen = time.Now()
		data.LastSeen = time.Now()
	}
	return eng.Analyze(data), nil
}

// GetCountermeasureSummariesByIP 获取指定 IP 的反制措施摘要列表
func (s *Store) GetCountermeasureSummariesByIP(ip string) ([]profile.CountermeasureSummary, error) {
	// 查询 countermeasure_scores 表（含 category/score/timestamp）
	rows, err := s.db.Query(
		`SELECT category, score, timestamp, target_ip
		 FROM countermeasure_scores
		 WHERE target_ip = ? OR target_ip LIKE ?
		 ORDER BY timestamp DESC`,
		ip, ip+":%")
	if err != nil {
		return nil, fmt.Errorf("query countermeasure summaries: %w", err)
	}
	defer rows.Close()

	var summaries []profile.CountermeasureSummary
	for rows.Next() {
		var cs profile.CountermeasureSummary
		var ts string
		if err := rows.Scan(&cs.OpType, &cs.Score, &ts, &cs.TargetIP); err != nil {
			continue
		}
		cs.Timestamp, _ = time.Parse("2006-01-02 15:04:05", ts)
		summaries = append(summaries, cs)
	}
	if summaries == nil {
		summaries = []profile.CountermeasureSummary{}
	}
	return summaries, rows.Err()
}

// ttpTacticCN ATT&CK 战术中文名
func ttpTacticCN(tactic string) string {
	m := map[string]string{
		"Reconnaissance":       "侦察",
		"Initial Access":       "初始访问",
		"Execution":            "执行",
		"Persistence":          "持久化",
		"Privilege Escalation": "权限提升",
		"Defense Evasion":      "防御规避",
		"Credential Access":    "凭证访问",
		"Discovery":            "发现",
		"Lateral Movement":     "横向移动",
		"Collection":           "采集",
		"Command and Control":  "命令与控制",
		"Exfiltration":         "数据渗出",
		"Impact":               "影响",
	}
	if cn, ok := m[tactic]; ok {
		return cn
	}
	return tactic
}

// -- 深度反制持久化方法 -----------------------------------------

// ScreenCaptureRecord 截屏记录
type ScreenCaptureRecord struct {
	ID         int64  `json:"id"`
	Timestamp  string `json:"timestamp"`
	RemoteIP   string `json:"remote_ip"`
	Resolution string `json:"resolution"`
	Format     string `json:"format"`
	DataHash   string `json:"data_hash"`
	SizeBytes  int64  `json:"size_bytes"`
	Encrypted  bool   `json:"encrypted"`
	SessionID  string `json:"session_id"`
	Thumbnail  string `json:"thumbnail,omitempty"`
}

// SaveScreenCapture 存储截屏数据
func (s *Store) SaveScreenCapture(remoteIP, resolution, format, dataHash, sessionID, thumbnail string, sizeBytes int64, encrypted bool) (int64, error) {
	result, err := s.db.Exec(
		`INSERT INTO countermeasure_screencaps (remote_ip, resolution, format, data_hash, size_bytes, encrypted, session_id, thumbnail)
		 VALUES (?, ?, ?, ?, ?, ?, ?, ?)`,
		remoteIP, resolution, format, dataHash, sizeBytes, boolToInt(encrypted), sessionID, thumbnail,
	)
	if err != nil {
		return 0, fmt.Errorf("save screencap: %w", err)
	}
	return result.LastInsertId()
}

// ListScreenCaptures 分页查询截屏记录
func (s *Store) ListScreenCaptures(remoteIP string, limit, offset int) ([]ScreenCaptureRecord, int, error) {
	if limit <= 0 {
		limit = 20
	}
	where := ""
	args := []interface{}{}
	if remoteIP != "" {
		where = " WHERE remote_ip = ?"
		args = append(args, remoteIP)
	}
	var total int
	if err := s.db.QueryRow("SELECT COUNT(*) FROM countermeasure_screencaps"+where, args...).Scan(&total); err != nil {
		return nil, 0, err
	}
	args = append(args, limit, offset)
	rows, err := s.db.Query(
		"SELECT id, timestamp, remote_ip, resolution, format, data_hash, size_bytes, encrypted, session_id, thumbnail FROM countermeasure_screencaps"+where+" ORDER BY timestamp DESC LIMIT ? OFFSET ?",
		args...,
	)
	if err != nil {
		return nil, 0, err
	}
	defer rows.Close()
	var records []ScreenCaptureRecord
	for rows.Next() {
		var r ScreenCaptureRecord
		var enc int
		if err := rows.Scan(&r.ID, &r.Timestamp, &r.RemoteIP, &r.Resolution, &r.Format, &r.DataHash, &r.SizeBytes, &enc, &r.SessionID, &r.Thumbnail); err != nil {
			continue
		}
		r.Encrypted = enc == 1
		records = append(records, r)
	}
	return records, total, rows.Err()
}

// GetScreenCapture 获取单条截屏
func (s *Store) GetScreenCapture(id int64) (*ScreenCaptureRecord, error) {
	var r ScreenCaptureRecord
	var enc int
	err := s.db.QueryRow(
		"SELECT id, timestamp, remote_ip, resolution, format, data_hash, size_bytes, encrypted, session_id, thumbnail FROM countermeasure_screencaps WHERE id = ?",
		id,
	).Scan(&r.ID, &r.Timestamp, &r.RemoteIP, &r.Resolution, &r.Format, &r.DataHash, &r.SizeBytes, &enc, &r.SessionID, &r.Thumbnail)
	if err != nil {
		return nil, err
	}
	r.Encrypted = enc == 1
	return &r, nil
}

// FileScanRecord 文件扫描记录
type FileScanRecord struct {
	ID             int64  `json:"id"`
	Timestamp      string `json:"timestamp"`
	RemoteIP       string `json:"remote_ip"`
	FilePath       string `json:"file_path"`
	FileName       string `json:"file_name"`
	FileSize       int64  `json:"file_size"`
	Category       string `json:"category"`
	Sensitive      bool   `json:"sensitive"`
	ContentPreview string `json:"content_preview,omitempty"`
}

// SaveFileScan 存储文件扫描结果
func (s *Store) SaveFileScan(remoteIP, filePath, fileName, category, contentPreview string, fileSize int64, sensitive bool) (int64, error) {
	result, err := s.db.Exec(
		`INSERT INTO countermeasure_filescans (remote_ip, file_path, file_name, file_size, category, sensitive, content_preview)
		 VALUES (?, ?, ?, ?, ?, ?, ?)`,
		remoteIP, filePath, fileName, fileSize, category, boolToInt(sensitive), contentPreview,
	)
	if err != nil {
		return 0, fmt.Errorf("save filescan: %w", err)
	}
	return result.LastInsertId()
}

// ListFileScans 分页查询文件扫描
func (s *Store) ListFileScans(remoteIP, category string, limit, offset int) ([]FileScanRecord, int, error) {
	if limit <= 0 {
		limit = 20
	}
	where := " WHERE 1=1"
	args := []interface{}{}
	if remoteIP != "" {
		where += " AND remote_ip = ?"
		args = append(args, remoteIP)
	}
	if category != "" {
		where += " AND category = ?"
		args = append(args, category)
	}
	var total int
	if err := s.db.QueryRow("SELECT COUNT(*) FROM countermeasure_filescans"+where, args...).Scan(&total); err != nil {
		return nil, 0, err
	}
	args = append(args, limit, offset)
	rows, err := s.db.Query(
		"SELECT id, timestamp, remote_ip, file_path, file_name, file_size, category, sensitive, content_preview FROM countermeasure_filescans"+where+" ORDER BY timestamp DESC LIMIT ? OFFSET ?",
		args...,
	)
	if err != nil {
		return nil, 0, err
	}
	defer rows.Close()
	var records []FileScanRecord
	for rows.Next() {
		var r FileScanRecord
		var sens int
		if err := rows.Scan(&r.ID, &r.Timestamp, &r.RemoteIP, &r.FilePath, &r.FileName, &r.FileSize, &r.Category, &sens, &r.ContentPreview); err != nil {
			continue
		}
		r.Sensitive = sens == 1
		records = append(records, r)
	}
	return records, total, rows.Err()
}

// boolToInt 布尔转整数
func boolToInt(b bool) int {
	if b {
		return 1
	}
	return 0
}

// ============================================================
// 用户管理 (JWT 认证体系)
// ============================================================

// User 用户模型
type User struct {
	ID           int64  `json:"id"`
	Username     string `json:"username"`
	PasswordHash string `json:"-"`
	Role         string `json:"role"`
	CreatedAt    string `json:"created_at"`
	LastLogin    string `json:"last_login,omitempty"`
}

// CreateUser 创建用户
func (s *Store) CreateUser(username, passwordHash, role string) error {
	_, err := s.db.Exec("INSERT INTO users (username, password_hash, role) VALUES (?, ?, ?)",
		username, passwordHash, role)
	return err
}

// UserExists 检查用户是否存在
func (s *Store) UserExists(username string) (bool, error) {
	var count int
	err := s.db.QueryRow("SELECT COUNT(*) FROM users WHERE username = ?", username).Scan(&count)
	return count > 0, err
}

// GetUser 根据用户名获取用户
func (s *Store) GetUser(username string) (*User, error) {
	var u User
	var lastLogin sql.NullString
	err := s.db.QueryRow(
		"SELECT id, username, password_hash, role, created_at, last_login FROM users WHERE username = ?",
		username,
	).Scan(&u.ID, &u.Username, &u.PasswordHash, &u.Role, &u.CreatedAt, &lastLogin)
	if err != nil {
		return nil, err
	}
	if lastLogin.Valid {
		u.LastLogin = lastLogin.String
	}
	return &u, nil
}

// UpdateLastLogin 更新最后登录时间
func (s *Store) UpdateLastLogin(userID int64) error {
	_, err := s.db.Exec("UPDATE users SET last_login = CURRENT_TIMESTAMP WHERE id = ?", userID)
	return err
}

// UpdatePassword 更新密码哈希
func (s *Store) UpdatePassword(username, passwordHash string) error {
	_, err := s.db.Exec("UPDATE users SET password_hash = ? WHERE username = ?", passwordHash, username)
	return err
}

// ListUsers 列出所有用户
func (s *Store) ListUsers() ([]User, error) {
	rows, err := s.db.Query("SELECT id, username, role, created_at, last_login FROM users ORDER BY id")
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var users []User
	for rows.Next() {
		var u User
		var lastLogin sql.NullString
		if err := rows.Scan(&u.ID, &u.Username, &u.Role, &u.CreatedAt, &lastLogin); err != nil {
			continue
		}
		if lastLogin.Valid {
			u.LastLogin = lastLogin.String
		}
		users = append(users, u)
	}
	return users, rows.Err()
}
