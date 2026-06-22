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
		stats.ActiveServices = 7 // HTTP/MySQL/Redis/SSH/FTP/LDAP/DNS
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

// Close 关闭数据库连接
func (s *Store) Close() error {
	return s.db.Close()
}
