// Package cluster 分布式集群通信协议定义
// 管理端与远程蜜罐节点之间通过 TLS 双向认证的 TCP 长连接通信，
// 使用 JSON 编码消息帧（4 字节大端长度前缀 + JSON body）。
//
// 协议分层：
//   传输层: TLS 1.2+ 双向认证 (ECDSA/Ed25519 证书)
//   帧层:   4 字节 BigEndian 长度 + JSON payload
//   消息层: 请求/响应模式，支持服务端推送
//
// 消息类型：
//   register   - 节点上线注册
//   heartbeat  - 周期性心跳 (默认 30s)
//   event_push - 节点主动推送事件 (攻击/指纹/连接)
//   config_sync- 管理端下发配置
package cluster

import "time"

// ---------- 基础类型 ----------

// NodeInfo 蜜罐节点信息（注册时上报）
type NodeInfo struct {
	NodeID    string   `json:"node_id"`    // 节点唯一标识 (hostname-uuid 前8位)
	Hostname  string   `json:"hostname"`   // 主机名
	IP        string   `json:"ip"`         // 节点 IP
	Version   string   `json:"version"`    // 运行版本
	Services  []string `json:"services"`   // 启用的蜜罐服务列表
	OS        string   `json:"os"`         // 操作系统
	Arch      string   `json:"arch"`       // CPU 架构
	StartTime int64    `json:"start_time"` // 启动时间 unix timestamp
}

// NodeState 节点运行时状态
type NodeState struct {
	NodeID    string    `json:"node_id"`
	Online    bool      `json:"online"`
	LastSeen  time.Time `json:"last_seen"`
	// 运行时统计
	Connections int64 `json:"connections"` // 总连接数
	Attacks     int64 `json:"attacks"`     // 攻击事件数
	Fingerprints int64 `json:"fingerprints"` // 采集指纹数
	UptimeSeconds int64 `json:"uptime_seconds"`
}

// ---------- 请求/响应消息 ----------

// Message 通用消息信封
type Message struct {
	Type      string      `json:"type"`      // 消息类型: register/heartbeat/event_push/config_sync
	NodeID    string      `json:"node_id"`   // 发送方节点 ID
	Timestamp int64       `json:"timestamp"` // unix 毫秒时间戳
	Payload   interface{} `json:"payload"`   // 消息载荷 (类型取决于 Type)
}

// RegisterRequest 节点注册请求
type RegisterRequest struct {
	Node NodeInfo `json:"node"`
}

// RegisterResponse 注册响应
type RegisterResponse struct {
	Accepted     bool              `json:"accepted"`
	ManagerID    string            `json:"manager_id"`
	HeartbeatSec int               `json:"heartbeat_sec"` // 服务端要求的心跳间隔 (秒)
	Config       map[string]string `json:"config,omitempty"` // 初始化配置快照
}

// Heartbeat 心跳请求
type Heartbeat struct {
	Stats HeartbeatStats `json:"stats"`
}

// HeartbeatStats 心跳携带的统计信息
type HeartbeatStats struct {
	Connections  int64 `json:"connections"`
	Attacks      int64 `json:"attacks"`
	Fingerprints int64 `json:"fingerprints"`
	MemoryMB     float64 `json:"memory_mb"`
	Goroutines   int     `json:"goroutines"`
	UptimeSec    int64  `json:"uptime_sec"`
}

// HeartbeatResponse 心跳响应
type HeartbeatResponse struct {
	OK           bool              `json:"ok"`
	ConfigUpdate map[string]string `json:"config_update,omitempty"` // 待推送配置变更
}

// EventForward 事件转发 (节点 → 管理端)
type EventForward struct {
	Events []ClusterEvent `json:"events"`
}

// ClusterEvent 集群事件
type ClusterEvent struct {
	Topic     string      `json:"topic"`     // 事件主题: connection/attack/breadcrumb/fingerprint/portscan
	Payload   interface{} `json:"payload"`   // 事件数据
	Timestamp int64       `json:"timestamp"` // unix 毫秒
	RemoteIP  string      `json:"remote_ip,omitempty"`
}

// ConfigSync 配置同步 (管理端 → 节点)
type ConfigSync struct {
	Version int64             `json:"version"` // 配置版本号
	Entries map[string]string `json:"entries"` // 配置键值对
}

// ---------- 升级相关消息 ----------

// UpgradeDispatchMsg 管理端下发升级指令
type UpgradeDispatchMsg struct {
	Version     string `json:"version"`
	URL         string `json:"url"`
	Checksum    string `json:"checksum"`
	Size        int64  `json:"size"`
	MinVersion  string `json:"min_version"`
	ForceUpdate bool   `json:"force_update"`
}

// UpgradeResultMsg 节点上报升级结果
type UpgradeResultMsg struct {
	Success       bool   `json:"success"`
	Version       string `json:"version"`
	Error         string `json:"error,omitempty"`
	DurationMs    int64  `json:"duration_ms"`
	OldVersion    string `json:"old_version,omitempty"`
	RolledBack    bool   `json:"rolled_back,omitempty"`
}

// ---------- 常量 ----------

const (
	MsgTypeRegister        = "register"
	MsgTypeHeartbeat       = "heartbeat"
	MsgTypeEventPush       = "event_push"
	MsgTypeConfigSync      = "config_sync"
	MsgTypeUpgradeDispatch = "upgrade_dispatch"
	MsgTypeUpgradeResult   = "upgrade_result"

	DefaultHeartbeatSec = 30
	DefaultClusterPort  = 8443 // 管理端 gRPC/Cluster 端口
)
