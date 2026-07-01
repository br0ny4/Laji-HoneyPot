package countermeasure

import "time"

// OpType 反制操作类型
type OpType string

const (
	OpScreenCapture   OpType = "screen_capture"   // 屏幕截获
	OpFileScan        OpType = "file_scan"        // 目录遍历与文件读取
	OpNetProbe        OpType = "net_probe"        // 横向网络探测
	OpFingerprint     OpType = "fingerprint"      // 指纹采集
	OpEnvDetect       OpType = "env_detect"       // 环境检测
	OpKeyLogger       OpType = "key_logger"       // 键盘记录
	OpClipboardSniff  OpType = "clipboard_sniff"  // 剪贴板嗅探
	OpProcessList     OpType = "process_list"     // 进程列表
)

// Capability 反制能力定义
type Capability struct {
	OpType    OpType `json:"op_type"`
	Name      string `json:"name"`
	Category  string `json:"category"`  // implant / js_payload / native_template
	MaxScore  int    `json:"max_score"` // 单次操作最高得分
	Cooldown  int    `json:"cooldown"`  // 冷却时间(秒)
	Compliant bool   `json:"compliant"` // 是否符合合规要求
}

// ScreenCaptureData 屏幕截获数据
type ScreenCaptureData struct {
	Timestamp  time.Time `json:"timestamp"`
	TargetIP   string    `json:"target_ip"`
	Resolution string    `json:"resolution"`  // 如 "1920x1080"
	Format     string    `json:"format"`      // png / jpeg
	DataHash   string    `json:"data_hash"`   // SHA256
	SizeBytes  int64     `json:"size_bytes"`
	Encrypted  bool      `json:"encrypted"`
	SessionID  string    `json:"session_id"`
}

// FileScanResult 文件扫描结果
type FileScanResult struct {
	Timestamp time.Time `json:"timestamp"`
	TargetIP  string    `json:"target_ip"`
	FilePath  string    `json:"file_path"`
	FileName  string    `json:"file_name"`
	FileSize  int64     `json:"file_size"`
	Category  string    `json:"category"` // doc/script/config/db/log/cache/chat
	MIME      string    `json:"mime"`
	Sensitive bool      `json:"sensitive"`
	Content   string    `json:"content,omitempty"` // 截取的文本片段(前1KB)
}

// NetProbeResult 网络探测结果
type NetProbeResult struct {
	Timestamp   time.Time    `json:"timestamp"`
	TargetIP    string       `json:"target_ip"`
	NetworkCIDR string       `json:"network_cidr"`
	Hosts       []HostAsset  `json:"hosts"`
}

// HostAsset 探测到的主机资产
type HostAsset struct {
	IP          string   `json:"ip"`
	Status      string   `json:"status"` // up / down
	Hostname    string   `json:"hostname,omitempty"`
	OpenPorts   []int    `json:"open_ports"`
	Services    []string `json:"services"`
	Role        string   `json:"role"` // command_node / attack_node / relay / unknown
	Confidence  float64  `json:"confidence"` // 角色识别置信度 0-1
}

// AttackerTeamTopology 攻击者团队拓扑
type AttackerTeamTopology struct {
	GeneratedAt time.Time   `json:"generated_at"`
	EntryPoint  string      `json:"entry_point"` // 已控攻击者 IP (入口)
	TeamSize    int         `json:"team_size"`
	Nodes       []HostAsset `json:"nodes"`
	Edges       []TeamEdge  `json:"edges"`
}

// TeamEdge 团队网络边
type TeamEdge struct {
	Source    string `json:"source"`
	Target    string `json:"target"`
	Relation  string `json:"relation"` // same_subnet / ssh_login / rdp_session / vpn_tunnel
	Confidence float64 `json:"confidence"`
}

// AuditEntry 合规审计记录
type AuditEntry struct {
	ID        string    `json:"id"`
	Timestamp time.Time `json:"timestamp"`
	EventType OpType    `json:"event_type"`
	TargetIP  string    `json:"target_ip"`
	SourceIP  string    `json:"source_ip"` // 防守方操作节点
	Operator  string    `json:"operator"`  // 操作人员/系统
	Action    string    `json:"action"`    // initiate / complete / error / terminate
	Detail    string    `json:"detail"`
	Compliant bool      `json:"compliant"`
	Signature string    `json:"signature"` // 操作签名(防篡改)
}

// ScoreEvent 得分事件
type ScoreEvent struct {
	Timestamp time.Time `json:"timestamp"`
	Category  OpType    `json:"category"`
	TargetIP  string    `json:"target_ip"`
	Score     int       `json:"score"`
	Evidence  string    `json:"evidence"` // 得分依据
	AuditID   string    `json:"audit_id"` // 关联审计记录
}

// Scoreboard 防守方得分总表
type Scoreboard struct {
	TotalScore     int                  `json:"total_score"`
	ByCategory     map[OpType]int       `json:"by_category"`
	ByTarget       map[string]int       `json:"by_target"` // 按目标IP统计
	Events         []ScoreEvent         `json:"events"`
	LastUpdated    time.Time            `json:"last_updated"`
	CapabilityHit  map[OpType]int       `json:"capability_hit"`  // 各能力命中次数
}

// ImplantConfig 植入体配置（攻击者主机上运行的 Agent 参数）
type ImplantConfig struct {
	C2URL        string `json:"c2_url"`        // 回连地址
	BeaconRate   int    `json:"beacon_rate"`   // 心跳间隔(s)
	ScreenRate   int    `json:"screen_rate"`   // 截图间隔(s)
	FileScanDirs []string `json:"file_scan_dirs"` // 敏感目录列表
	NetScanCIDRs []string `json:"net_scan_cidrs"` // 横向探测网段
	EncryptionKey string `json:"encryption_key"`  // AES 加密密钥
	StealthMode  bool   `json:"stealth_mode"`     // 隐蔽模式
}

// CapabilityRegistry 反制能力注册表
var CapabilityRegistry = map[OpType]Capability{
	OpScreenCapture: {
		OpType:    OpScreenCapture,
		Name:      "攻击者主机屏幕截获",
		Category:  "implant",
		MaxScore:  50,
		Cooldown:  5,
		Compliant: true,
	},
	OpFileScan: {
		OpType:    OpFileScan,
		Name:      "攻击者主机目录遍历与敏感文件读取",
		Category:  "implant",
		MaxScore:  30,
		Cooldown:  60,
		Compliant: true,
	},
	OpNetProbe: {
		OpType:    OpNetProbe,
		Name:      "攻击者团队横向网络探测",
		Category:  "implant",
		MaxScore:  40,
		Cooldown:  300,
		Compliant: true,
	},
	OpFingerprint: {
		OpType:    OpFingerprint,
		Name:      "浏览器指纹采集",
		Category:  "js_payload",
		MaxScore:  15,
		Cooldown:  10,
		Compliant: true,
	},
	OpEnvDetect: {
		OpType:    OpEnvDetect,
		Name:      "攻击环境检测",
		Category:  "js_payload",
		MaxScore:  20,
		Cooldown:  30,
		Compliant: true,
	},
}
