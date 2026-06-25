package fingerprint

import (
	"encoding/json"
	"net"
	"sync"
	"time"

	"github.com/Laji-HoneyPot/honeypot/internal/core/log"
)

// AttackerFingerprint 攻击者综合指纹（多维度浏览器+设备+网络+行为）
type AttackerFingerprint struct {
	IP        string    `json:"ip"`
	Port      int       `json:"port"`
	Timestamp time.Time `json:"timestamp"`

	TCPWindowSize int    `json:"tcp_window_size,omitempty"`
	TCPOptions    string `json:"tcp_options,omitempty"`
	TTL           int    `json:"ttl,omitempty"`

	UserAgent        string   `json:"user_agent,omitempty"`
	SSHClientVersion string   `json:"ssh_client_version,omitempty"`
	SSHImpl          string   `json:"ssh_impl,omitempty"`
	MySQLUsername    string   `json:"mysql_username,omitempty"`
	MySQLQuery       string   `json:"mysql_query,omitempty"`
	FTPUsername      string   `json:"ftp_username,omitempty"`
	FTPPassword      string   `json:"ftp_password,omitempty"`
	RedisCommands    []string `json:"redis_commands,omitempty"`
	TLSSNI           string   `json:"tls_sni,omitempty"`
	TLSVersion       string   `json:"tls_version,omitempty"`
	Service          string   `json:"service,omitempty"`

	ToolName    string `json:"tool_name,omitempty"`
	ToolVersion string `json:"tool_version,omitempty"`

	// 浏览器被动指纹
	CanvasHash    string   `json:"canvas_hash,omitempty"`
	WebGLVendor   string   `json:"webgl_vendor,omitempty"`
	WebGLRenderer string   `json:"webgl_renderer,omitempty"`
	ScreenRes     string   `json:"screen_res,omitempty"`
	ColorDepth    int      `json:"color_depth,omitempty"`
	Timezone      string   `json:"timezone,omitempty"`
	Languages     []string `json:"languages,omitempty"`
	InnerIP       string   `json:"inner_ip,omitempty"` // WebRTC 内网 IP
	BrowserName   string   `json:"browser_name,omitempty"`

	// 扩展设备指纹
	HardwareConcurrency int    `json:"hardware_concurrency,omitempty"` // CPU 核心数
	DeviceMemory        int    `json:"device_memory,omitempty"`        // 设备内存(GB)
	Platform            string `json:"platform,omitempty"`             // 操作系统架构
	ConnectionType      string `json:"connection_type,omitempty"`      // 网络类型 (4g/wifi/ethernet)
	TouchSupport        bool   `json:"touch_support,omitempty"`        // 是否触屏设备
	MaxTouchPoints      int    `json:"max_touch_points,omitempty"`     // 最大触控点数
	AudioHash           string `json:"audio_hash,omitempty"`           // AudioContext 指纹
	MathPrecision       string `json:"math_precision,omitempty"`       // 数学精度指纹
	DoNotTrack          string `json:"do_not_track,omitempty"`         // DNT 状态
	AdBlocker           bool   `json:"ad_blocker,omitempty"`           // 广告拦截器检测
	CookieEnabled       bool   `json:"cookie_enabled,omitempty"`       // Cookie 启用状态
	FontFingerprint     string `json:"font_fingerprint,omitempty"`     // 字体指纹哈希

	// 网络信息
	PublicIP  string   `json:"public_ip,omitempty"`  // 攻击者真实公网 IP
	WebRTCIPs []string `json:"webrtc_ips,omitempty"` // WebRTC 暴露的全部 IP
	Referrer  string   `json:"referrer,omitempty"`   // HTTP Referer 来源

	// 行为轨迹
	VisitCount    int      `json:"visit_count,omitempty"`    // 页面访问次数
	PageSequence  []string `json:"page_sequence,omitempty"`  // 页面浏览路径序列
	TotalStayMS   int64    `json:"total_stay_ms,omitempty"`  // 累计停留时长(毫秒)
	ScrollDepth   int      `json:"scroll_depth,omitempty"`   // 最大滚动深度(px)
	ClickCount    int      `json:"click_count,omitempty"`    // 点击次数
	BreadcrumbHit int      `json:"breadcrumb_hit,omitempty"` // 触发面包屑次数

	SocialAccounts []string `json:"social_accounts,omitempty"`
}

// Collector 攻击者指纹采集器
type Collector struct {
	mu     sync.RWMutex
	logger *log.Logger
	store  map[string]*AttackerFingerprint
}

// NewCollector 创建指纹采集器
func NewCollector(logger *log.Logger) *Collector {
	return &Collector{
		logger: logger,
		store:  make(map[string]*AttackerFingerprint),
	}
}

// RecordConnection 记录新连接的基础信息
func (c *Collector) RecordConnection(remoteAddr string) *AttackerFingerprint {
	host, port, _ := net.SplitHostPort(remoteAddr)
	portNum := 0
	if p, err := net.LookupPort("tcp", port); err == nil {
		portNum = p
	}

	fp := &AttackerFingerprint{
		IP:        host,
		Port:      portNum,
		Timestamp: time.Now(),
	}

	c.mu.Lock()
	if existing, ok := c.store[host]; ok {
		existing.Port = portNum
		existing.Timestamp = fp.Timestamp
	} else {
		c.store[host] = fp
	}
	c.mu.Unlock()

	c.logger.Debugw("fingerprint recorded", "ip", host, "port", portNum)
	return fp
}

// Update 更新攻击者指纹信息
func (c *Collector) Update(ip string, updater func(*AttackerFingerprint)) {
	c.mu.Lock()
	defer c.mu.Unlock()

	if fp, ok := c.store[ip]; ok {
		updater(fp)
	}
}

// Get 获取攻击者指纹
func (c *Collector) Get(ip string) (*AttackerFingerprint, bool) {
	c.mu.RLock()
	defer c.mu.RUnlock()
	fp, ok := c.store[ip]
	return fp, ok
}

// GetAll 获取所有采集到的指纹
func (c *Collector) GetAll() []*AttackerFingerprint {
	c.mu.RLock()
	defer c.mu.RUnlock()
	result := make([]*AttackerFingerprint, 0, len(c.store))
	for _, fp := range c.store {
		result = append(result, fp)
	}
	return result
}

// MergeProtocolData 合并协议层指纹数据到已有记录
func (c *Collector) MergeProtocolData(ip string, data map[string]interface{}) {
	c.mu.Lock()
	defer c.mu.Unlock()

	fp, ok := c.store[ip]
	if !ok {
		fp = &AttackerFingerprint{IP: ip, Timestamp: time.Now()}
		c.store[ip] = fp
	}

	if v, ok := data["service"].(string); ok && v != "" {
		fp.Service = v
	}
	if v, ok := data["ssh_client_version"].(string); ok && v != "" {
		fp.SSHClientVersion = v
	}
	if v, ok := data["ssh_impl"].(string); ok && v != "" {
		fp.SSHImpl = v
	}
	if v, ok := data["mysql_username"].(string); ok && v != "" {
		fp.MySQLUsername = v
	}
	if v, ok := data["mysql_query"].(string); ok && v != "" {
		fp.MySQLQuery = v
	}
	if v, ok := data["ftp_username"].(string); ok && v != "" {
		fp.FTPUsername = v
	}
	if v, ok := data["ftp_password"].(string); ok && v != "" {
		fp.FTPPassword = v
	}
	if v, ok := data["redis_commands"]; ok {
		switch cmds := v.(type) {
		case []string:
			fp.RedisCommands = append(fp.RedisCommands, cmds...)
		case string:
			fp.RedisCommands = append(fp.RedisCommands, cmds)
		}
	}
	if v, ok := data["tls_sni"].(string); ok && v != "" {
		fp.TLSSNI = v
	}
	if v, ok := data["tls_version"].(string); ok && v != "" {
		fp.TLSVersion = v
	}
	if v, ok := data["tcp_window_size"].(float64); ok {
		fp.TCPWindowSize = int(v)
	}

	c.logger.Debugw("protocol fingerprint merged", "ip", ip, "data", data)
}

// DetectTool 根据指纹识别攻击工具（含浏览器识别）
func (c *Collector) DetectTool(fp *AttackerFingerprint) string {
	if fp.UserAgent == "" {
		return "unknown"
	}

	ua := fp.UserAgent

	// Burp Suite
	if containsAny(ua, []string{"Burp Suite", "Java/1."}) {
		return "burpsuite"
	}

	// Cobalt Strike Beacon
	if containsAny(ua, []string{"Mozilla/4.0 (compatible; MSIE 6.0; Windows NT 5.1)"}) {
		return "cobaltstrike"
	}

	// SQLMap
	if containsAny(ua, []string{"sqlmap"}) {
		return "sqlmap"
	}

	// 冰蝎
	if containsAny(ua, []string{"Apache-HttpClient", "okhttp", "Java"}) {
		return "behinder"
	}

	// Nuclei
	if containsAny(ua, []string{"Nuclei", "nuclei"}) {
		return "nuclei"
	}

	// 浏览器识别（用于溯源反制的关键信息）
	if containsAny(ua, []string{"Chrome"}) {
		return "chrome"
	}
	if containsAny(ua, []string{"Firefox"}) {
		return "firefox"
	}
	if containsAny(ua, []string{"Safari"}) && !containsAny(ua, []string{"Chrome"}) {
		return "safari"
	}
	if containsAny(ua, []string{"Edge"}) {
		return "edge"
	}

	return "unknown"
}

func containsAny(s string, substrs []string) bool {
	for _, sub := range substrs {
		for i := 0; i <= len(s)-len(sub); i++ {
			if s[i:i+len(sub)] == sub {
				return true
			}
		}
	}
	return false
}

// ToJSON 序列化指纹
func (fp *AttackerFingerprint) ToJSON() ([]byte, error) {
	return json.Marshal(fp)
}
