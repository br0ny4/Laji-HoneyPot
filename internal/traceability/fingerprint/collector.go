package fingerprint

import (
	"encoding/json"
	"net"
	"sync"
	"time"

	"github.com/Laji-HoneyPot/honeypot/internal/core/log"
)

// AttackerFingerprint 攻击者综合指纹
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
	RedisCommands    []string `json:"redis_commands,omitempty"`

	ToolName    string `json:"tool_name,omitempty"`
	ToolVersion string `json:"tool_version,omitempty"`

	CanvasHash  string   `json:"canvas_hash,omitempty"`
	WebGLVendor string   `json:"webgl_vendor,omitempty"`
	ScreenRes   string   `json:"screen_res,omitempty"`
	Timezone    string   `json:"timezone,omitempty"`
	Languages   []string `json:"languages,omitempty"`
	InnerIP     string   `json:"inner_ip,omitempty"` // WebRTC 内网 IP
	BrowserName string   `json:"browser_name,omitempty"`

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
