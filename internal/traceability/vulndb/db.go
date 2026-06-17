package vulndb

import (
	"sync"
	"time"

	"github.com/Laji-HoneyPot/honeypot/internal/core/log"
)

// VulnEntry 漏洞条目
type VulnEntry struct {
	ID          string    `json:"id"`
	Tool        string    `json:"tool"`
	Title       string    `json:"title"`
	Description string    `json:"description"`
	Severity    string    `json:"severity"`
	CVE         string    `json:"cve"`
	Exploit     string    `json:"exploit"`
	References  []string  `json:"references"`
	Discovered  time.Time `json:"discovered"`
}

// DB 漏洞数据库（内存存储，后续可切换 SQLite/PostgreSQL）
type DB struct {
	mu      sync.RWMutex
	entries map[string]*VulnEntry
	logger  *log.Logger
}

// NewDB 创建漏洞数据库
func NewDB(logger *log.Logger) *DB {
	db := &DB{
		entries: make(map[string]*VulnEntry),
		logger:  logger,
	}
	db.seed()
	return db
}

func (db *DB) seed() {
	entries := []*VulnEntry{
		{
			ID:          "CVE-2022-39197",
			Tool:        "cobaltstrike",
			Title:       "Cobalt Strike Cross-Site Scripting (XSS) in team server",
			Description: "Cobalt Strike 4.7.1 及之前版本的团队服务器存在 XSS 漏洞，允许通过特制 Beacon 配置触发客户端 RCE",
			Severity:    "critical",
			CVE:         "CVE-2022-39197",
			Exploit:     "通过构造恶意 Beacon 元数据，在管理端渲染时执行任意 JavaScript，可获取 CS 团队服务器 IP 及证书信息",
			References:  []string{"https://nvd.nist.gov/vuln/detail/CVE-2022-39197"},
			Discovered:  time.Date(2022, 9, 20, 0, 0, 0, 0, time.UTC),
		},
		{
			ID:          "BD-2023-001",
			Tool:        "behinder",
			Title:       "冰蝎 WebShell 通信特征可被识别并利用",
			Description: "冰蝎 3.x/4.x 的 AES 加密通信模式存在可被流量侧精准识别的固定特征（固定密钥协商包格式、固定 Content-Type 等）",
			Severity:    "high",
			Exploit:     "当检测到冰蝎流量特征时，蜜罐可返回构造的反序列化 Payload，利用 Java/.NET 反序列化链对攻击者实施回击",
		},
		{
			ID:          "BS-2024-001",
			Tool:        "burpsuite",
			Title:       "Burp Collaborator 内网 IP 泄露",
			Description: "Burp Suite Professional 的 Collaborator 功能在 DNS/HTTP 回调中可能暴露攻击者内网 IP 及浏览器指纹",
			Severity:    "medium",
			Exploit:     "蜜罐运营专属 Collaborator 相似域名，收集请求中的内网 DNS 查询来源 IP 及 WebRTC STUN 请求中的内网地址",
		},
		{
			ID:          "CH-2024-001",
			Tool:        "chrome",
			Title:       "浏览器 WebRTC 内网 IP 泄露",
			Description: "Chrome/Firefox 等主流浏览器的 WebRTC 实现默认允许内网 IP 泄露，可用于攻击者溯源定位",
			Severity:    "medium",
			Exploit:     "在蜜罐页面嵌入 WebRTC STUN 请求 JS，收集访问者的内网 IP 地址，实现精准网络定位",
		},
		{
			ID:          "CVE-2024-0519",
			Tool:        "chrome",
			Title:       "Chrome V8 越界内存访问漏洞",
			Description: "Chrome V8 JavaScript 引擎中存在越界内存访问漏洞，攻击者可构造特制 HTML 页面触发远程代码执行",
			Severity:    "critical",
			CVE:         "CVE-2024-0519",
			Exploit:     "在蜜罐页面中嵌入针对旧版 Chrome 的 PoC，若攻击者使用未更新浏览器访问则触发 RCE 获取设备控制权",
			References:  []string{"https://nvd.nist.gov/vuln/detail/CVE-2024-0519"},
			Discovered:  time.Date(2024, 1, 16, 0, 0, 0, 0, time.UTC),
		},
		{
			ID:          "FF-2024-001",
			Tool:        "firefox",
			Title:       "Firefox Cross-Origin 信息泄露",
			Description: "特定版本 Firefox 在跨域 iframe 处理中存在信息泄露，可读取攻击者浏览器的部分状态信息",
			Severity:    "low",
			Exploit:     "蜜罐页面嵌入跨域 iframe 探测脚本，收集攻击者浏览器扩展安装信息，辅助身份画像",
		},
		{
			ID:          "CVE-2023-32784",
			Tool:        "sqlmap",
			Title:       "SQLMap 流量特征可被识别",
			Description: "SQLMap 的 HTTP User-Agent、请求模式、参数组合等特征可被精准识别",
			Severity:    "low",
			Exploit:     "当检测到 SQLMap 自动化扫描时，返回虚假 SQL 注入结果引导攻击者进入更深层蜜罐",
		},
	}

	for _, e := range entries {
		db.entries[e.ID] = e
	}
	db.logger.Infow("vulndb seeded", "count", len(entries))
}

// FindByTool 按工具名查找关联漏洞
func (db *DB) FindByTool(tool string) []*VulnEntry {
	db.mu.RLock()
	defer db.mu.RUnlock()

	var result []*VulnEntry
	for _, e := range db.entries {
		if e.Tool == tool {
			result = append(result, e)
		}
	}
	return result
}

// Get 按 ID 获取漏洞
func (db *DB) Get(id string) (*VulnEntry, bool) {
	db.mu.RLock()
	defer db.mu.RUnlock()
	e, ok := db.entries[id]
	return e, ok
}

// All 获取所有漏洞
func (db *DB) All() []*VulnEntry {
	db.mu.RLock()
	defer db.mu.RUnlock()
	result := make([]*VulnEntry, 0, len(db.entries))
	for _, e := range db.entries {
		result = append(result, e)
	}
	return result
}

// Add 动态添加新漏洞条目
func (db *DB) Add(e *VulnEntry) {
	db.mu.Lock()
	defer db.mu.Unlock()
	if _, exists := db.entries[e.ID]; !exists {
		db.entries[e.ID] = e
		db.logger.Infow("vulndb entry added", "id", e.ID, "tool", e.Tool)
	}
}
