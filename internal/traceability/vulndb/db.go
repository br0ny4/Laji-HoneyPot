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
		// === 文件读取类漏洞利用 ===
		{
			ID:          "CVE-2021-44228",
			Tool:        "log4j",
			Title:       "Log4Shell JNDI 注入导致远程代码执行",
			Description: "Apache Log4j2 2.0-2.14.1 存在 JNDI 注入漏洞，可通过特制日志消息触发 LDAP 回连实现 RCE 及敏感文件读取",
			Severity:    "critical",
			CVE:         "CVE-2021-44228",
			Exploit:     "蜜罐页面嵌入 Log4j JNDI 查找字符串，若攻击者扫描工具存在 Log4Shell 漏洞则触发回连，泄露攻击者环境信息",
			References:  []string{"https://nvd.nist.gov/vuln/detail/CVE-2021-44228"},
			Discovered:  time.Date(2021, 12, 10, 0, 0, 0, 0, time.UTC),
		},
		{
			ID:          "CVE-2022-22963",
			Tool:        "spring_cloud",
			Title:       "Spring Cloud Function SpEL 注入",
			Description: "Spring Cloud Function 3.1.6/3.2.2 及之前版本存在 SpEL 表达式注入漏洞，可导致任意文件读取与 RCE",
			Severity:    "critical",
			CVE:         "CVE-2022-22963",
			Exploit:     "蜜罐返回 Spring Cloud 端点路由，引导攻击者触发 SpEL 表达式注入获取攻击者主机信息",
			References:  []string{"https://nvd.nist.gov/vuln/detail/CVE-2022-22963"},
			Discovered:  time.Date(2022, 3, 29, 0, 0, 0, 0, time.UTC),
		},
		{
			ID:          "CVE-2022-22947",
			Tool:        "spring_gateway",
			Title:       "Spring Cloud Gateway 代码注入",
			Description: "Spring Cloud Gateway 3.1.1/3.0.7 之前版本存在 Actuator 端点的 SpEL 注入，可读取任意文件并执行命令",
			Severity:    "critical",
			CVE:         "CVE-2022-22947",
			Exploit:     "蜜罐暴露 Actuator/gateway 端点，若攻击者利用此漏洞将泄露攻击者环境变量及任意文件",
			References:  []string{"https://nvd.nist.gov/vuln/detail/CVE-2022-22947"},
			Discovered:  time.Date(2022, 3, 3, 0, 0, 0, 0, time.UTC),
		},
		{
			ID:          "CVE-2021-41773",
			Tool:        "apache_httpd",
			Title:       "Apache HTTP Server 路径穿越文件读取",
			Description: "Apache HTTP Server 2.4.49 存在路径穿越漏洞，攻击者可通过特制 URL 读取服务器任意文件（如 /etc/passwd）",
			Severity:    "high",
			CVE:         "CVE-2021-41773",
			Exploit:     "蜜罐模拟 Apache 2.4.49 响应路径穿越请求，记录攻击者文件读取目标与手法特征",
			References:  []string{"https://nvd.nist.gov/vuln/detail/CVE-2021-41773"},
			Discovered:  time.Date(2021, 10, 5, 0, 0, 0, 0, time.UTC),
		},
		{
			ID:          "CVE-2021-42013",
			Tool:        "apache_httpd",
			Title:       "Apache HTTP Server 路径穿越RCE (CVE-2021-41773 变体)",
			Description: "Apache HTTP Server 2.4.50 未完全修复 CVE-2021-41773，攻击者仍可通过路径穿越实现任意文件读取与 RCE",
			Severity:    "critical",
			CVE:         "CVE-2021-42013",
			Exploit:     "蜜罐检测路径穿越变种攻击（..%%32%65, .%2e 编码绕道），捕获高级文件读取 Exploit 行为",
			References:  []string{"https://nvd.nist.gov/vuln/detail/CVE-2021-42013"},
			Discovered:  time.Date(2021, 10, 7, 0, 0, 0, 0, time.UTC),
		},
		{
			ID:          "CVE-2019-3799",
			Tool:        "spring_cloud",
			Title:       "Spring Cloud Config 目录穿越",
			Description: "Spring Cloud Config 2.1.2 之前版本存在目录穿越漏洞，攻击者可读取服务端任意文件（含凭据、密钥）",
			Severity:    "high",
			CVE:         "CVE-2019-3799",
			Exploit:     "蜜罐暴露 Spring Cloud Config 端点，若攻击者利用目录穿越将读取蜜罐内预置的蜜标凭据文件",
			References:  []string{"https://nvd.nist.gov/vuln/detail/CVE-2019-3799"},
			Discovered:  time.Date(2019, 4, 8, 0, 0, 0, 0, time.UTC),
		},
		// === 截屏/录屏劫持类漏洞 ===
		{
			ID:          "CVE-2023-3079",
			Tool:        "chrome",
			Title:       "Chrome V8 类型混淆（截屏/录屏劫持）",
			Description: "Chrome 114 之前版本 V8 引擎存在类型混淆漏洞，攻击者可通过特制页面绕过 Content Security Policy 并捕获当前页面的屏幕内容",
			Severity:    "high",
			CVE:         "CVE-2023-3079",
			Exploit:     "通过页面嵌入 Canvas 像素嗅探与 CSS 时序攻击，间接获取攻击者浏览器中其他标签页的截图信息",
			References:  []string{"https://nvd.nist.gov/vuln/detail/CVE-2023-3079"},
			Discovered:  time.Date(2023, 6, 5, 0, 0, 0, 0, time.UTC),
		},
		{
			ID:          "SC-2024-001",
			Tool:        "screen_capture",
			Title:       "getDisplayMedia API 滥用检测",
			Description: "攻击者可能使用浏览器 getDisplayMedia API 对蜜罐页面进行截图/录屏以规避溯源，该 API 可被蜜罐前端 JS 主动检测",
			Severity:    "medium",
			Exploit:     "蜜罐页面嵌入 getDisplayMedia API 检测脚本，记录攻击者的屏幕捕获行为特征（视频设备数量、录屏工具名称等）",
		},
		{
			ID:          "SC-2024-002",
			Tool:        "rdp_vnc",
			Title:       "远程桌面/虚拟显示器环境检测",
			Description: "攻击者可能通过 RDP/VNC/虚拟机等方式访问蜜罐以隐藏真实指纹，此类环境存在可检测特征（虚拟GPU、像素深度、色彩深度偏移）",
			Severity:    "medium",
			Exploit:     "蜜罐页面通过 WebGL 渲染器名称、屏幕色彩深度、像素响应时间差异检测远程桌面/虚拟显示环境",
		},
		{
			ID:          "CVE-2024-4671",
			Tool:        "chrome",
			Title:       "Chrome 屏幕捕获沙箱逃逸",
			Description: "Chrome 124 之前版本屏幕捕获 API 存在释放后使用漏洞，攻击者可能利用此漏洞在蜜罐页面中注入恶意代码监控管理员操作",
			Severity:    "high",
			CVE:         "CVE-2024-4671",
			Exploit:     "蜜罐检测攻击者是否启用了屏幕捕获权限，若检测到 getDisplayMedia 调用则记录并尝试逆向追踪",
			References:  []string{"https://nvd.nist.gov/vuln/detail/CVE-2024-4671"},
			Discovered:  time.Date(2024, 5, 13, 0, 0, 0, 0, time.UTC),
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
