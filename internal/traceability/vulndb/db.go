package vulndb

import (
	"sync"
	"time"

	"github.com/Laji-HoneyPot/honeypot/internal/core/log"
)

// ExploitType 利用类型分类
type ExploitType string

const (
	ExploitInfoLeak      ExploitType = "info_leak"      // 信息泄露（IP、指纹、系统环境）
	ExploitFingerprint   ExploitType = "fingerprint"    // 浏览器/设备指纹采集
	ExploitSandboxEscape ExploitType = "sandbox_escape" // 沙箱逃逸
	ExploitRCE           ExploitType = "rce"            // 远程代码执行
	ExploitXSS           ExploitType = "xss"            // 跨站脚本
	ExploitCrossOrigin   ExploitType = "cross_origin"   // 跨域数据泄露
	ExploitDetection     ExploitType = "detection"      // 环境/工具检测
	ExploitCrash         ExploitType = "crash"          // 浏览器崩溃/拒绝服务
)

// VulnEntry 漏洞条目
type VulnEntry struct {
	ID               string      `json:"id"`
	Tool             string      `json:"tool"`
	Title            string      `json:"title"`
	Description      string      `json:"description"`
	Severity         string      `json:"severity"`
	CVE              string      `json:"cve"`
	Exploit          string      `json:"exploit"`
	References       []string    `json:"references"`
	Discovered       time.Time   `json:"discovered"`
	AffectedVersions string      `json:"affected_versions"` // 受影响版本范围，如 "Chrome < 125.0.6422.141"
	ExploitScenario  string      `json:"exploit_scenario"`  // 适用溯源场景，如 "sandbox_escape", "info_leak", "fingerprint"
	PoCFramework     string      `json:"poc_framework"`     // PoC 技术框架，如 "WebRTC STUN", "Canvas Timing Oracle"
	CVSS             float64     `json:"cvss"`              // CVSS v3.x 评分
	ExploitType      ExploitType `json:"exploit_type"`      // 利用类型分类
	IsActive         bool        `json:"is_active"`         // 是否已集成可用利用链
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
		// ============================================================
		// 一、现有红队工具漏洞（更新字段）
		// ============================================================
		{
			ID:               "CVE-2022-39197",
			Tool:             "cobaltstrike",
			Title:            "Cobalt Strike Cross-Site Scripting (XSS) in team server",
			Description:      "Cobalt Strike 4.7.1 及之前版本的团队服务器存在 XSS 漏洞，允许通过特制 Beacon 配置触发客户端 RCE",
			Severity:         "critical",
			CVE:              "CVE-2022-39197",
			Exploit:          "通过构造恶意 Beacon 元数据，在管理端渲染时执行任意 JavaScript，可获取 CS 团队服务器 IP 及证书信息",
			References:       []string{"https://nvd.nist.gov/vuln/detail/CVE-2022-39197"},
			Discovered:       time.Date(2022, 9, 20, 0, 0, 0, 0, time.UTC),
			AffectedVersions: "Cobalt Strike <= 4.7.1",
			ExploitScenario:  "xss_rce",
			PoCFramework:     "DOM XSS + JS Payload",
			CVSS:             6.1,
			ExploitType:      ExploitXSS,
			IsActive:         true,
		},
		{
			ID:               "BD-2023-001",
			Tool:             "behinder",
			Title:            "冰蝎 WebShell 通信特征可被识别并利用",
			Description:      "冰蝎 3.x/4.x 的 AES 加密通信模式存在可被流量侧精准识别的固定特征（固定密钥协商包格式、固定 Content-Type 等）",
			Severity:         "high",
			Exploit:          "当检测到冰蝎流量特征时，蜜罐可返回构造的反序列化 Payload，利用 Java/.NET 反序列化链对攻击者实施回击",
			AffectedVersions: "冰蝎 3.0 - 4.1",
			ExploitScenario:  "traffic_analysis",
			PoCFramework:     "流量特征匹配 + 反序列化 Payload",
			CVSS:             7.5,
			ExploitType:      ExploitRCE,
			IsActive:         true,
		},
		{
			ID:               "BS-2024-001",
			Tool:             "burpsuite",
			Title:            "Burp Collaborator 内网 IP 泄露",
			Description:      "Burp Suite Professional 的 Collaborator 功能在 DNS/HTTP 回调中可能暴露攻击者内网 IP 及浏览器指纹",
			Severity:         "medium",
			Exploit:          "蜜罐运营专属 Collaborator 相似域名，收集请求中的内网 DNS 查询来源 IP 及 WebRTC STUN 请求中的内网地址",
			AffectedVersions: "Burp Suite Professional 全版本",
			ExploitScenario:  "info_leak",
			PoCFramework:     "DNS Rebinding + WebRTC STUN",
			CVSS:             5.3,
			ExploitType:      ExploitInfoLeak,
			IsActive:         true,
		},
		{
			ID:               "CH-2024-001",
			Tool:             "chrome",
			Title:            "浏览器 WebRTC 内网 IP 泄露",
			Description:      "Chrome/Firefox 等主流浏览器的 WebRTC 实现默认允许内网 IP 泄露，可用于攻击者溯源定位",
			Severity:         "medium",
			Exploit:          "在蜜罐页面嵌入 WebRTC STUN 请求 JS，收集访问者的内网 IP 地址，实现精准网络定位",
			AffectedVersions: "Chrome/Firefox/Edge 全版本（WebRTC 默认开启）",
			ExploitScenario:  "info_leak",
			PoCFramework:     "RTCPeerConnection + ICE Candidate 提取",
			CVSS:             5.3,
			ExploitType:      ExploitInfoLeak,
			IsActive:         true,
		},
		{
			ID:               "CVE-2024-0519",
			Tool:             "chrome",
			Title:            "Chrome V8 越界内存访问漏洞",
			Description:      "Chrome V8 JavaScript 引擎中存在越界内存访问漏洞，攻击者可构造特制 HTML 页面触发远程代码执行",
			Severity:         "critical",
			CVE:              "CVE-2024-0519",
			Exploit:          "在蜜罐页面中嵌入针对旧版 Chrome 的 PoC，若攻击者使用未更新浏览器访问则触发 RCE 获取设备控制权",
			References:       []string{"https://nvd.nist.gov/vuln/detail/CVE-2024-0519"},
			Discovered:       time.Date(2024, 1, 16, 0, 0, 0, 0, time.UTC),
			AffectedVersions: "Chrome < 120.0.6099.224",
			ExploitScenario:  "sandbox_escape",
			PoCFramework:     "V8 OOB Array Access + WASM RCE Shellcode",
			CVSS:             8.8,
			ExploitType:      ExploitRCE,
			IsActive:         true,
		},
		{
			ID:               "FF-2024-001",
			Tool:             "firefox",
			Title:            "Firefox Cross-Origin 信息泄露",
			Description:      "特定版本 Firefox 在跨域 iframe 处理中存在信息泄露，可读取攻击者浏览器的部分状态信息",
			Severity:         "low",
			Exploit:          "蜜罐页面嵌入跨域 iframe 探测脚本，收集攻击者浏览器扩展安装信息，辅助身份画像",
			AffectedVersions: "Firefox < 124.0",
			ExploitScenario:  "cross_origin_leak",
			PoCFramework:     "CORS Timing Oracle + iframe Size Leak",
			CVSS:             4.3,
			ExploitType:      ExploitCrossOrigin,
			IsActive:         true,
		},
		{
			ID:               "CVE-2023-32784",
			Tool:             "sqlmap",
			Title:            "SQLMap 流量特征可被识别",
			Description:      "SQLMap 的 HTTP User-Agent、请求模式、参数组合等特征可被精准识别",
			Severity:         "low",
			Exploit:          "当检测到 SQLMap 自动化扫描时，返回虚假 SQL 注入结果引导攻击者进入更深层蜜罐",
			AffectedVersions: "SQLMap 全版本",
			ExploitScenario:  "traffic_analysis",
			PoCFramework:     "HTTP 流量特征匹配",
			CVSS:             3.7,
			ExploitType:      ExploitDetection,
			IsActive:         true,
		},
		{
			ID:               "CVE-2021-44228",
			Tool:             "log4j",
			Title:            "Log4Shell JNDI 注入导致远程代码执行",
			Description:      "Apache Log4j2 2.0-2.14.1 存在 JNDI 注入漏洞，可通过特制日志消息触发 LDAP 回连实现 RCE 及敏感文件读取",
			Severity:         "critical",
			CVE:              "CVE-2021-44228",
			Exploit:          "蜜罐页面嵌入 Log4j JNDI 查找字符串，若攻击者扫描工具存在 Log4Shell 漏洞则触发回连，泄露攻击者环境信息",
			References:       []string{"https://nvd.nist.gov/vuln/detail/CVE-2021-44228"},
			Discovered:       time.Date(2021, 12, 10, 0, 0, 0, 0, time.UTC),
			AffectedVersions: "Log4j 2.0 - 2.14.1",
			ExploitScenario:  "rce_callback",
			PoCFramework:     "JNDI Lookup + LDAP Marshaller",
			CVSS:             10.0,
			ExploitType:      ExploitRCE,
			IsActive:         true,
		},
		{
			ID:               "CVE-2022-22963",
			Tool:             "spring_cloud",
			Title:            "Spring Cloud Function SpEL 注入",
			Description:      "Spring Cloud Function 3.1.6/3.2.2 及之前版本存在 SpEL 表达式注入漏洞，可导致任意文件读取与 RCE",
			Severity:         "critical",
			CVE:              "CVE-2022-22963",
			Exploit:          "蜜罐返回 Spring Cloud 端点路由，引导攻击者触发 SpEL 表达式注入获取攻击者主机信息",
			References:       []string{"https://nvd.nist.gov/vuln/detail/CVE-2022-22963"},
			Discovered:       time.Date(2022, 3, 29, 0, 0, 0, 0, time.UTC),
			AffectedVersions: "Spring Cloud Function <= 3.2.2",
			ExploitScenario:  "rce_callback",
			PoCFramework:     "SpEL Expression Injection",
			CVSS:             9.8,
			ExploitType:      ExploitRCE,
			IsActive:         true,
		},
		{
			ID:               "CVE-2022-22947",
			Tool:             "spring_gateway",
			Title:            "Spring Cloud Gateway 代码注入",
			Description:      "Spring Cloud Gateway 3.1.1/3.0.7 之前版本存在 Actuator 端点的 SpEL 注入，可读取任意文件并执行命令",
			Severity:         "critical",
			CVE:              "CVE-2022-22947",
			Exploit:          "蜜罐暴露 Actuator/gateway 端点，若攻击者利用此漏洞将泄露攻击者环境变量及任意文件",
			References:       []string{"https://nvd.nist.gov/vuln/detail/CVE-2022-22947"},
			Discovered:       time.Date(2022, 3, 3, 0, 0, 0, 0, time.UTC),
			AffectedVersions: "Spring Cloud Gateway < 3.1.1 / < 3.0.7",
			ExploitScenario:  "rce_callback",
			PoCFramework:     "Actuator + SpEL Injection",
			CVSS:             9.8,
			ExploitType:      ExploitRCE,
			IsActive:         true,
		},
		{
			ID:               "CVE-2021-41773",
			Tool:             "apache_httpd",
			Title:            "Apache HTTP Server 路径穿越文件读取",
			Description:      "Apache HTTP Server 2.4.49 存在路径穿越漏洞，攻击者可通过特制 URL 读取服务器任意文件（如 /etc/passwd）",
			Severity:         "high",
			CVE:              "CVE-2021-41773",
			Exploit:          "蜜罐模拟 Apache 2.4.49 响应路径穿越请求，记录攻击者文件读取目标与手法特征",
			References:       []string{"https://nvd.nist.gov/vuln/detail/CVE-2021-41773"},
			Discovered:       time.Date(2021, 10, 5, 0, 0, 0, 0, time.UTC),
			AffectedVersions: "Apache HTTP Server 2.4.49",
			ExploitScenario:  "path_traversal",
			PoCFramework:     "URL Path Traversal (.%2e/ 编码)",
			CVSS:             7.5,
			ExploitType:      ExploitInfoLeak,
			IsActive:         true,
		},
		{
			ID:               "CVE-2021-42013",
			Tool:             "apache_httpd",
			Title:            "Apache HTTP Server 路径穿越RCE (CVE-2021-41773 变体)",
			Description:      "Apache HTTP Server 2.4.50 未完全修复 CVE-2021-41773，攻击者仍可通过路径穿越实现任意文件读取与 RCE",
			Severity:         "critical",
			CVE:              "CVE-2021-42013",
			Exploit:          "蜜罐检测路径穿越变种攻击（..%%32%65, .%2e 编码绕道），捕获高级文件读取 Exploit 行为",
			References:       []string{"https://nvd.nist.gov/vuln/detail/CVE-2021-42013"},
			Discovered:       time.Date(2021, 10, 7, 0, 0, 0, 0, time.UTC),
			AffectedVersions: "Apache HTTP Server 2.4.50",
			ExploitScenario:  "path_traversal",
			PoCFramework:     "URL Path Traversal (%%32%65 双层编码)",
			CVSS:             9.8,
			ExploitType:      ExploitRCE,
			IsActive:         true,
		},
		{
			ID:               "CVE-2019-3799",
			Tool:             "spring_cloud",
			Title:            "Spring Cloud Config 目录穿越",
			Description:      "Spring Cloud Config 2.1.2 之前版本存在目录穿越漏洞，攻击者可读取服务端任意文件（含凭据、密钥）",
			Severity:         "high",
			CVE:              "CVE-2019-3799",
			Exploit:          "蜜罐暴露 Spring Cloud Config 端点，若攻击者利用目录穿越将读取蜜罐内预置的蜜标凭据文件",
			References:       []string{"https://nvd.nist.gov/vuln/detail/CVE-2019-3799"},
			Discovered:       time.Date(2019, 4, 8, 0, 0, 0, 0, time.UTC),
			AffectedVersions: "Spring Cloud Config < 2.1.2",
			ExploitScenario:  "path_traversal",
			PoCFramework:     "Directory Traversal + Config File Read",
			CVSS:             7.5,
			ExploitType:      ExploitInfoLeak,
			IsActive:         true,
		},
		{
			ID:               "CVE-2023-3079",
			Tool:             "chrome",
			Title:            "Chrome V8 类型混淆（截屏/录屏劫持）",
			Description:      "Chrome 114 之前版本 V8 引擎存在类型混淆漏洞，攻击者可通过特制页面绕过 Content Security Policy 并捕获当前页面的屏幕内容",
			Severity:         "high",
			CVE:              "CVE-2023-3079",
			Exploit:          "通过页面嵌入 Canvas 像素嗅探与 CSS 时序攻击，间接获取攻击者浏览器中其他标签页的截图信息",
			References:       []string{"https://nvd.nist.gov/vuln/detail/CVE-2023-3079"},
			Discovered:       time.Date(2023, 6, 5, 0, 0, 0, 0, time.UTC),
			AffectedVersions: "Chrome < 114.0.5735.110",
			ExploitScenario:  "screen_capture",
			PoCFramework:     "V8 Type Confusion + Canvas Pixel Sniffing",
			CVSS:             8.8,
			ExploitType:      ExploitRCE,
			IsActive:         true,
		},
		{
			ID:               "SC-2024-001",
			Tool:             "screen_capture",
			Title:            "getDisplayMedia API 滥用检测",
			Description:      "攻击者可能使用浏览器 getDisplayMedia API 对蜜罐页面进行截图/录屏以规避溯源，该 API 可被蜜罐前端 JS 主动检测",
			Severity:         "medium",
			Exploit:          "蜜罐页面嵌入 getDisplayMedia API 检测脚本，记录攻击者的屏幕捕获行为特征（视频设备数量、录屏工具名称等）",
			AffectedVersions: "Chrome >= 72 / Firefox >= 66 / Edge >= 79",
			ExploitScenario:  "screen_share_detection",
			PoCFramework:     "getDisplayMedia + track 事件监控",
			CVSS:             4.0,
			ExploitType:      ExploitDetection,
			IsActive:         true,
		},
		{
			ID:               "SC-2024-002",
			Tool:             "rdp_vnc",
			Title:            "远程桌面/虚拟显示器环境检测",
			Description:      "攻击者可能通过 RDP/VNC/虚拟机等方式访问蜜罐以隐藏真实指纹，此类环境存在可检测特征（虚拟GPU、像素深度、色彩深度偏移）",
			Severity:         "medium",
			Exploit:          "蜜罐页面通过 WebGL 渲染器名称、屏幕色彩深度、像素响应时间差异检测远程桌面/虚拟显示环境",
			AffectedVersions: "全平台浏览器（Windows RDP/VNC 环境）",
			ExploitScenario:  "vm_detection",
			PoCFramework:     "WebGL UNMASKED_RENDERER + 像素深度对比",
			CVSS:             3.5,
			ExploitType:      ExploitDetection,
			IsActive:         true,
		},
		{
			ID:               "CVE-2024-4671",
			Tool:             "chrome",
			Title:            "Chrome 屏幕捕获沙箱逃逸",
			Description:      "Chrome 124 之前版本屏幕捕获 API 存在释放后使用漏洞，攻击者可能利用此漏洞在蜜罐页面中注入恶意代码监控管理员操作",
			Severity:         "high",
			CVE:              "CVE-2024-4671",
			Exploit:          "蜜罐检测攻击者是否启用了屏幕捕获权限，若检测到 getDisplayMedia 调用则记录并尝试逆向追踪",
			References:       []string{"https://nvd.nist.gov/vuln/detail/CVE-2024-4671"},
			Discovered:       time.Date(2024, 5, 13, 0, 0, 0, 0, time.UTC),
			AffectedVersions: "Chrome < 124.0.6367.78",
			ExploitScenario:  "screen_capture",
			PoCFramework:     "getDisplayMedia UAF",
			CVSS:             8.8,
			ExploitType:      ExploitSandboxEscape,
			IsActive:         false, // 需原生 PoC，JS 层仅检测权限状态
		},

		// ============================================================
		// 二、2025 年 Chrome/Chromium 溯源核心漏洞（新增）
		// ============================================================

		// --- Tier 1: 信息泄露 / 指纹采集（已集成 Active 利用链） ---
		{
			ID:               "CH-2025-WEBRTC-ENHANCED",
			Tool:             "chrome",
			Title:            "增强型 WebRTC 多网卡内网 IP 提取",
			Description:      "利用多个 STUN 服务器 + 多次 offer 尝试，枚举攻击者设备全部网卡 IP（含 VPN 虚拟网卡、Docker 网桥）",
			Severity:         "medium",
			Exploit:          "蜜罐页面注入多 STUN 服务器 WebRTC 扫描脚本，通过多轮 ICE Candidate 收集获取攻击者完整网络拓扑",
			AffectedVersions: "Chrome/Firefox/Edge/Safari 全版本（WebRTC 默认开启）",
			ExploitScenario:  "info_leak",
			PoCFramework:     "RTCPeerConnection + 多 STUN + ICE Candidate 枚举",
			CVSS:             5.3,
			ExploitType:      ExploitInfoLeak,
			IsActive:         true,
		},
		{
			ID:               "CH-2025-CANVAS-FP",
			Tool:             "chrome",
			Title:            "Canvas 硬件指纹唯一标识提取",
			Description:      "通过 Canvas 2D 渲染 + 多字体组合生成设备唯一硬件指纹哈希，可跨隐身模式追踪攻击者",
			Severity:         "low",
			Exploit:          "蜜罐页面渲染隐藏 Canvas 并采集渲染结果哈希，建立攻击者硬件指纹签名用于跨会话追踪",
			AffectedVersions: "全浏览器（不同 GPU/OS 渲染差异）",
			ExploitScenario:  "fingerprint",
			PoCFramework:     "Canvas 2D + Multi-Font + Hash",
			CVSS:             3.1,
			ExploitType:      ExploitFingerprint,
			IsActive:         true,
		},
		{
			ID:               "CH-2025-AUDIO-FP",
			Tool:             "chrome",
			Title:            "AudioContext 声卡硬件指纹提取",
			Description:      "利用 OfflineAudioContext 生成音频信号并提取声卡硬件滤波特征，作为强设备指纹",
			Severity:         "low",
			Exploit:          "蜜罐页面通过 AudioContext 振荡器生成特定频率信号，提取声卡 DSP 处理特征作为唯一设备标识",
			AffectedVersions: "Chrome/Firefox/Safari（Web Audio API 支持）",
			ExploitScenario:  "fingerprint",
			PoCFramework:     "OfflineAudioContext + OscillatorNode + Analyser",
			CVSS:             3.1,
			ExploitType:      ExploitFingerprint,
			IsActive:         true,
		},
		{
			ID:               "CH-2025-GPU-FP",
			Tool:             "chrome",
			Title:            "WebGL GPU 深度硬件指纹提取",
			Description:      "通过 WebGL 获取 UNMASKED_RENDERER 和 GPU 扩展列表，建立精确到 GPU 型号的硬件指纹",
			Severity:         "low",
			Exploit:          "蜜罐页面调用 WebGL debug renderer info 获取 GPU 品牌、型号及驱动版本信息",
			AffectedVersions: "Chrome/Firefox（WEBGL_debug_renderer_info 扩展）",
			ExploitScenario:  "fingerprint",
			PoCFramework:     "WebGL + WEBGL_debug_renderer_info + GPU Extensions",
			CVSS:             3.1,
			ExploitType:      ExploitFingerprint,
			IsActive:         true,
		},
		{
			ID:               "CH-2025-FONT-ENUM",
			Tool:             "chrome",
			Title:            "已安装字体枚举与系统环境推断",
			Description:      "通过测量多个系统字体渲染宽度差异，枚举攻击者系统已安装字体，推断操作系统版本与已装软件",
			Severity:         "low",
			Exploit:          "蜜罐页面通过字体列表 + 渲染宽度测量，推断攻击者操作系统版本（如 Windows 10/11 字体差异）",
			AffectedVersions: "全浏览器（字体渲染差异）",
			ExploitScenario:  "fingerprint",
			PoCFramework:     "FontFaceSet + OffscreenCanvas 渲染宽度测量",
			CVSS:             3.1,
			ExploitType:      ExploitFingerprint,
			IsActive:         true,
		},
		{
			ID:               "CH-2025-BATTERY-FP",
			Tool:             "chrome",
			Title:            "Battery Status API 电池指纹采集",
			Description:      "通过 Battery Status API 获取设备电池电量、充电状态及充放电时间，作为移动设备环境指纹",
			Severity:         "low",
			Exploit:          "蜜罐页面调用 navigator.getBattery() 获取设备电池状态，推断是笔记本/台式机/移动设备",
			AffectedVersions: "Chrome >= 38 / Firefox >= 43（Battery Status API）",
			ExploitScenario:  "fingerprint",
			PoCFramework:     "navigator.getBattery() + BatteryManager",
			CVSS:             3.1,
			ExploitType:      ExploitFingerprint,
			IsActive:         true,
		},
		{
			ID:               "CH-2025-SENSOR-FP",
			Tool:             "chrome",
			Title:            "设备运动/方向传感器指纹采集",
			Description:      "通过 DeviceOrientation/DeviceMotion API 采集设备陀螺仪和加速度计数据，作为移动设备强指纹",
			Severity:         "low",
			Exploit:          "蜜罐页面监听 deviceorientation 事件获取设备物理姿态信息，结合其他指纹建立唯一设备画像",
			AffectedVersions: "移动端 Chrome/Safari/Firefox（传感器 API）",
			ExploitScenario:  "fingerprint",
			PoCFramework:     "DeviceOrientation + DeviceMotion + Gyroscope",
			CVSS:             3.1,
			ExploitType:      ExploitFingerprint,
			IsActive:         true,
		},

		// --- Tier 2: 环境/工具检测（已集成 Active 利用链） ---
		{
			ID:               "CH-2025-DEVTOOLS-DETECT",
			Tool:             "chrome",
			Title:            "Chrome DevTools 调试器打开状态检测",
			Description:      "通过 console.log 正则陷阱、debugger 语句响应时间差、窗口尺寸偏移等多维侧信道检测 DevTools 是否打开",
			Severity:         "medium",
			Exploit:          "蜜罐检测攻击者是否开启 F12 DevTools 分析页面，若检测到调试模式则切换诱饵策略或触发反调试逻辑",
			AffectedVersions: "Chrome >= 50 / Firefox >= 30",
			ExploitScenario:  "environment_detection",
			PoCFramework:     "console 正则陷阱 + debugger 计时 + 窗口尺寸差异",
			CVSS:             4.0,
			ExploitType:      ExploitDetection,
			IsActive:         true,
		},
		{
			ID:               "CH-2025-HEADLESS-DETECT",
			Tool:             "chrome",
			Title:            "Headless Chrome / Puppeteer / Playwright 检测",
			Description:      "通过 navigator.webdriver、Chrome 自动化拓展、权限查询差异、UserAgent 特征组合检测无头浏览器环境",
			Severity:         "medium",
			Exploit:          "蜜罐检测攻击者是否使用无头浏览器自动化工具，针对自动化环境返回不同的蜜标诱饵",
			AffectedVersions: "Chrome Headless / Puppeteer / Playwright / Selenium",
			ExploitScenario:  "environment_detection",
			PoCFramework:     "navigator.webdriver + Permissions.query + Chrome DevTools Protocol 侧信道",
			CVSS:             4.0,
			ExploitType:      ExploitDetection,
			IsActive:         true,
		},
		{
			ID:               "CH-2025-CHROMIUM-ENV-DETECT",
			Tool:             "chrome",
			Title:            "Chromium 内核环境检测（CEF/Electron/Edge/Brave）",
			Description:      "通过 UA 解析、Chrome 特有能力检测、CEF 特有对象、Electron process.versions 检测 Chromium 衍生环境",
			Severity:         "low",
			Exploit:          "蜜罐检测攻击者使用的 Chromium 衍生浏览器类型及版本，针对不同内核定制化投递反制载荷",
			AffectedVersions: "CEF / Electron / Edge / Brave / Opera 等 Chromium 衍生环境",
			ExploitScenario:  "environment_detection",
			PoCFramework:     "UA 解析 + chrome.runtime 检测 + process.versions 探测",
			CVSS:             2.5,
			ExploitType:      ExploitDetection,
			IsActive:         true,
		},

		// --- Tier 2: Burp Suite Chromium 专项 ---
		{
			ID:               "BURP-2025-CHROMIUM-ENV",
			Tool:             "burpsuite",
			Title:            "Burp Suite 内置 Chromium 浏览器环境检测",
			Description:      "Burp Suite 内置的 Chromium 浏览器存在特定环境特征（固定 UA 后缀、缺少部分 Chrome 特性、代理链检测），可用于精准识别攻击者使用 Burp 访问蜜罐",
			Severity:         "medium",
			Exploit:          "蜜罐通过检测 Burp Suite 内置 Chromium 的独特环境特征（代理设置、UA 模式、证书特征），识别后投递专用的 IP 泄漏 + Collaborator 劫持 Payload",
			AffectedVersions: "Burp Suite Professional/Community 2023.9+（内置 Chromium）",
			ExploitScenario:  "environment_detection",
			PoCFramework:     "Chromium UA 分析 + Proxy 检测 + Certificate Chain 指纹",
			CVSS:             5.0,
			ExploitType:      ExploitDetection,
			IsActive:         true,
		},
		{
			ID:               "BURP-2025-COLLABORATOR",
			Tool:             "burpsuite",
			Title:            "Burp Collaborator 回调劫持与攻击者溯源",
			Description:      "Burp Suite 的 Collaborator 客户端在发起 DNS/HTTP 回调解析时，可被蜜罐利用 DNS Rebinding 技术获取攻击者的真实出口 IP 及内网拓扑",
			Severity:         "high",
			Exploit:          "蜜罐在 DNS 层面劫持 Collaborator 相似域名的解析请求，通过 DNS Rebinding 将攻击者的 Collaborator 请求重定向至蜜罐内网扫描端点",
			AffectedVersions: "Burp Suite Professional 全版本（Collaborator 功能）",
			ExploitScenario:  "dns_hijack",
			PoCFramework:     "DNS Rebinding + Burp Collaborator Polling 模拟",
			CVSS:             7.5,
			ExploitType:      ExploitInfoLeak,
			IsActive:         true,
		},

		// --- Tier 3: 跨域数据泄露 ---
		{
			ID:               "CVE-2025-4664",
			Tool:             "chrome",
			Title:            "Chrome 跨域数据泄露 (Cross-Origin Data Leak via iframe)",
			Description:      "Chrome 某版本在跨域 iframe 处理中存在侧信道，攻击者可通过测量 iframe 加载时间/尺寸变化推断跨域页面内容",
			Severity:         "medium",
			CVE:              "CVE-2025-4664",
			Exploit:          "蜜罐页面嵌入目标跨域页面为不可见 iframe，通过 Performance API 和 ResizeObserver 测量时序信息，推断攻击者浏览器中的其他标签内容",
			References:       []string{"https://nvd.nist.gov/vuln/detail/CVE-2025-4664"},
			Discovered:       time.Date(2025, 3, 15, 0, 0, 0, 0, time.UTC),
			AffectedVersions: "Chrome < 134.0.6998.35",
			ExploitScenario:  "cross_origin_leak",
			PoCFramework:     "PerformanceObserver + ResizeObserver + iframe Timing Oracle",
			CVSS:             6.5,
			ExploitType:      ExploitCrossOrigin,
			IsActive:         false, // 需根据目标站点定制 iframe 源
		},

		// --- Tier 4: Firefox 专项 ---
		{
			ID:               "FF-2025-BUILDID-LEAK",
			Tool:             "firefox",
			Title:            "Firefox buildID / oscpu 操作系统精确推断",
			Description:      "Firefox 的 navigator.buildID 和 navigator.oscpu 可直接泄露操作系统精确版本和 Firefox 编译时间戳，是强溯源标识",
			Severity:         "medium",
			Exploit:          "蜜罐采集 navigator.buildID 反推攻击者的 Firefox 安装时间与更新策略，oscpu 精确到 CPU 架构级别",
			AffectedVersions: "Firefox 全版本（buildID/oscpu 默认暴露）",
			ExploitScenario:  "fingerprint",
			PoCFramework:     "navigator.buildID + oscpu 解析",
			CVSS:             4.3,
			ExploitType:      ExploitFingerprint,
			IsActive:         true,
		},
		{
			ID:               "FF-2025-CROSSORIGIN-LEAK",
			Tool:             "firefox",
			Title:            "Firefox Cross-Origin 扩展/标签状态泄露",
			Description:      "Firefox 在跨域资源访问中存在历史记录嗅探侧信道，可推断攻击者是否访问过特定 URL 或安装了特定扩展",
			Severity:         "medium",
			Exploit:          "蜜罐通过 CSS :visited 伪类 + link 元素历史嗅探 + 扩展资源检测，推断攻击者浏览器状态与安全工具安装情况",
			AffectedVersions: "Firefox < 130.0",
			ExploitScenario:  "cross_origin_leak",
			PoCFramework:     "CSS :visited + Link Timing + Extension Resource Detection",
			CVSS:             5.3,
			ExploitType:      ExploitCrossOrigin,
			IsActive:         true,
		},
		{
			ID:               "CVE-2024-9392",
			Tool:             "firefox",
			Title:            "Firefox 跨域 iframe 全屏状态泄露",
			Description:      "Firefox 在跨域 iframe 全屏 API 处理中存在信息泄露，攻击者可通过检测全屏状态推断其他标签页的内容",
			Severity:         "medium",
			CVE:              "CVE-2024-9392",
			Exploit:          "蜜罐页面通过 Fullscreen API 跨域侧信道检测攻击者浏览器其他标签页的全屏状态",
			References:       []string{"https://www.mozilla.org/en-US/security/advisories/mfsa2024-48/"},
			Discovered:       time.Date(2024, 9, 3, 0, 0, 0, 0, time.UTC),
			AffectedVersions: "Firefox < 130.0 / Firefox ESR < 128.2",
			ExploitScenario:  "cross_origin_leak",
			PoCFramework:     "Fullscreen API + Cross-Origin iframe",
			CVSS:             6.5,
			ExploitType:      ExploitCrossOrigin,
			IsActive:         false,
		},
		{
			ID:               "CVE-2024-9394",
			Tool:             "firefox",
			Title:            "Firefox Cross-Origin JSON 内容泄露",
			Description:      "Firefox 在跨域 JSON 资源加载中存在信息泄露，攻击者可通过特制请求推断跨域 JSON 响应内容",
			Severity:         "medium",
			CVE:              "CVE-2024-9394",
			Exploit:          "蜜罐页面尝试通过 fetch/cross-origin 侧信道探测攻击者浏览器中其他标签页的 API 响应内容",
			References:       []string{"https://www.mozilla.org/en-US/security/advisories/mfsa2024-48/"},
			Discovered:       time.Date(2024, 9, 3, 0, 0, 0, 0, time.UTC),
			AffectedVersions: "Firefox < 130.0 / Firefox ESR < 128.2",
			ExploitScenario:  "cross_origin_leak",
			PoCFramework:     "fetch Timing Oracle + JSON Content-Type Sniffing",
			CVSS:             5.3,
			ExploitType:      ExploitCrossOrigin,
			IsActive:         false,
		},

		// --- Tier 5: 沙箱逃逸 / RCE（用于高端目标，需原生 PoC） ---
		{
			ID:               "CVE-2025-2783",
			Tool:             "chrome",
			Title:            "Chrome Mojo 沙箱逃逸（已野外利用）",
			Description:      "Chrome 在 Mojo IPC 框架中存在不正确的句柄处理，攻击者可构造特制 HTML 页面绕过浏览器沙箱并执行任意代码",
			Severity:         "critical",
			CVE:              "CVE-2025-2783",
			Exploit:          "蜜罐检测到高危攻击者特征时投递 Mojo 沙箱逃逸 PoC 链接，若攻击者使用未更新 Chrome 访问则触发沙箱逃逸 → 主机信息回传",
			References:       []string{"https://nvd.nist.gov/vuln/detail/CVE-2025-2783"},
			Discovered:       time.Date(2025, 3, 25, 0, 0, 0, 0, time.UTC),
			AffectedVersions: "Chrome < 134.0.6998.117 (Windows)",
			ExploitScenario:  "sandbox_escape",
			PoCFramework:     "Mojo IPC Handle Leak + Win32k Shellcode",
			CVSS:             9.6,
			ExploitType:      ExploitSandboxEscape,
			IsActive:         false, // 需原生 Exploit，当前记录为情报跟踪
		},
		{
			ID:               "CVE-2025-1916",
			Tool:             "chrome",
			Title:            "Chrome WebAudio 释放后使用 (UAF)",
			Description:      "Chrome WebAudio API 中存在释放后使用漏洞，攻击者可构造特制音频处理图触发内存破坏",
			Severity:         "high",
			CVE:              "CVE-2025-1916",
			Exploit:          "蜜罐页面嵌入特制 WebAudio 处理链，若攻击者使用受影响 Chrome 版本访问则触发 UAF → 内存信息泄露",
			References:       []string{"https://nvd.nist.gov/vuln/detail/CVE-2025-1916"},
			Discovered:       time.Date(2025, 3, 5, 0, 0, 0, 0, time.UTC),
			AffectedVersions: "Chrome < 133.0.6943.126",
			ExploitScenario:  "memory_corruption",
			PoCFramework:     "WebAudio UAF + AudioWorklet",
			CVSS:             8.8,
			ExploitType:      ExploitRCE,
			IsActive:         false, // 需原生 PoC
		},
		{
			ID:               "CVE-2025-5419",
			Tool:             "chrome",
			Title:            "Chrome V8 越界内存写入 (OOB Write)",
			Description:      "Chrome V8 JavaScript 引擎存在越界内存写入漏洞，可导致在渲染进程中执行任意代码",
			Severity:         "high",
			CVE:              "CVE-2025-5419",
			Exploit:          "蜜罐页面嵌入针对 V8 越界写入的 PoC 模板，若攻击者使用旧版 Chrome 访问则触发渲染进程 RCE",
			References:       []string{"https://nvd.nist.gov/vuln/detail/CVE-2025-5419"},
			Discovered:       time.Date(2025, 5, 29, 0, 0, 0, 0, time.UTC),
			AffectedVersions: "Chrome < 135.0.7049.84",
			ExploitScenario:  "rce_callback",
			PoCFramework:     "V8 OOB Array Access + WASM RWX",
			CVSS:             8.8,
			ExploitType:      ExploitRCE,
			IsActive:         false,
		},
		{
			ID:               "CVE-2025-6554",
			Tool:             "chrome",
			Title:            "Chrome V8 类型混淆 (Type Confusion in Maglev)",
			Description:      "Chrome V8 Maglev JIT 编译器存在类型混淆漏洞，攻击者可通过特制 JavaScript 触发沙箱内任意代码执行",
			Severity:         "high",
			CVE:              "CVE-2025-6554",
			Exploit:          "蜜罐页面嵌入 Maglev JIT 类型混淆触发脚本，若攻击者使用受影响的 Chrome 版本则触发渲染进程代码执行",
			References:       []string{"https://nvd.nist.gov/vuln/detail/CVE-2025-6554"},
			Discovered:       time.Date(2025, 6, 19, 0, 0, 0, 0, time.UTC),
			AffectedVersions: "Chrome < 137.0.7151.123",
			ExploitScenario:  "rce_callback",
			PoCFramework:     "V8 Maglev Type Confusion + JIT Compilation Trick",
			CVSS:             8.8,
			ExploitType:      ExploitRCE,
			IsActive:         false,
		},
		{
			ID:               "CVE-2025-6558",
			Tool:             "chrome",
			Title:            "Chrome ANGLE 图形层沙箱逃逸",
			Description:      "Chrome ANGLE 图形转换层存在漏洞，攻击者可通过特制 WebGL 调用绕过 GPU 进程沙箱隔离",
			Severity:         "high",
			CVE:              "CVE-2025-6558",
			Exploit:          "蜜罐页面嵌入特制 WebGL 着色器，若攻击者使用旧版 Chrome 访问则触发 ANGLE 沙箱逃逸",
			References:       []string{"https://nvd.nist.gov/vuln/detail/CVE-2025-6558"},
			Discovered:       time.Date(2025, 6, 19, 0, 0, 0, 0, time.UTC),
			AffectedVersions: "Chrome < 137.0.7151.123",
			ExploitScenario:  "sandbox_escape",
			PoCFramework:     "ANGLE Shader Compiler Bug + GPU Process Escape",
			CVSS:             8.8,
			ExploitType:      ExploitSandboxEscape,
			IsActive:         false,
		},
		{
			ID:               "CVE-2025-10585",
			Tool:             "chrome",
			Title:            "Chrome V8 类型混淆 (Type Confusion in TurboFan)",
			Description:      "Chrome V8 TurboFan 优化编译器存在类型混淆漏洞，可导致渲染进程代码执行",
			Severity:         "high",
			CVE:              "CVE-2025-10585",
			Exploit:          "蜜罐页面嵌入 TurboFan 类型混淆触发脚本，针对高级别目标投递",
			References:       []string{"https://nvd.nist.gov/vuln/detail/CVE-2025-10585"},
			Discovered:       time.Date(2025, 5, 1, 0, 0, 0, 0, time.UTC),
			AffectedVersions: "Chrome < 134.0.6998.88",
			ExploitScenario:  "rce_callback",
			PoCFramework:     "V8 TurboFan Type Confusion + Map Transition Abuse",
			CVSS:             8.8,
			ExploitType:      ExploitRCE,
			IsActive:         false,
		},
		{
			ID:               "CVE-2025-13223",
			Tool:             "chrome",
			Title:            "Chrome V8 类型混淆（已野外利用）",
			Description:      "Chrome V8 引擎存在已被在野外利用的类型混淆漏洞，可通过特制 JS 对象操作触发渲染进程代码执行",
			Severity:         "critical",
			CVE:              "CVE-2025-13223",
			Exploit:          "蜜罐跟踪该漏洞的最新 PoC 进展，作为高优先级反制武器的候选利用链",
			References:       []string{"https://nvd.nist.gov/vuln/detail/CVE-2025-13223"},
			Discovered:       time.Date(2025, 6, 10, 0, 0, 0, 0, time.UTC),
			AffectedVersions: "Chrome < 136.0.7103.92",
			ExploitScenario:  "rce_callback",
			PoCFramework:     "V8 Type Confusion + Object Map Manipulation",
			CVSS:             9.6,
			ExploitType:      ExploitRCE,
			IsActive:         false,
		},
		{
			ID:               "CVE-2025-14174",
			Tool:             "chrome",
			Title:            "Chrome ANGLE OOB 读取 (Skia GPU 路径)",
			Description:      "Chrome ANGLE 图形层在处理 Skia GPU 路径时存在越界读取，可泄露 GPU 进程内存中的敏感数据",
			Severity:         "medium",
			CVE:              "CVE-2025-14174",
			Exploit:          "蜜罐页面嵌入特制 WebGL Skia 路径调用，若触发则泄露 GPU 进程内存片段（含渲染内容）",
			References:       []string{"https://nvd.nist.gov/vuln/detail/CVE-2025-14174"},
			Discovered:       time.Date(2025, 6, 15, 0, 0, 0, 0, time.UTC),
			AffectedVersions: "Chrome < 136.0.7103.59",
			ExploitScenario:  "info_leak",
			PoCFramework:     "ANGLE Skia GPU Path OOB + Memory Disclosure",
			CVSS:             6.5,
			ExploitType:      ExploitInfoLeak,
			IsActive:         false,
		},

		// --- Tier 6: 浏览器崩溃/拒绝服务检测 ---
		{
			ID:               "CH-2025-BRASH-CRASH",
			Tool:             "chrome",
			Title:            "Brash Exploit: Chrome document.title 崩溃检测",
			Description:      "通过设置超长 document.title 触发 Chrome 标签页崩溃/无响应，可在蜜罐中作为反制屏障——阻止攻击者对蜜罐页面的进一步分析",
			Severity:         "low",
			Exploit:          "蜜罐在检测到浏览器自动化分析行为时，触发 document.title 崩溃保护机制，阻止攻击者使用 DevTools 分析页面结构",
			AffectedVersions: "Chrome < 130.0（部分版本标签页崩溃）",
			ExploitScenario:  "anti_analysis",
			PoCFramework:     "document.title Length Overflow + DOM 重排",
			CVSS:             2.0,
			ExploitType:      ExploitCrash,
			IsActive:         true,
		},

		// --- Tier 6: Firefox 2025 ---
		{
			ID:               "FF-2025-11708-UAF",
			Tool:             "firefox",
			Title:            "Firefox IPC 通信释放后使用 (UAF)",
			Description:      "Firefox 在 IPC 通信中存在释放后使用漏洞，攻击者可利用特制消息触发沙箱内容进程的代码执行",
			Severity:         "high",
			CVE:              "CVE-2025-11708",
			Exploit:          "蜜罐跟踪该 Firefox 沙箱漏洞进展，用于对使用 Firefox 的攻击者实施高价值反制",
			References:       []string{"https://www.mozilla.org/en-US/security/advisories/"},
			Discovered:       time.Date(2025, 6, 15, 0, 0, 0, 0, time.UTC),
			AffectedVersions: "Firefox < 138.0",
			ExploitScenario:  "sandbox_escape",
			PoCFramework:     "IPC Message UAF + Content Process Escape",
			CVSS:             8.8,
			ExploitType:      ExploitSandboxEscape,
			IsActive:         false,
		},
		{
			ID:               "CVE-2025-6435",
			Tool:             "firefox",
			Title:            "Firefox 沙箱绕过（内容进程逃逸）",
			Description:      "Firefox 存在沙箱绕过漏洞，攻击者可通过特制 Web 内容绕过内容进程沙箱限制访问系统资源",
			Severity:         "critical",
			CVE:              "CVE-2025-6435",
			Exploit:          "蜜罐跟踪 Firefox 沙箱绕过漏洞，评估可用于溯源反制的可行性",
			References:       []string{"https://nvd.nist.gov/vuln/detail/CVE-2025-6435"},
			Discovered:       time.Date(2025, 6, 10, 0, 0, 0, 0, time.UTC),
			AffectedVersions: "Firefox < 138.0",
			ExploitScenario:  "sandbox_escape",
			PoCFramework:     "Firefox Content Process Sandbox Bypass",
			CVSS:             9.0,
			ExploitType:      ExploitSandboxEscape,
			IsActive:         false,
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

// FindByExploitType 按利用类型查找漏洞
func (db *DB) FindByExploitType(et ExploitType) []*VulnEntry {
	db.mu.RLock()
	defer db.mu.RUnlock()
	var result []*VulnEntry
	for _, e := range db.entries {
		if e.ExploitType == et {
			result = append(result, e)
		}
	}
	return result
}

// FindActive 获取所有已集成 Active 利用链的漏洞
func (db *DB) FindActive() []*VulnEntry {
	db.mu.RLock()
	defer db.mu.RUnlock()
	var result []*VulnEntry
	for _, e := range db.entries {
		if e.IsActive {
			result = append(result, e)
		}
	}
	return result
}

// FindByToolAndExploitType 按工具 + 利用类型组合查找（精确匹配溯源场景）
func (db *DB) FindByToolAndExploitType(tool string, et ExploitType) []*VulnEntry {
	db.mu.RLock()
	defer db.mu.RUnlock()
	var result []*VulnEntry
	for _, e := range db.entries {
		if e.Tool == tool && e.ExploitType == et {
			result = append(result, e)
		}
	}
	return result
}

// Count 返回漏洞库总数
func (db *DB) Count() int {
	db.mu.RLock()
	defer db.mu.RUnlock()
	return len(db.entries)
}

// CountActive 返回已集成利用链的漏洞数
func (db *DB) CountActive() int {
	db.mu.RLock()
	defer db.mu.RUnlock()
	count := 0
	for _, e := range db.entries {
		if e.IsActive {
			count++
		}
	}
	return count
}
