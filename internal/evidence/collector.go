// Package evidence 渐进证据收集系统 (v0.20)
//
// 基于正则规则，扫描攻击者命令/请求中的证据信号（子网扫描、ARP缓存、
// 数据库探测、横向移动等），实现渐进式拓扑解锁。
// 每个证据令牌在 per-IP 维度上去重，仅在首次触发时返回。
//
// 设计参考: AlterHive evidence system (Fausto-404/AlterHive)
package evidence

import (
	"regexp"
	"sync"
)

// Token 证据令牌类型
type Token string

// 证据令牌常量
const (
	TokenRouteInfo      Token = "route_info"
	TokenARPTable       Token = "arp_cache"
	TokenSubnetScan     Token = "subnet_scan"
	TokenDBProbe        Token = "db_probe"
	TokenHTTPProbe      Token = "http_probe"
	TokenDomainProbe    Token = "domain_probe"
	TokenLateralProbe   Token = "lateral_probe"
	TokenAppConfig      Token = "app_config"
	TokenAppLog         Token = "app_log"
	TokenServiceEnum    Token = "service_enum"
	TokenPseudoProgress Token = "pseudo_progress"
	TokenPrivEscalation Token = "priv_escalation"
)

// Rule 证据发现规则
type Rule struct {
	Pattern   *regexp.Regexp
	Token     Token
	Category  string // 所属分类
	RiskLevel string // 风险等级
}

// rules 预编译的证据规则列表
var rules []Rule

func init() {
	patterns := []struct {
		regex     string
		token     Token
		category  string
		riskLevel string
	}{
		// 路由/拓扑信息
		{`\bip\s+(route|addr|a)\b`, TokenRouteInfo, "network", "medium"},
		{`\bcat\s+.*/etc/hosts\b`, TokenRouteInfo, "network", "medium"},
		{`\bifconfig\b`, TokenRouteInfo, "network", "medium"},

		// ARP 缓存
		{`\barp\s+-[an]`, TokenARPTable, "network", "medium"},

		// 子网/端口扫描
		{`\b(nmap|fscan)\b`, TokenSubnetScan, "scan", "high"},
		{`\b(ping|traceroute|tracepath)\s+\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}`, TokenSubnetScan, "scan", "high"},
		{`\b(masscan|zmap)\b`, TokenSubnetScan, "scan", "high"},

		// 数据库探测
		{`\b(mysql|mysqldump|mysqladmin)\b`, TokenDBProbe, "database", "high"},
		{`\bredis-cli\b`, TokenDBProbe, "database", "high"},
		{`\b(psql|pg_dump|mongo)\b`, TokenDBProbe, "database", "high"},

		// HTTP/Web 探测
		{`\bcurl\s+http`, TokenHTTPProbe, "web", "medium"},
		{`\bwget\s+`, TokenHTTPProbe, "web", "medium"},
		{`\b(nikto|dirb|gobuster|ffuf|nuclei)\b`, TokenHTTPProbe, "web", "high"},

		// 域渗透
		{`\b(ldapsearch|smbclient|rpcclient)\b`, TokenDomainProbe, "domain", "critical"},
		{`\b(kinit|klist|getST|getTGT|kerberos)\b`, TokenDomainProbe, "domain", "critical"},

		// 横向移动
		{`\bssh\s+\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}`, TokenLateralProbe, "lateral", "critical"},
		{`\bssh\s+\w+@\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}`, TokenLateralProbe, "lateral", "critical"},
		{`\bnc\s+(-z|-v|-w)?\s*\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}`, TokenLateralProbe, "lateral", "high"},
		{`\b(scp|sftp)\s`, TokenLateralProbe, "lateral", "high"},

		// 应用配置窃取
		{`\bcat\s+.*\.env\b`, TokenAppConfig, "credential", "high"},
		{`\benv\b`, TokenAppConfig, "credential", "medium"},
		{`\bprintenv\b`, TokenAppConfig, "credential", "medium"},
		{`\bhistory\b`, TokenAppConfig, "credential", "medium"},
		{`\bcat\s+.*\.git/config\b`, TokenAppConfig, "credential", "high"},
		{`\bcat\s+.*\.kube/config\b`, TokenAppConfig, "credential", "high"},

		// 应用日志探测
		{`\bcat\s+.*app\.log\b`, TokenAppLog, "recon", "medium"},
		{`\bcat\s+.*access\.log\b`, TokenAppLog, "recon", "medium"},
		{`\bjournalctl\b`, TokenAppLog, "recon", "low"},

		// 服务枚举
		{`\bsystemctl\s+(list|status)\b`, TokenServiceEnum, "recon", "medium"},
		{`\bps\s+aux\b`, TokenServiceEnum, "recon", "low"},
		{`\b(netstat|ss)\s+-tlnp\b`, TokenServiceEnum, "recon", "medium"},
		{`\bdocker\s+ps\b`, TokenServiceEnum, "recon", "medium"},
		{`\bkubectl\s+get\b`, TokenServiceEnum, "recon", "medium"},

		// 伪进度信号（凭据搜索）
		{`\bgrep\s+.*password`, TokenPseudoProgress, "credential", "high"},
		{`\bgrep\s+.*secret`, TokenPseudoProgress, "credential", "high"},
		{`\bgrep\s+.*token`, TokenPseudoProgress, "credential", "high"},
		{`\bgrep\s+.*key`, TokenPseudoProgress, "credential", "high"},
		{`\bcat\s+.*shadow\b`, TokenPseudoProgress, "credential", "critical"},
		{`\bfind\s+.*-name\s+.*key`, TokenPseudoProgress, "credential", "high"},
		{`\bfind\s+.*-name\s+.*cred`, TokenPseudoProgress, "credential", "high"},
		{`\bcat\s+.*\/\.aws\/`, TokenPseudoProgress, "credential", "high"},
		{`\bcat\s+.*\/\.docker\/`, TokenPseudoProgress, "credential", "high"},

		// 权限提升
		{`\bsudo\s+`, TokenPrivEscalation, "privilege", "critical"},
		{`\bsu\s+-?\s*\w`, TokenPrivEscalation, "privilege", "critical"},
	}

	for _, p := range patterns {
		rules = append(rules, Rule{
			Pattern:   regexp.MustCompile(`(?i)` + p.regex),
			Token:     p.token,
			Category:  p.category,
			RiskLevel: p.riskLevel,
		})
	}
}

// Hit 证据命中记录
type Hit struct {
	Token     Token  `json:"token"`
	Input     string `json:"input"`
	Category  string `json:"category"`
	RiskLevel string `json:"risk_level"`
}

// Collector per-IP 证据收集器
type Collector struct {
	mu        sync.Mutex
	hitTokens map[string]map[Token]bool // IP -> Set<Token>
}

// NewCollector 创建证据收集器
func NewCollector() *Collector {
	return &Collector{
		hitTokens: make(map[string]map[Token]bool),
	}
}

// Check 扫描一条命令/请求中的证据信号，返回 per-IP 去重后的新命中列表
func (c *Collector) Check(ip, input string) []Hit {
	c.mu.Lock()
	defer c.mu.Unlock()

	ipTokens, exists := c.hitTokens[ip]
	if !exists {
		ipTokens = make(map[Token]bool)
		c.hitTokens[ip] = ipTokens
	}

	var hits []Hit
	for _, rule := range rules {
		if ipTokens[rule.Token] {
			continue
		}
		if rule.Pattern.MatchString(input) {
			ipTokens[rule.Token] = true
			hits = append(hits, Hit{
				Token:     rule.Token,
				Input:     input,
				Category:  rule.Category,
				RiskLevel: rule.RiskLevel,
			})
		}
	}
	return hits
}

// HasToken 检查指定IP是否已收集到某个证据令牌
func (c *Collector) HasToken(ip string, token Token) bool {
	c.mu.Lock()
	defer c.mu.Unlock()

	ipTokens, exists := c.hitTokens[ip]
	if !exists {
		return false
	}
	return ipTokens[token]
}

// CollectedTokens 返回指定IP已收集的证据令牌列表
func (c *Collector) CollectedTokens(ip string) []Token {
	c.mu.Lock()
	defer c.mu.Unlock()

	ipTokens, exists := c.hitTokens[ip]
	if !exists {
		return nil
	}
	tokens := make([]Token, 0, len(ipTokens))
	for t := range ipTokens {
		tokens = append(tokens, t)
	}
	return tokens
}

// HitCount 返回指定IP已收集的证据数量
func (c *Collector) HitCount(ip string) int {
	c.mu.Lock()
	defer c.mu.Unlock()

	ipTokens, exists := c.hitTokens[ip]
	if !exists {
		return 0
	}
	return len(ipTokens)
}

// Reset 重置指定IP的证据收集状态
func (c *Collector) Reset(ip string) {
	c.mu.Lock()
	defer c.mu.Unlock()
	delete(c.hitTokens, ip)
}

// TokenTagName 返回证据令牌的中文标签
func (t Token) TagName() string {
	switch t {
	case TokenRouteInfo:
		return "路由信息"
	case TokenARPTable:
		return "ARP缓存"
	case TokenSubnetScan:
		return "子网扫描"
	case TokenDBProbe:
		return "数据库探测"
	case TokenHTTPProbe:
		return "Web探测"
	case TokenDomainProbe:
		return "域渗透"
	case TokenLateralProbe:
		return "横向移动"
	case TokenAppConfig:
		return "配置窃取"
	case TokenAppLog:
		return "日志探测"
	case TokenServiceEnum:
		return "服务枚举"
	case TokenPseudoProgress:
		return "凭据搜索"
	case TokenPrivEscalation:
		return "提权尝试"
	default:
		return string(t)
	}
}
