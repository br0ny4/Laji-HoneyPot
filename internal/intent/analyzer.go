// Package intent 攻击意图分析引擎 (v0.20)
//
// 基于正则的快速命令分类器，将攻击者输入映射到10类意图，
// 为后续的虚拟拓扑扩展、证据收集、伪进度反馈等策略链路提供决策依据。
//
// 设计参考: AlterHive intent analyzer (Fausto-404/AlterHive)
package intent

import (
	"regexp"
)

// Category 攻击意图分类
type Category string

const (
	NetworkScan         Category = "network_scan"
	ServiceProbe        Category = "service_probe"
	HTTPProbe           Category = "http_probe"
	DBProbe             Category = "db_probe"
	EvidenceSearch      Category = "evidence_search"
	DomainProbe         Category = "domain_probe"
	LateralMovement     Category = "lateral_movement"
	PrivilegeEscalation Category = "privilege_escalation"
	DataExfiltration    Category = "data_exfiltration"
	ShellCommand        Category = "shell_command"
	Unknown             Category = "unknown"
)

// Intent 表示一条命令的意图分类结果
type Intent struct {
	Category   Category `json:"category"`
	TargetIP   string   `json:"target_ip,omitempty"`
	Protocol   string   `json:"protocol,omitempty"`
	Confidence float64  `json:"confidence"`
	RawCommand string   `json:"raw_command,omitempty"`
}

var ipPattern = regexp.MustCompile(`\b(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})\b`)

type intentPattern struct {
	regex      *regexp.Regexp
	category   Category
	confidence float64
}

var patterns []intentPattern

func init() {
	defs := []struct {
		regexStr   string
		category   Category
		confidence float64
	}{
		// 网络扫描
		{`\b(nmap|fscan)\b`, NetworkScan, 0.95},
		{`\bping\s+\d`, NetworkScan, 0.80},
		{`\btraceroute\b`, NetworkScan, 0.85},
		{`\b(fping|masscan|zmap)\b`, NetworkScan, 0.95},
		// 服务探测
		{`\bnc\s+(-z|-v|-w)?\s*\d`, ServiceProbe, 0.90},
		{`\bncat\b`, ServiceProbe, 0.85},
		{`\btelnet\s+\d`, ServiceProbe, 0.85},
		// HTTP 探测
		{`\bcurl\s+https?://`, HTTPProbe, 0.90},
		{`\bwget\s+`, HTTPProbe, 0.85},
		{`\b(nikto|dirb|gobuster|ffuf)\b`, HTTPProbe, 0.95},
		// 数据库探测
		{`\bmysqldump\b`, DBProbe, 0.95},
		{`\bmysql\b`, DBProbe, 0.90},
		{`\bmysqladmin\b`, DBProbe, 0.85},
		{`\b(psql|pg_dump|mongo|redis-cli)\b`, DBProbe, 0.90},
		// 域探测
		{`\b(ldapsearch|ldapwhoami)\b`, DomainProbe, 0.90},
		{`\b(smbclient|rpcclient|enum4linux)\b`, DomainProbe, 0.90},
		{`\b(kinit|klist|getST|getTGT)\b`, DomainProbe, 0.90},
		{`\b(dig|nslookup)\s+.*(?:SRV|MX|ANY|AXFR)`, DomainProbe, 0.85},
		// 横向移动
		{`\bssh\s+\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}`, LateralMovement, 0.90},
		{`\bssh\s+\w+@\d`, LateralMovement, 0.85},
		{`\bscp\s+`, LateralMovement, 0.80},
		// 证据搜索 / 凭据窃取
		{`\bcat\s+.*\.env\b`, EvidenceSearch, 0.85},
		{`\bcat\s+.*shadow\b`, EvidenceSearch, 0.90},
		{`\bfind\s+.*(-name|(-perm\s+-))`, EvidenceSearch, 0.80},
		{`\bgrep\s+.*(password|secret|key|token)`, EvidenceSearch, 0.90},
		{`\bcat\s+.*\.git/config\b`, EvidenceSearch, 0.85},
		{`\bcat\s+.*\.kube/config\b`, EvidenceSearch, 0.85},
		// 权限提升
		{`\bsudo\s+`, PrivilegeEscalation, 0.85},
		{`\bsu\s+-?\s*\w`, PrivilegeEscalation, 0.80},
		{`\bchmod\s+\+s\b`, PrivilegeEscalation, 0.90},
		// 数据外传
		{`\b(base64|xxd|hexdump)\b`, DataExfiltration, 0.70},
		{`\btar\s+.*-[czx]`, DataExfiltration, 0.75},
		{`\bzip\b.*\b(rar|7z)\b`, DataExfiltration, 0.75},
		// 面包屑/攻击路径探测（从 HTTP 请求路径推断）
		{`/admin/`, HTTPProbe, 0.75},
		{`/wp-admin/`, HTTPProbe, 0.80},
		{`/actuator/`, HTTPProbe, 0.85},
		{`\/\.git/`, EvidenceSearch, 0.85},
		{`\/\.env\b`, EvidenceSearch, 0.90},
		{`\/etc/(passwd|shadow|hosts)`, EvidenceSearch, 0.95},
		{`\/backup/`, EvidenceSearch, 0.80},
		{`\/\.aws/`, EvidenceSearch, 0.90},
		{`\/\.kube/`, EvidenceSearch, 0.90},
		{`\/\.docker/`, EvidenceSearch, 0.85},
		{`\/shell\.jsp`, HTTPProbe, 0.95},
		{`\/cmd\.jsp`, HTTPProbe, 0.95},
		{`\/phpmyadmin/`, DBProbe, 0.85},
		{`\/swagger`, EvidenceSearch, 0.80},
		{`\/api-docs`, EvidenceSearch, 0.80},
	}

	for _, d := range defs {
		patterns = append(patterns, intentPattern{
			regex:      regexp.MustCompile(`(?i)` + d.regexStr),
			category:   d.category,
			confidence: d.confidence,
		})
	}
}

// Analyze 分析一条命令/请求的意图类别
// 返回匹配到的意图，未匹配时返回 ShellCommand/Unknown
func Analyze(input string) Intent {
	for _, p := range patterns {
		if p.regex.MatchString(input) {
			intent := Intent{
				Category:   p.category,
				Confidence: p.confidence,
				RawCommand: input,
			}
			if match := ipPattern.FindString(input); match != "" {
				intent.TargetIP = match
			}
			return intent
		}
	}
	// 未匹配任何已知模式，判断是否看起来像 shell 命令
	if looksLikeCommand(input) {
		return Intent{
			Category:   ShellCommand,
			Confidence: 0.50,
			RawCommand: input,
		}
	}
	return Intent{
		Category:   Unknown,
		Confidence: 0.30,
		RawCommand: input,
	}
}

// looksLikeCommand 启发式判断输入是否像命令（非纯文本路径）
func looksLikeCommand(input string) bool {
	if len(input) == 0 {
		return false
	}
	// 包含空格且首字符为 / 或字母 → 可能为命令
	if input[0] == '/' || (input[0] >= 'a' && input[0] <= 'z') || (input[0] >= 'A' && input[0] <= 'Z') {
		return true
	}
	return false
}

// TagName 返回意图类别的中文标签
func (c Category) TagName() string {
	switch c {
	case NetworkScan:
		return "网络扫描"
	case ServiceProbe:
		return "服务探测"
	case HTTPProbe:
		return "Web探测"
	case DBProbe:
		return "数据库探测"
	case EvidenceSearch:
		return "凭据窃取"
	case DomainProbe:
		return "域渗透"
	case LateralMovement:
		return "横向移动"
	case PrivilegeEscalation:
		return "提权"
	case DataExfiltration:
		return "数据外传"
	case ShellCommand:
		return "命令执行"
	case Unknown:
		return "未知"
	default:
		return string(c)
	}
}

// RiskLevel 返回意图对应的风险等级
func (c Category) RiskLevel() string {
	switch c {
	case LateralMovement, PrivilegeEscalation, DataExfiltration, DomainProbe:
		return "critical"
	case NetworkScan, EvidenceSearch, DBProbe:
		return "high"
	case HTTPProbe, ServiceProbe:
		return "medium"
	default:
		return "low"
	}
}
