// Package asset 资产探测模块 — 端口扫描、服务识别、Banner 抓取
// 用于蜜罐运营者了解当前暴露的服务面，识别高危资产
package asset

import (
	"fmt"
	"net"
	"strings"
	"sync"
	"time"
)

// ScanTarget 扫描目标
type ScanTarget struct {
	Host string `json:"host"`
	Port int    `json:"port"`
}

// ServiceInfo 探测到的服务信息
type ServiceInfo struct {
	Host     string    `json:"host"`
	Port     int       `json:"port"`
	Open     bool      `json:"open"`
	Protocol string    `json:"protocol"`
	Service  string    `json:"service"`
	Banner   string    `json:"banner"`
	Scanned  time.Time `json:"scanned"`
}

// ScanResult 扫描结果汇总
type ScanResult struct {
	Total    int           `json:"total"`
	Open     int           `json:"open"`
	Services []ServiceInfo `json:"services"`
	Duration string        `json:"duration"`
}

// knownPorts 已知服务端口映射（用于服务识别）
var knownPorts = map[int]string{
	21:    "FTP",
	22:    "SSH",
	23:    "Telnet",
	25:    "SMTP",
	53:    "DNS",
	80:    "HTTP",
	110:   "POP3",
	143:   "IMAP",
	389:   "LDAP",
	443:   "HTTPS",
	445:   "SMB",
	1433:  "MSSQL",
	1521:  "Oracle",
	2375:  "Docker",
	2376:  "Docker-TLS",
	3000:  "Grafana/Web",
	3306:  "MySQL",
	3389:  "RDP",
	4444:  "C2/Metasploit",
	5000:  "Flask/Web",
	5432:  "PostgreSQL",
	5555:  "ADB",
	5601:  "Kibana",
	6379:  "Redis",
	6443:  "Kubernetes",
	7001:  "WebLogic",
	8000:  "Web",
	8009:  "AJP",
	8080:  "HTTP-Alt",
	8081:  "蜜罐-管理",
	8443:  "HTTPS-Alt",
	8888:  "Web",
	9000:  "Web",
	9090:  "Prometheus",
	9200:  "ElasticSearch",
	27017: "MongoDB",
}

// Scanner 资产扫描器
type Scanner struct {
	mu          sync.Mutex
	results     []ServiceInfo
	timeout     time.Duration
	hostTargets []string
}

// NewScanner 创建资产扫描器
// hostTargets: 待扫描的主机列表（默认扫描本机）
func NewScanner(hostTargets []string) *Scanner {
	if len(hostTargets) == 0 {
		hostTargets = []string{"127.0.0.1"}
	}
	return &Scanner{
		timeout:     3 * time.Second,
		hostTargets: hostTargets,
	}
}

// Scan 执行 TCP 端口扫描并抓取 Banner
// targets: 端口列表（如 nil 则扫描常见端口）
func (s *Scanner) Scan(targets []ScanTarget) *ScanResult {
	if len(targets) == 0 {
		// 未指定端口时扫描所有已知端口
		for port := range knownPorts {
			for _, host := range s.hostTargets {
				targets = append(targets, ScanTarget{Host: host, Port: port})
			}
		}
	}

	start := time.Now()
	s.results = make([]ServiceInfo, 0, len(targets))

	var wg sync.WaitGroup
	sem := make(chan struct{}, 20) // 并发限制 20

	for _, t := range targets {
		wg.Add(1)
		go func(target ScanTarget) {
			defer wg.Done()
			sem <- struct{}{}
			defer func() { <-sem }()

			info := s.scanPort(target)
			s.mu.Lock()
			s.results = append(s.results, info)
			s.mu.Unlock()
		}(t)
	}

	wg.Wait()

	open := 0
	for _, svc := range s.results {
		if svc.Open {
			open++
		}
	}

	return &ScanResult{
		Total:    len(s.results),
		Open:     open,
		Services: s.results,
		Duration: time.Since(start).String(),
	}
}

// scanPort 扫描单个端口并尝试识别服务
func (s *Scanner) scanPort(target ScanTarget) ServiceInfo {
	info := ServiceInfo{
		Host:    target.Host,
		Port:    target.Port,
		Scanned: time.Now(),
	}

	addr := net.JoinHostPort(target.Host, fmt.Sprintf("%d", target.Port))
	conn, err := net.DialTimeout("tcp", addr, s.timeout)
	if err != nil {
		return info
	}
	defer conn.Close()

	info.Open = true
	info.Protocol = "TCP"

	// 识别已知服务
	if svc, ok := knownPorts[target.Port]; ok {
		info.Service = svc
	}

	// Banner 抓取：发送探测包并读取响应
	info.Banner = s.grabBanner(conn, target.Port)

	return info
}

// grabBanner 尝试抓取服务 Banner
func (s *Scanner) grabBanner(conn net.Conn, port int) string {
	// 设置读写超时
	conn.SetDeadline(time.Now().Add(s.timeout))

	// 根据端口发送不同的探测请求
	switch port {
	case 80, 8080, 8000, 8081, 8888, 3000, 5000, 9000:
		// HTTP 请求
		fmt.Fprintf(conn, "HEAD / HTTP/1.0\r\nHost: %s\r\n\r\n", conn.RemoteAddr().String())
	case 443, 8443:
		// HTTPS — 仅检查连接，不进行 TLS 握手
		return "TLS/SSL"
	case 3306:
		// MySQL — 读取握手包
		// MySQL 服务端握手包前 5 字节为协议版本
	case 6379:
		// Redis — PING
		fmt.Fprintf(conn, "PING\r\n")
	case 22:
		// SSH — 读取 Banner
		// SSH 服务端会在连接后主动发送 Banner
	case 27017:
		// MongoDB
		fmt.Fprintf(conn, "buildinfo\r\n")
	}

	// 读取响应（最多 256 字节）
	buf := make([]byte, 256)
	n, err := conn.Read(buf)
	if err != nil || n == 0 {
		return ""
	}

	// 清洗不可打印字符
	banner := strings.TrimSpace(string(buf[:n]))
	banner = strings.ReplaceAll(banner, "\r\n", " ")
	banner = strings.ReplaceAll(banner, "\n", " ")
	if len(banner) > 128 {
		banner = banner[:128] + "..."
	}

	// 从 Banner 中提取版本信息
	banner = extractVersion(banner)

	return banner
}

// extractVersion 从 Banner 中提取服务版本信息
func extractVersion(banner string) string {
	// SSH: "SSH-2.0-OpenSSH_8.9p1 Ubuntu-3ubuntu0.1"
	if strings.HasPrefix(banner, "SSH-") {
		return banner
	}

	// HTTP: "HTTP/1.1 200 OK\r\nServer: nginx/1.18.0"
	for _, line := range strings.Split(banner, " ") {
		if strings.Contains(strings.ToLower(line), "server") ||
			strings.Contains(strings.ToLower(line), "x-powered") {
			return line
		}
	}

	// Redis: "+PONG"
	if strings.Contains(banner, "PONG") {
		return "Redis (PONG response)"
	}

	// MySQL handshake
	if len(banner) > 4 && banner[4] == 0x0a {
		return "MySQL (handshake received)"
	}

	return banner
}

// GetKnownPorts 返回已知端口映射（供前端使用）
func GetKnownPorts() map[int]string {
	return knownPorts
}
