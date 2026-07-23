// Package domain 虚拟拓扑领域模型 (v0.21)
//
// 定义蜜罐虚拟网络拓扑的核心数据结构，支持 YAML 配置驱动的拓扑定义、
// per-session 拓扑过滤（基于证据令牌）、影子主机动态扩展。
//
// 设计参考: AlterHive topology system (Fausto-404/AlterHive)
package domain

import (
	"net"
	"sync"
)

// VirtualHost 虚拟主机（蜜罐网络中的一个虚假节点）
type VirtualHost struct {
	IP           string           `yaml:"ip" json:"ip"`
	Hostname     string           `yaml:"hostname" json:"hostname"`
	Role         string           `yaml:"role" json:"role"`               // web | db | dc | k8s | gitlab | jenkins | shadow
	OS           string           `yaml:"os" json:"os"`                   // 操作系统描述
	Services     []VirtualService  `yaml:"services" json:"services"`       // 运行的服务
	SubnetID     string           `yaml:"subnet_id" json:"subnet_id"`     // 所属网段
	VisibleAfter []string         `yaml:"visible_after,omitempty" json:"visible_after,omitempty"` // 需要的证据令牌
	CanaryID     string           `yaml:"-" json:"canary_id,omitempty"`   // 蜜标ID（用于追踪）
	IsShadow     bool             `yaml:"-" json:"is_shadow,omitempty"`   // 是否为动态添加的影子主机
}

// VirtualService 虚拟服务
type VirtualService struct {
	Port        int    `yaml:"port" json:"port"`
	Protocol    string `yaml:"protocol" json:"protocol"`       // ssh | http | https | mysql | redis | ldap | smb | dns | kerberos | etcd
	ProcessName string `yaml:"process_name,omitempty" json:"process_name,omitempty"` // 模拟的进程名
	FailureMode string `yaml:"failure_mode,omitempty" json:"failure_mode,omitempty"` // auth_denied | refused | redirect_login | timeout | stronger_auth_required | access_denied
	Banner      string `yaml:"banner,omitempty" json:"banner,omitempty"`             // 服务 banner
	BindAddr    string `yaml:"bind_addr,omitempty" json:"bind_addr,omitempty"`       // 监听地址 (0.0.0.0 | 127.0.0.1)
}

// Segment 网段（一组虚拟主机）
type Segment struct {
	ID      string   `yaml:"id" json:"id"`
	CIDR    string   `yaml:"cidr" json:"cidr"`
	Gateway string   `yaml:"gateway" json:"gateway"`
	Desc    string   `yaml:"desc" json:"desc"`
	ipNet   *net.IPNet `yaml:"-" json:"-"`
}

// Edge 表示两个主机之间的网络连通关系
type Edge struct {
	From string `yaml:"from" json:"from"` // 主机 IP 或 "*" (所有)
	To   string `yaml:"to" json:"to"`     // 主机 IP
	Via  string `yaml:"via,omitempty" json:"via,omitempty"` // 经由的路径 (ssh/http/mysql/...)
}

// TopologyConfig 拓扑 YAML 配置结构
type TopologyConfig struct {
	Segments []Segment      `yaml:"segments" json:"segments"`
	Hosts    []VirtualHost  `yaml:"hosts" json:"hosts"`
	Edges    []Edge         `yaml:"edges" json:"edges"`
}

// VirtualTopology 虚拟拓扑运行时
type VirtualTopology struct {
	mu       sync.RWMutex
	config   TopologyConfig
	segments map[string]*Segment
	hosts    map[string]*VirtualHost // IP -> host
	subnets  map[string][]*VirtualHost // subnet_id -> hosts
}

// NewTopology 从配置创建拓扑
func NewTopology(config TopologyConfig) *VirtualTopology {
	t := &VirtualTopology{
		config:   config,
		segments: make(map[string]*Segment),
		hosts:    make(map[string]*VirtualHost),
		subnets:  make(map[string][]*VirtualHost),
	}
	// 索引 segments
	for i := range config.Segments {
		seg := &config.Segments[i]
		if _, ipNet, err := net.ParseCIDR(seg.CIDR); err == nil {
			seg.ipNet = ipNet
		}
		t.segments[seg.ID] = seg
	}
	// 索引 hosts
	for i := range config.Hosts {
		host := &config.Hosts[i]
		t.hosts[host.IP] = host
		t.subnets[host.SubnetID] = append(t.subnets[host.SubnetID], host)
	}
	return t
}

// GetHost 根据 IP 查找主机
func (t *VirtualTopology) GetHost(ip string) *VirtualHost {
	t.mu.RLock()
	defer t.mu.RUnlock()
	return t.hosts[ip]
}

// GetHostsForSession 根据会话已收集的证据令牌过滤可见主机
func (t *VirtualTopology) GetHostsForSession(session *SessionContext) []VirtualHost {
	t.mu.RLock()
	defer t.mu.RUnlock()

	var visible []VirtualHost
	for ip, host := range t.hosts {
		// 影子主机总是可见（已通过动态扩展流程添加）
		if host.IsShadow {
			visible = append(visible, *host)
			continue
		}
		// 检查证据门控
		if t.isHostVisible(host, session) {
			visible = append(visible, *host)
			_ = ip
		}
	}
	return visible
}

// isHostVisible 检查主机对当前会话是否可见
func (t *VirtualTopology) isHostVisible(host *VirtualHost, session *SessionContext) bool {
	if len(host.VisibleAfter) == 0 {
		return true // 无门控条件 = 默认可见
	}
	if session == nil || session.Evidence == nil {
		return false
	}
	for _, token := range host.VisibleAfter {
		if session.Evidence.Has(token) {
			return true
		}
	}
	return false
}

// GetHostsInSubnet 获取指定网段中的所有主机
func (t *VirtualTopology) GetHostsInSubnet(subnetID string) []*VirtualHost {
	t.mu.RLock()
	defer t.mu.RUnlock()
	return t.subnets[subnetID]
}

// GetSubnet 获取网段信息
func (t *VirtualTopology) GetSubnet(id string) *Segment {
	t.mu.RLock()
	defer t.mu.RUnlock()
	return t.segments[id]
}

// GetAllSegments 返回所有网段信息
func (t *VirtualTopology) GetAllSegments() []Segment {
	t.mu.RLock()
	defer t.mu.RUnlock()
	result := make([]Segment, 0, len(t.segments))
	for _, seg := range t.segments {
		result = append(result, *seg)
	}
	return result
}

// GetEdges 返回所有连通边
func (t *VirtualTopology) GetEdges() []Edge {
	t.mu.RLock()
	defer t.mu.RUnlock()
	return t.config.Edges
}

// IsVirtualIP 检查 IP 是否在虚拟拓扑的子网范围内
func (t *VirtualTopology) IsVirtualIP(ip string) bool {
	parsed := net.ParseIP(ip)
	if parsed == nil {
		return false
	}
	t.mu.RLock()
	defer t.mu.RUnlock()
	for _, seg := range t.segments {
		if seg.ipNet != nil && seg.ipNet.Contains(parsed) {
			return true
		}
	}
	// 也检查主机直接 IP
	if _, exists := t.hosts[ip]; exists {
		return true
	}
	return false
}

// AppendShadowHost 动态添加影子主机
func (t *VirtualTopology) AppendShadowHost(host VirtualHost) {
	host.IsShadow = true
	t.mu.Lock()
	defer t.mu.Unlock()
	t.hosts[host.IP] = &host
	t.subnets[host.SubnetID] = append(t.subnets[host.SubnetID], &host)
}

// HostCount 返回总主机数
func (t *VirtualTopology) HostCount() int {
	t.mu.RLock()
	defer t.mu.RUnlock()
	return len(t.hosts)
}

// AllHosts 返回所有主机
func (t *VirtualTopology) AllHosts() []VirtualHost {
	t.mu.RLock()
	defer t.mu.RUnlock()
	result := make([]VirtualHost, 0, len(t.hosts))
	for _, h := range t.hosts {
		result = append(result, *h)
	}
	return result
}

// SessionContext 会话上下文（per-attacker 会话状态）
type SessionContext struct {
	SessionID     string          `json:"session_id"`
	RemoteIP      string          `json:"remote_ip"`
	Username      string          `json:"username"`
	SubnetLocalIP string          `json:"subnet_local_ip"`  // 攻击者所处的虚拟IP
	Evidence      *EvidenceSet    `json:"evidence,omitempty"` // 已收集的证据令牌
	ShadowHosts   []ShadowEntry   `json:"shadow_hosts,omitempty"`
	ConnectedAt   int64           `json:"connected_at"`
	LastActive    int64           `json:"last_active"`
}

// ShadowEntry 影子主机记录
type ShadowEntry struct {
	IP       string `json:"ip"`
	Hostname string `json:"hostname"`
	Role     string `json:"role"`
	Status   string `json:"status"` // active | pending
}

// EvidenceSet per-session 证据令牌集合
type EvidenceSet struct {
	mu     sync.RWMutex
	tokens map[string]bool
}

// NewEvidenceSet 创建证据集合
func NewEvidenceSet() *EvidenceSet {
	return &EvidenceSet{tokens: make(map[string]bool)}
}

// Has 检查是否持有指定令牌
func (e *EvidenceSet) Has(token string) bool {
	if e == nil {
		return false
	}
	e.mu.RLock()
	defer e.mu.RUnlock()
	return e.tokens[token]
}

// Add 添加证据令牌
func (e *EvidenceSet) Add(token string) {
	if e == nil {
		return
	}
	e.mu.Lock()
	defer e.mu.Unlock()
	e.tokens[token] = true
}

// Count 返回令牌数量
func (e *EvidenceSet) Count() int {
	if e == nil {
		return 0
	}
	e.mu.RLock()
	defer e.mu.RUnlock()
	return len(e.tokens)
}

// HitCount 兼容别名
func (e *EvidenceSet) HitCount() int {
	return e.Count()
}

// AllTokens 返回所有令牌
func (e *EvidenceSet) AllTokens() []string {
	if e == nil {
		return nil
	}
	e.mu.RLock()
	defer e.mu.RUnlock()
	tokens := make([]string, 0, len(e.tokens))
	for t := range e.tokens {
		tokens = append(tokens, t)
	}
	return tokens
}
