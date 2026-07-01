// Package traps 陷阱模块注册中心 — 支持场景化陷阱选配
//
// 将蜜罐的9个协议服务 + 面包屑路径 + 反制载荷按场景分组，
// 用户可通过 config.yaml 中的 trap_scenario 字段选择部署场景，
// 仅启用对应的陷阱模块，未选配的陷阱不会产生无效资源占用。
package traps

import "slices"

// TrapScenario 陷阱部署场景
type TrapScenario string

const (
	ScenarioWeb            TrapScenario = "web"             // Web 业务场景：仅 HTTP 蜜罐 + 浏览器反制载荷
	ScenarioDatabase       TrapScenario = "database"        // 数据库场景：MySQL + Redis 蜜罐
	ScenarioRemoteAccess   TrapScenario = "remote_access"   // 主机远程访问场景：SSH + RDP + FTP 蜜罐
	ScenarioInfrastructure TrapScenario = "infrastructure"  // 基础设施场景：DNS + LDAP + SMB 蜜罐
	ScenarioFull           TrapScenario = "full"            // 全量启用（默认，向后兼容）
	ScenarioCustom         TrapScenario = "custom"          // 自定义选配
)

// AllScenarios 所有可用的预设场景列表
var AllScenarios = []TrapScenario{
	ScenarioWeb,
	ScenarioDatabase,
	ScenarioRemoteAccess,
	ScenarioInfrastructure,
	ScenarioFull,
	ScenarioCustom,
}

// AllServices 所有可选的协议蜜罐服务
var AllServices = []string{"http", "mysql", "redis", "ssh", "ftp", "ldap", "dns", "smb", "rdp"}

// scenarioServices 预设场景 → 启用的服务列表
var scenarioServices = map[TrapScenario][]string{
	ScenarioWeb:            {"http"},
	ScenarioDatabase:       {"mysql", "redis"},
	ScenarioRemoteAccess:   {"ssh", "rdp", "ftp"},
	ScenarioInfrastructure: {"dns", "ldap", "smb"},
	ScenarioFull:           {"http", "mysql", "redis", "ssh", "ftp", "ldap", "dns", "smb", "rdp"},
}

// scenarioDescriptions 场景中文描述
var scenarioDescriptions = map[TrapScenario]string{
	ScenarioWeb:            "Web 业务场景 — 启用 HTTP 蜜罐、浏览器指纹采集、Web 反制载荷",
	ScenarioDatabase:       "数据库场景 — 启用 MySQL、Redis 蜜罐，捕获数据库攻击行为",
	ScenarioRemoteAccess:   "主机远程访问场景 — 启用 SSH、RDP、FTP 蜜罐，捕获远程登录攻击",
	ScenarioInfrastructure: "基础设施场景 — 启用 DNS、LDAP、SMB 蜜罐，捕获基础设施扫描",
	ScenarioFull:           "全量启用 — 启用全部9种协议蜜罐（默认模式）",
	ScenarioCustom:         "自定义选配 — 手动选择需要启用的协议服务",
}

// ScenarioInfo 场景元信息（供前端展示）
type ScenarioInfo struct {
	Key         TrapScenario `json:"key"`
	Description string       `json:"description"`
	Services    []string     `json:"services"`
}

// Registry 陷阱模块注册中心
// 根据部署场景决定启用哪些协议蜜罐服务
type Registry struct {
	Scenario       TrapScenario `json:"scenario"`
	customServices []string     `json:"custom_services,omitempty"`
}

// New 创建陷阱注册中心
// scenario: 部署场景；custom: 自定义选配的服务列表（仅 scenario=custom 时生效）
func New(scenario TrapScenario, custom []string) *Registry {
	// 验证场景有效性
	if _, ok := scenarioServices[scenario]; !ok && scenario != ScenarioCustom {
		scenario = ScenarioFull // 无效场景回退到全量
	}
	// 过滤无效的自定义服务名
	filtered := make([]string, 0, len(custom))
	for _, s := range custom {
		if slices.Contains(AllServices, s) {
			filtered = append(filtered, s)
		}
	}
	return &Registry{
		Scenario:       scenario,
		customServices: filtered,
	}
}

// IsServiceEnabled 检查指定服务是否在当前场景下启用
func (r *Registry) IsServiceEnabled(name string) bool {
	for _, s := range r.EnabledServices() {
		if s == name {
			return true
		}
	}
	return false
}

// EnabledServices 返回当前场景下启用的服务列表
func (r *Registry) EnabledServices() []string {
	if r.Scenario == ScenarioCustom {
		return r.customServices
	}
	if svcs, ok := scenarioServices[r.Scenario]; ok {
		return svcs
	}
	return nil
}

// IsHTTPEnabled 便捷方法：HTTP 蜜罐是否启用（决定面包屑/反制载荷是否生效）
func (r *Registry) IsHTTPEnabled() bool {
	return r.IsServiceEnabled("http")
}

// GetScenarioInfo 获取所有预设场景的元信息（供前端渲染）
func GetScenarioInfo() []ScenarioInfo {
	infos := make([]ScenarioInfo, 0, len(AllScenarios))
	for _, s := range AllScenarios {
		desc := scenarioDescriptions[s]
		svcs := scenarioServices[s]
		if svcs == nil {
			svcs = []string{}
		}
		infos = append(infos, ScenarioInfo{
			Key:         s,
			Description: desc,
			Services:    svcs,
		})
	}
	return infos
}

// ParseScenario 将字符串转换为 TrapScenario，无效则返回 ScenarioFull
func ParseScenario(s string) TrapScenario {
	scenario := TrapScenario(s)
	if _, ok := scenarioServices[scenario]; ok || scenario == ScenarioCustom {
		return scenario
	}
	return ScenarioFull
}
