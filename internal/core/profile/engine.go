// Package profile 攻击者画像引擎 — 多维度分析、威胁标签匹配、技术评分
package profile

import (
	"strconv"
	"strings"
	"time"
)

// ---------- 画像数据结构 ----------

// AttackerProfile 攻击者完整画像
type AttackerProfile struct {
	IP                   string                  `json:"ip"`
	FirstSeen            time.Time               `json:"first_seen"`
	LastSeen             time.Time               `json:"last_seen"`
	TotalConnections     int                     `json:"total_connections"`
	TotalAttacks         int                     `json:"total_attacks"`
	TotalBreadcrumbs     int                     `json:"total_breadcrumbs"`
	TotalFingerprints    int                     `json:"total_fingerprints"`
	TotalCountermeasures int                     `json:"total_countermeasures"`
	Countermeasures      []CountermeasureSummary `json:"countermeasures,omitempty"`
	TotalPostBodies      int                     `json:"total_post_bodies"`
	UniqueServices       []string                `json:"unique_services"`
	UniquePaths          []string                `json:"unique_paths"`
	PortScanCount        int                     `json:"port_scan_count"`
	AvgReqPerMinute      float64                 `json:"avg_req_per_minute"`
	PeakHour             int                     `json:"peak_hour"`
	ActiveDays           int                     `json:"active_days"`
	InteractionDepth     int                     `json:"interaction_depth"` // 面包屑触发数占访问数比例(bp)
	ToolSignatures       []string                `json:"tool_signatures"`
	TTPSignatures        []TTPSignature          `json:"ttp_signatures"`
	GEO                  *GEOInfo                `json:"geo,omitempty"`
	FingerprintSummary   *FingerprintSummary     `json:"fingerprint_summary,omitempty"`
	Tags                 []ProfileTag            `json:"tags"`
	SkillScore           int                     `json:"skill_score"`  // 0-100
	RiskScore            int                     `json:"risk_score"`   // 0-100
	ThreatLevel          string                  `json:"threat_level"` // low/medium/high/critical
}

// TTPSignature ATT&CK 技术签名
type TTPSignature struct {
	Tactic      string `json:"tactic"`
	TacticCN    string `json:"tactic_cn"`
	TechniqueID string `json:"technique_id"`
	Count       int    `json:"count"`
}

// GEOInfo 地理信息
type GEOInfo struct {
	Country string `json:"country"`
	City    string `json:"city"`
	Org     string `json:"org"`
}

// FingerprintSummary 指纹摘要
type FingerprintSummary struct {
	Browser      string `json:"browser,omitempty"`
	OS           string `json:"os,omitempty"`
	GPU          string `json:"gpu,omitempty"`
	Screen       string `json:"screen,omitempty"`
	Timezone     string `json:"timezone,omitempty"`
	InnerIP      string `json:"inner_ip,omitempty"`
	HardwareCPUs int    `json:"hardware_cpus,omitempty"`
	DeviceMemory int    `json:"device_memory,omitempty"`
}

// ProfileTag 画像标签
type ProfileTag struct {
	Category   string `json:"category"`   // skill/behavior/motive/tool
	Name       string `json:"name"`       // 标签名称
	NameCN     string `json:"name_cn"`    // 中文名
	Confidence int    `json:"confidence"` // 置信度 0-100
	Source     string `json:"source"`     // rule/ml/manual
	Detail     string `json:"detail,omitempty"`
}

// TagCategory 标签分类定义
type TagCategory struct {
	Key  string `json:"key"`
	Name string `json:"name"`
}

var TagCategories = []TagCategory{
	{Key: "skill", Name: "技术水平"},
	{Key: "behavior", Name: "行为特征"},
	{Key: "motive", Name: "攻击目的"},
	{Key: "tool", Name: "工具偏好"},
}

// ---------- 标签匹配引擎 ----------

// Engine 画像分析引擎
type Engine struct {
	tags map[string][]ProfileTag // IP -> tags
}

// NewEngine 创建画像引擎
func NewEngine() *Engine {
	return &Engine{
		tags: make(map[string][]ProfileTag),
	}
}

// ProfileData 画像原始数据（从 store 聚合）
type ProfileData struct {
	IP                   string
	FirstSeen            time.Time
	LastSeen             time.Time
	TotalConnections     int
	TotalAttacks         int
	TotalBreadcrumbs     int
	TotalFingerprints    int
	TotalCountermeasures int
	TotalPostBodies      int
	UniqueServices       []string
	UniquePaths          []string
	PortScanCount        int
	AvgReqPerMinute      float64 // 由 Analyze 计算并回填
	ActiveDays           int     // 由 Analyze 计算并回填
	PeakHour             int     // 由 Analyze 计算并回填
	ServiceCounts        map[string]int
	PathCounts           map[string]int
	HourDistribution     map[int]int // hour -> count
	UAs                  []string
	TTPSignatures        []TTPSignature
	HasFingerprint       bool
	FPBrowser            string
	FPOS                 string
	FPGPU                string
	FPScreen             string
	FPTimezone           string
	FPInnerIP            string
	FPHardwareCPUs       int
	FPDeviceMemory       int
}

// Analyze 执行多维度画像分析
func (e *Engine) Analyze(data *ProfileData) *AttackerProfile {
	profile := &AttackerProfile{
		IP:                   data.IP,
		FirstSeen:            data.FirstSeen,
		LastSeen:             data.LastSeen,
		TotalConnections:     data.TotalConnections,
		TotalAttacks:         data.TotalAttacks,
		TotalBreadcrumbs:     data.TotalBreadcrumbs,
		TotalFingerprints:    data.TotalFingerprints,
		TotalCountermeasures: data.TotalCountermeasures,
		TotalPostBodies:      data.TotalPostBodies,
		UniqueServices:       data.UniqueServices,
		UniquePaths:          data.UniquePaths,
		PortScanCount:        data.PortScanCount,
		TTPSignatures:        data.TTPSignatures,
		Tags:                 make([]ProfileTag, 0),
	}

	// 活动指标 — 回填至 data 供子函数使用
	duration := data.LastSeen.Sub(data.FirstSeen)
	if data.TotalConnections > 0 && duration.Seconds() > 0 {
		data.AvgReqPerMinute = float64(data.TotalConnections) / duration.Minutes()
	}
	data.ActiveDays = max(1, int(duration.Hours()/24)+1)
	peakHour, _ := findPeakHour(data.HourDistribution)
	data.PeakHour = peakHour

	// 回填至 profile
	profile.AvgReqPerMinute = data.AvgReqPerMinute
	profile.ActiveDays = data.ActiveDays
	profile.PeakHour = data.PeakHour
	if data.TotalConnections > 0 {
		profile.InteractionDepth = (data.TotalBreadcrumbs * 100) / data.TotalConnections
	}

	// 指纹
	if data.HasFingerprint {
		profile.FingerprintSummary = &FingerprintSummary{
			Browser:      data.FPBrowser,
			OS:           data.FPOS,
			GPU:          data.FPGPU,
			Screen:       data.FPScreen,
			Timezone:     data.FPTimezone,
			InnerIP:      data.FPInnerIP,
			HardwareCPUs: data.FPHardwareCPUs,
			DeviceMemory: data.FPDeviceMemory,
		}
	}

	// 工具检测
	profile.ToolSignatures = detectTools(data)

	// ---- 标签匹配 ----

	// 1. 技术水平标签
	profile.SkillScore = calcSkillScore(data)
	applySkillTags(profile)

	// 2. 行为特征标签
	applyBehaviorTags(profile, data)

	// 3. 攻击目的标签
	applyMotiveTags(profile, data)

	// 4. 工具偏好标签
	applyToolTags(profile, data)

	// 风险评分
	profile.RiskScore = calcRiskScore(profile)
	switch {
	case profile.RiskScore >= 80:
		profile.ThreatLevel = "critical"
	case profile.RiskScore >= 60:
		profile.ThreatLevel = "high"
	case profile.RiskScore >= 30:
		profile.ThreatLevel = "medium"
	default:
		profile.ThreatLevel = "low"
	}

	return profile
}

// ---------- 技能评分 ----------

func calcSkillScore(data *ProfileData) int {
	score := 0

	// 多服务扫描 (+15)
	if len(data.UniqueServices) >= 5 {
		score += 15
	} else if len(data.UniqueServices) >= 3 {
		score += 8
	} else if len(data.UniqueServices) >= 2 {
		score += 3
	}

	// 端口扫描 (+10)
	if data.PortScanCount > 0 {
		score += 10
	}

	// 多路径探测 (+15)
	if len(data.UniquePaths) >= 10 {
		score += 15
	} else if len(data.UniquePaths) >= 5 {
		score += 8
	} else if len(data.UniquePaths) >= 2 {
		score += 3
	}

	// 连续活动天数长 (+10)
	if data.ActiveDays >= 7 {
		score += 10
	} else if data.ActiveDays >= 3 {
		score += 5
	}

	// 高频攻击 (+15)
	if data.AvgReqPerMinute >= 10 {
		score += 15
	} else if data.AvgReqPerMinute >= 2 {
		score += 8
	}

	// 面包屑触发率高表示深度交互 (+15)
	interactionRate := 0
	if data.TotalConnections > 0 {
		interactionRate = (data.TotalBreadcrumbs * 100) / data.TotalConnections
	}
	if interactionRate >= 20 {
		score += 15
	} else if interactionRate >= 5 {
		score += 8
	}

	// 使用多种工具 (+10)
	tools := detectTools(data)
	if len(tools) >= 3 {
		score += 10
	} else if len(tools) >= 1 {
		score += 5
	}

	// TTP 覆盖广度 (+10)
	if len(data.TTPSignatures) >= 5 {
		score += 10
	} else if len(data.TTPSignatures) >= 2 {
		score += 5
	}

	return min(score, 100)
}

func applySkillTags(profile *AttackerProfile) {
	switch {
	case profile.SkillScore >= 75:
		addTag(profile, "skill", "advanced_actor", "高级威胁行为者", 90, "rule",
			"综合评分"+itoa(profile.SkillScore)+"/100")
	case profile.SkillScore >= 50:
		addTag(profile, "skill", "intermediate", "进阶攻击者", 70, "rule",
			"综合评分"+itoa(profile.SkillScore)+"/100")
	case profile.SkillScore >= 25:
		addTag(profile, "skill", "script_kiddie", "脚本小子/入门级", 65, "rule",
			"综合评分"+itoa(profile.SkillScore)+"/100")
	default:
		addTag(profile, "skill", "novice", "新手/自动扫描", 60, "rule",
			"综合评分"+itoa(profile.SkillScore)+"/100")
	}
}

// ---------- 行为特征标签 ----------

func applyBehaviorTags(profile *AttackerProfile, data *ProfileData) {
	// 谨慎 vs 激进
	interactionRate := 0
	if data.TotalConnections > 0 {
		interactionRate = (data.TotalBreadcrumbs * 100) / data.TotalConnections
	}

	cautiousScore := 0
	aggressiveScore := 0

	// 谨慎特征
	if data.PortScanCount > 0 && data.TotalConnections > 50 {
		cautiousScore += 20 // 先扫描后攻击
	}
	if data.TotalConnections > 0 && data.TotalBreadcrumbs == 0 {
		cautiousScore += 15 // 避免触发蜜罐陷阱
	}
	if len(data.UniqueServices) <= 2 && data.TotalConnections > 20 {
		cautiousScore += 15 // 聚焦少数目标
	}
	if data.AvgReqPerMinute < 1 {
		cautiousScore += 10 // 慢速探测
	}
	if data.PeakHour >= 0 && data.PeakHour < 6 {
		cautiousScore += 10 // 凌晨活动
	}

	// 激进特征
	if interactionRate >= 10 {
		aggressiveScore += 20 // 大量触发蜜罐
	}
	if data.AvgReqPerMinute >= 10 {
		aggressiveScore += 20 // 高频攻击
	}
	if len(data.UniqueServices) >= 5 {
		aggressiveScore += 15 // 广泛扫描
	}
	if data.TotalConnections >= 100 {
		aggressiveScore += 15 // 大量连接
	}

	if cautiousScore >= aggressiveScore+10 {
		addTag(profile, "behavior", "cautious", "性格谨慎", 70, "rule",
			"谨慎度"+itoa(cautiousScore)+"/激进度"+itoa(aggressiveScore))
	} else if aggressiveScore >= cautiousScore+10 {
		addTag(profile, "behavior", "aggressive", "性格激进", 70, "rule",
			"激进度"+itoa(aggressiveScore)+"/谨慎度"+itoa(cautiousScore))
	} else {
		addTag(profile, "behavior", "moderate", "行为中性", 50, "rule", "")
	}

	// 有组织 vs 随机
	if data.TotalConnections >= 20 && len(data.UniqueServices) >= 3 && data.ActiveDays >= 2 {
		addTag(profile, "behavior", "organized", "有组织攻击", 65, "rule", "")
	} else {
		addTag(profile, "behavior", "random", "随机扫描", 60, "rule", "")
	}

	// 单一目标 vs 广撒网
	if len(data.UniqueServices) <= 1 && data.TotalConnections >= 10 {
		addTag(profile, "behavior", "targeted", "单一目标", 60, "rule", "")
	} else if len(data.UniqueServices) >= 5 {
		addTag(profile, "behavior", "scattershot", "广撒网扫描", 65, "rule", "")
	}
}

// ---------- 攻击目的标签 ----------

func applyMotiveTags(profile *AttackerProfile, data *ProfileData) {
	// 根据访问路径判断动机
	hasConfigPath := false
	hasDBPath := false
	hasAdminPath := false
	hasAPIPath := false
	hasSwaggerPath := false
	hasSourceCodePath := false
	hasJMSPath := false

	for _, p := range data.UniquePaths {
		pl := strings.ToLower(p)
		if strings.Contains(pl, "admin") || strings.Contains(pl, "login") || strings.Contains(pl, "manage") {
			hasAdminPath = true
		}
		if strings.Contains(pl, "config") || strings.Contains(pl, ".env") || strings.Contains(pl, "application.yml") {
			hasConfigPath = true
		}
		if strings.Contains(pl, "database") || strings.Contains(pl, ".sql") || strings.Contains(pl, "backup") {
			hasDBPath = true
		}
		if strings.Contains(pl, "api") || strings.Contains(pl, "swagger") {
			hasAPIPath = true
		}
		if strings.Contains(pl, "swagger") || strings.Contains(pl, "api-docs") {
			hasSwaggerPath = true
		}
		if strings.Contains(pl, ".git") || strings.Contains(pl, "backup") || strings.Contains(pl, "source") {
			hasSourceCodePath = true
		}
		if strings.Contains(pl, ".jsp") || strings.Contains(pl, "shell") || strings.Contains(pl, "cmd") {
			hasJMSPath = true
		}
	}

	if hasConfigPath || hasDBPath || hasSourceCodePath {
		addTag(profile, "motive", "data_theft", "数据窃取", 60, "rule", "")
	}
	if hasAdminPath {
		addTag(profile, "motive", "privilege_escalation", "权限提升/横向移动", 55, "rule", "")
	}
	if hasSwaggerPath || hasAPIPath {
		addTag(profile, "motive", "api_recon", "API探测", 60, "rule", "")
	}
	if hasJMSPath {
		addTag(profile, "motive", "webshell", "WebShell植入", 65, "rule", "")
	}
	if data.TotalPostBodies > 0 {
		addTag(profile, "motive", "credential_test", "凭据测试/爆破", 55, "rule", "")
	}

	// 如果扫描了多个服务但没有深入，可能是网络滋事
	if len(data.UniqueServices) >= 4 && data.TotalBreadcrumbs == 0 {
		addTag(profile, "motive", "recon_only", "纯侦查/网络滋事", 50, "rule", "")
	}
}

// ---------- 工具偏好标签 ----------

func applyToolTags(profile *AttackerProfile, data *ProfileData) {
	tools := detectTools(data)
	for _, tool := range tools {
		switch {
		case strings.Contains(strings.ToLower(tool), "nuclei"):
			addTag(profile, "tool", "nuclei_user", "Nuclei 用户", 80, "rule", tool)
		case strings.Contains(strings.ToLower(tool), "sqlmap"):
			addTag(profile, "tool", "sqlmap_user", "SQLMap 用户", 80, "rule", tool)
		case strings.Contains(strings.ToLower(tool), "burp"):
			addTag(profile, "tool", "burp_user", "Burp Suite 用户", 80, "rule", tool)
		case strings.Contains(strings.ToLower(tool), "chrome"):
			addTag(profile, "tool", "browser_user", "浏览器访问者", 70, "rule", tool)
		case strings.Contains(strings.ToLower(tool), "curl") || strings.Contains(strings.ToLower(tool), "python"):
			addTag(profile, "tool", "script_user", "脚本/自动化工具", 70, "rule", tool)
		}
	}
}

// ---------- 风险评分 ----------

func calcRiskScore(profile *AttackerProfile) int {
	score := 0

	// 技能高分 => 高风险
	score += profile.SkillScore / 3

	// 面包屑触发多 => 高风险
	if profile.TotalBreadcrumbs >= 10 {
		score += 20
	} else if profile.TotalBreadcrumbs >= 5 {
		score += 10
	}

	// 端口扫描 => 高风险
	if profile.PortScanCount > 0 {
		score += 10
	}

	// TTP 覆盖广 => 高风险
	if len(profile.TTPSignatures) >= 5 {
		score += 15
	} else if len(profile.TTPSignatures) >= 2 {
		score += 8
	}

	// 反制事件触发 => 极高风险
	if profile.TotalCountermeasures > 0 {
		score += 15
	}

	return min(score, 100)
}

// ---------- 工具函数 ----------

func detectTools(data *ProfileData) []string {
	seen := make(map[string]bool)
	var tools []string
	for _, ua := range data.UAs {
		l := strings.ToLower(ua)
		if strings.Contains(l, "nuclei") && !seen["Nuclei"] {
			seen["Nuclei"] = true
			tools = append(tools, "Nuclei")
		}
		if strings.Contains(l, "sqlmap") && !seen["SQLMap"] {
			seen["SQLMap"] = true
			tools = append(tools, "SQLMap")
		}
		if strings.Contains(l, "burp") && !seen["Burp Suite"] {
			seen["Burp Suite"] = true
			tools = append(tools, "Burp Suite")
		}
		if strings.Contains(l, "chrome") && !strings.Contains(l, "headless") && !seen["Chrome"] {
			seen["Chrome"] = true
			tools = append(tools, "Chrome")
		}
		if strings.Contains(l, "firefox") && !seen["Firefox"] {
			seen["Firefox"] = true
			tools = append(tools, "Firefox")
		}
		if (strings.Contains(l, "curl") || strings.Contains(l, "python") || strings.Contains(l, "wget")) && !seen["Script/Automation"] {
			seen["Script/Automation"] = true
			tools = append(tools, "脚本/自动化")
		}
	}
	return tools
}

func findPeakHour(dist map[int]int) (int, int) {
	maxHour, maxCount := -1, 0
	for h, c := range dist {
		if c > maxCount {
			maxHour, maxCount = h, c
		}
	}
	return maxHour, maxCount
}

func addTag(profile *AttackerProfile, category, name, nameCN string, confidence int, source, detail string) {
	profile.Tags = append(profile.Tags, ProfileTag{
		Category:   category,
		Name:       name,
		NameCN:     nameCN,
		Confidence: confidence,
		Source:     source,
		Detail:     detail,
	})
}

func min(a, b int) int {
	if a < b {
		return a
	}
	return b
}

func max(a, b int) int {
	if a > b {
		return a
	}
	return b
}

func itoa(n int) string {
	return strconv.Itoa(n)
}
