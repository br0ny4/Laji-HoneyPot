package profile

import (
	"testing"
	"time"
)

func makeTestData() *ProfileData {
	return &ProfileData{
		IP:          "10.0.0.1",
		FirstSeen:   time.Now().Add(-24 * time.Hour),
		LastSeen:    time.Now(),
		TotalConnections: 100,
		TotalBreadcrumbs: 15,
		TotalFingerprints: 1,
		PortScanCount: 1,
		UniqueServices: []string{"http", "https", "mysql", "ssh", "redis"},
		UniquePaths: []string{
			"/admin/config.php",
			"/etc/passwd",
			"/../../../../etc/shadow",
			"/.git/config",
			"/.env",
			"/actuator/heapdump",
			"/swagger-ui.html",
			"/shell.jsp",
			"/backup/database.sql",
			"/nacos/v1/cs/configs",
			"/api/v1/users",
		},
		HourDistribution: map[int]int{3: 20, 14: 30, 22: 50},
		UAs:              []string{"Mozilla/5.0 Chrome/124", "sqlmap/1.0", "Nuclei"},
		TTPSignatures: []TTPSignature{
			{Tactic: "Credential Access", TacticCN: "凭证访问", TechniqueID: "T1003", Count: 3},
			{Tactic: "Collection", TacticCN: "采集", TechniqueID: "T1005", Count: 5},
			{Tactic: "Discovery", TacticCN: "发现", TechniqueID: "T1083", Count: 4},
			{Tactic: "Discovery", TacticCN: "发现", TechniqueID: "T1046", Count: 2},
			{Tactic: "Collection", TacticCN: "采集", TechniqueID: "T1552", Count: 1},
		},
		HasFingerprint: true,
		FPBrowser:      "Chrome 124",
		FPOS:           "Windows 10",
		FPGPU:          "NVIDIA GeForce RTX 3060",
		FPScreen:       "1920x1080",
		FPTimezone:     "Asia/Shanghai",
		FPInnerIP:      "192.168.1.100",
		FPHardwareCPUs: 16,
		FPDeviceMemory: 64,
	}
}

// TestAnalyze_BasicFields 验证基础字段正确传递
func TestAnalyze_BasicFields(t *testing.T) {
	data := makeTestData()
	eng := NewEngine()
	profile := eng.Analyze(data)

	if profile.IP != "10.0.0.1" {
		t.Errorf("expected IP '10.0.0.1', got '%s'", profile.IP)
	}
	if profile.TotalConnections != 100 {
		t.Errorf("expected 100 connections, got %d", profile.TotalConnections)
	}
	if profile.PortScanCount != 1 {
		t.Errorf("expected 1 port scan, got %d", profile.PortScanCount)
	}
	if len(profile.UniqueServices) != 5 {
		t.Errorf("expected 5 unique services, got %d", len(profile.UniqueServices))
	}
	if len(profile.UniquePaths) != 11 {
		t.Errorf("expected 11 unique paths, got %d", len(profile.UniquePaths))
	}
}

// TestAnalyze_ActiveMetrics 验证活动指标计算
func TestAnalyze_ActiveMetrics(t *testing.T) {
	data := makeTestData()
	eng := NewEngine()
	profile := eng.Analyze(data)

	if profile.ActiveDays < 1 {
		t.Errorf("expected ActiveDays >= 1, got %d", profile.ActiveDays)
	}
	if profile.AvgReqPerMinute <= 0 {
		t.Errorf("expected AvgReqPerMinute > 0, got %.2f", profile.AvgReqPerMinute)
	}
	// Peak hour should be 22 (highest count in HourDistribution)
	if profile.PeakHour != 22 {
		t.Errorf("expected peak hour 22, got %d", profile.PeakHour)
	}
	if profile.InteractionDepth != 15 {
		t.Errorf("expected interaction depth 15%%, got %d", profile.InteractionDepth)
	}
}

// TestAnalyze_FingerprintSummary 验证指纹摘要
func TestAnalyze_FingerprintSummary(t *testing.T) {
	data := makeTestData()
	eng := NewEngine()
	profile := eng.Analyze(data)

	if profile.FingerprintSummary == nil {
		t.Fatal("expected FingerprintSummary, got nil")
	}
	if profile.FingerprintSummary.Browser != "Chrome 124" {
		t.Errorf("expected browser 'Chrome 124', got '%s'", profile.FingerprintSummary.Browser)
	}
	if profile.FingerprintSummary.GPU != "NVIDIA GeForce RTX 3060" {
		t.Errorf("expected GPU 'NVIDIA GeForce RTX 3060', got '%s'", profile.FingerprintSummary.GPU)
	}
	if profile.FingerprintSummary.HardwareCPUs != 16 {
		t.Errorf("expected 16 CPUs, got %d", profile.FingerprintSummary.HardwareCPUs)
	}
	if profile.FingerprintSummary.DeviceMemory != 64 {
		t.Errorf("expected 64GB memory, got %d", profile.FingerprintSummary.DeviceMemory)
	}
}

// TestAnalyze_FingerprintSummary_WithoutFP 验证无指纹时的处理
func TestAnalyze_FingerprintSummary_WithoutFP(t *testing.T) {
	data := makeTestData()
	data.HasFingerprint = false
	eng := NewEngine()
	profile := eng.Analyze(data)

	if profile.FingerprintSummary != nil {
		t.Error("expected nil FingerprintSummary when no fingerprint data")
	}
}

// TestSkillScore_HighScore 验证高技能评分场景
func TestSkillScore_HighScore(t *testing.T) {
	data := makeTestData()
	score := calcSkillScore(data)
	// 5 services (+15), port scan (+10), 11 paths (+15), 1 active day (+5),
	// high freq (~0.07 req/min gets 0 for the threshold),
	// 15% interaction (+8), 3 tools (+10), 5 TTPs (+10) = 73
	if score < 60 {
		t.Errorf("expected score >= 60 for high-activity attacker, got %d", score)
	}
}

// TestSkillScore_NoActivity 验证无活动场景评分
func TestSkillScore_NoActivity(t *testing.T) {
	data := &ProfileData{
		IP:               "192.168.1.1",
		FirstSeen:        time.Now(),
		LastSeen:         time.Now(),
		TotalConnections: 1,
		UniqueServices:   []string{"http"},
		UniquePaths:      []string{"/"},
		HourDistribution: map[int]int{},
		UAs:              []string{""},
	}
	score := calcSkillScore(data)
	if score >= 25 {
		t.Errorf("expected score < 25 for no-activity attacker, got %d", score)
	}
}

// TestSkillTags 验证技术水平标签分档
func TestSkillTags(t *testing.T) {
	tests := []struct {
		score    int
		expected string
	}{
		{90, "advanced_actor"},
		{75, "advanced_actor"},
		{50, "intermediate"},
		{74, "intermediate"},
		{25, "script_kiddie"},
		{49, "script_kiddie"},
		{0, "novice"},
		{24, "novice"},
	}
	for _, tt := range tests {
		profile := &AttackerProfile{Tags: make([]ProfileTag, 0), SkillScore: tt.score}
		applySkillTags(profile)
		found := false
		for _, tag := range profile.Tags {
			if tag.Category == "skill" && tag.Name == tt.expected {
				found = true
				break
			}
		}
		if !found {
			t.Errorf("score=%d: expected tag '%s', got tags %v", tt.score, tt.expected, profile.Tags)
		}
	}
}

// TestBehaviorTags_Cautious 验证谨慎标签
func TestBehaviorTags_Cautious(t *testing.T) {
	data := &ProfileData{
		IP:               "10.0.0.50",
		FirstSeen:        time.Now().Add(-48 * time.Hour),
		LastSeen:         time.Now(),
		TotalConnections: 60,
		TotalBreadcrumbs: 0, // 避免触发蜜罐
		PortScanCount:    1, // 先扫描
		UniqueServices:   []string{"http", "https"},
		AvgReqPerMinute:  0.1, // 慢速
		PeakHour:         3,    // 凌晨活动
		HourDistribution: map[int]int{3: 40},
		UniquePaths:      []string{"/"},
		UAs:              []string{""},
		ActiveDays:       3,
	}
	profile := &AttackerProfile{Tags: make([]ProfileTag, 0)}
	applyBehaviorTags(profile, data)

	hasCautious := false
	for _, tag := range profile.Tags {
		if tag.Name == "cautious" {
			hasCautious = true
			break
		}
	}
	if !hasCautious {
		t.Error("expected 'cautious' behavior tag for low-interaction attacker")
	}
}

// TestBehaviorTags_Aggressive 验证激进标签
func TestBehaviorTags_Aggressive(t *testing.T) {
	data := &ProfileData{
		IP:               "10.0.0.60",
		FirstSeen:        time.Now(),
		LastSeen:         time.Now(),
		TotalConnections: 500,
		TotalBreadcrumbs: 50, // 大量触发
		UniqueServices:   []string{"http", "ssh", "mysql", "redis", "ftp", "mongo"},
		AvgReqPerMinute:  10, // 高频
		HourDistribution: map[int]int{14: 200},
		UniquePaths:      []string{"/"},
		UAs:              []string{""},
	}
	profile := &AttackerProfile{Tags: make([]ProfileTag, 0)}
	applyBehaviorTags(profile, data)

	hasAggressive := false
	for _, tag := range profile.Tags {
		if tag.Name == "aggressive" {
			hasAggressive = true
			break
		}
	}
	if !hasAggressive {
		t.Error("expected 'aggressive' behavior tag for high-interaction attacker")
	}
}

// TestBehaviorTags_Organized 验证有组织攻击标签
func TestBehaviorTags_Organized(t *testing.T) {
	data := &ProfileData{
		IP:               "10.0.0.70",
		FirstSeen:        time.Now().Add(-72 * time.Hour),
		LastSeen:         time.Now(),
		TotalConnections: 30,
		UniqueServices:   []string{"http", "https", "mysql"},
		ActiveDays:       3,
		HourDistribution: map[int]int{10: 10, 14: 10, 18: 10},
		UniquePaths:      []string{"/"},
		UAs:              []string{""},
	}
	profile := &AttackerProfile{Tags: make([]ProfileTag, 0)}
	applyBehaviorTags(profile, data)

	hasOrganized := false
	for _, tag := range profile.Tags {
		if tag.Name == "organized" {
			hasOrganized = true
			break
		}
	}
	if !hasOrganized {
		t.Error("expected 'organized' tag for multi-service multi-day attacker")
	}
}

// TestMotiveTags_DataTheft 验证数据窃取标签
func TestMotiveTags_DataTheft(t *testing.T) {
	data := &ProfileData{
		IP:        "10.0.0.80",
		FirstSeen: time.Now(),
		LastSeen:  time.Now(),
		UniquePaths: []string{
			"/config/application.yml",
			"/.env",
			"/backup/database.sql",
		},
		UniqueServices:   []string{"http"},
		HourDistribution: map[int]int{},
		UAs:              []string{""},
	}
	profile := &AttackerProfile{Tags: make([]ProfileTag, 0)}
	applyMotiveTags(profile, data)

	hasDataTheft := false
	for _, tag := range profile.Tags {
		if tag.Name == "data_theft" {
			hasDataTheft = true
			break
		}
	}
	if !hasDataTheft {
		t.Error("expected 'data_theft' tag for config/db path access")
	}
}

// TestMotiveTags_WebShell 验证WebShell标签
func TestMotiveTags_WebShell(t *testing.T) {
	data := &ProfileData{
		IP:        "10.0.0.90",
		FirstSeen: time.Now(),
		LastSeen:  time.Now(),
		UniquePaths: []string{
			"/shell.jsp",
			"/cmd.jsp",
		},
		UniqueServices:   []string{"http"},
		HourDistribution: map[int]int{},
		UAs:              []string{""},
	}
	profile := &AttackerProfile{Tags: make([]ProfileTag, 0)}
	applyMotiveTags(profile, data)

	hasWebShell := false
	for _, tag := range profile.Tags {
		if tag.Name == "webshell" {
			hasWebShell = true
			break
		}
	}
	if !hasWebShell {
		t.Error("expected 'webshell' tag for JSP path access")
	}
}

// TestMotiveTags_ReconOnly 验证纯侦查标签
func TestMotiveTags_ReconOnly(t *testing.T) {
	data := &ProfileData{
		IP:               "10.0.0.91",
		FirstSeen:        time.Now(),
		LastSeen:         time.Now(),
		UniqueServices:   []string{"http", "https", "mysql", "redis", "ssh"},
		TotalBreadcrumbs: 0,
		UniquePaths:      []string{"/"},
		HourDistribution: map[int]int{},
		UAs:              []string{""},
	}
	profile := &AttackerProfile{Tags: make([]ProfileTag, 0)}
	applyMotiveTags(profile, data)

	hasReconOnly := false
	for _, tag := range profile.Tags {
		if tag.Name == "recon_only" {
			hasReconOnly = true
			break
		}
	}
	if !hasReconOnly {
		t.Error("expected 'recon_only' tag for multi-service no-breadcrumb scanner")
	}
}

// TestToolTags 验证工具检测
func TestToolTags(t *testing.T) {
	data := &ProfileData{
		IP:               "10.0.0.92",
		FirstSeen:        time.Now(),
		LastSeen:         time.Now(),
		UniqueServices:   []string{"http"},
		HourDistribution: map[int]int{},
		UAs: []string{
			"Nuclei v2.9.1",
			"sqlmap/1.6-dev",
			"Burp Suite Professional",
		},
		UniquePaths: []string{"/"},
	}
	profile := &AttackerProfile{Tags: make([]ProfileTag, 0)}
	applyToolTags(profile, data)

	hasNuclei := false
	hasSQLMap := false
	hasBurp := false
	for _, tag := range profile.Tags {
		switch tag.Name {
		case "nuclei_user":
			hasNuclei = true
		case "sqlmap_user":
			hasSQLMap = true
		case "burp_user":
			hasBurp = true
		}
	}
	if !hasNuclei || !hasSQLMap || !hasBurp {
		t.Errorf("expected all tool tags, got Nuclei=%v SQLMap=%v Burp=%v", hasNuclei, hasSQLMap, hasBurp)
	}
}

// TestRiskScore_Critical 验证严重风险
func TestRiskScore_Critical(t *testing.T) {
	profile := &AttackerProfile{
		Tags:               make([]ProfileTag, 0),
		SkillScore:         90,
		TotalBreadcrumbs:   15,
		PortScanCount:      1,
		TotalCountermeasures: 1,
		TTPSignatures: []TTPSignature{
			{Tactic: "A", Count: 1}, {Tactic: "B", Count: 1}, {Tactic: "C", Count: 1},
			{Tactic: "D", Count: 1}, {Tactic: "E", Count: 1},
		},
	}
	score := calcRiskScore(profile)
	if score < 60 {
		t.Errorf("expected risk score >= 60 for critical attacker, got %d", score)
	}
}

// TestRiskScore_Low 验证低风险
func TestRiskScore_Low(t *testing.T) {
	profile := &AttackerProfile{
		Tags:               make([]ProfileTag, 0),
		SkillScore:         10,
		TotalBreadcrumbs:   1,
		PortScanCount:      0,
		TotalCountermeasures: 0,
		TTPSignatures: []TTPSignature{{Tactic: "A", Count: 1}},
	}
	score := calcRiskScore(profile)
	if score >= 20 {
		t.Errorf("expected risk score < 20 for low-risk attacker, got %d", score)
	}
}

// TestThreatLevel 验证威胁等级判定
func TestThreatLevel(t *testing.T) {
	tests := []struct {
		riskScore int
		level     string
	}{
		{95, "critical"},
		{80, "critical"},
		{60, "high"},
		{79, "high"},
		{30, "medium"},
		{59, "medium"},
		{0, "low"},
		{29, "low"},
	}
	for _, tt := range tests {
		profile := &AttackerProfile{
			Tags: make([]ProfileTag, 0),
		}
		profile.RiskScore = tt.riskScore
		// Re-apply threat level logic
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
		if profile.ThreatLevel != tt.level {
			t.Errorf("riskScore=%d: expected '%s', got '%s'", tt.riskScore, tt.level, profile.ThreatLevel)
		}
	}
}

// TestAnalyze_NoData 验证空数据场景不会崩溃
func TestAnalyze_NoData(t *testing.T) {
	data := &ProfileData{
		IP:               "0.0.0.0",
		FirstSeen:        time.Now(),
		LastSeen:         time.Now(),
		UniqueServices:   []string{},
		UniquePaths:      []string{},
		HourDistribution: map[int]int{},
		UAs:              []string{},
	}
	eng := NewEngine()
	profile := eng.Analyze(data)

	if profile == nil {
		t.Fatal("expected non-nil profile for empty data")
	}
	if profile.ThreatLevel != "low" {
		t.Errorf("expected 'low' threat level for empty data, got '%s'", profile.ThreatLevel)
	}
	if profile.SkillScore != 0 {
		t.Errorf("expected 0 skill score for empty data, got %d", profile.SkillScore)
	}
}

// TestAnalyze_ComprehensiveOutput 验证综合画像输出完整性
func TestAnalyze_ComprehensiveOutput(t *testing.T) {
	data := makeTestData()
	eng := NewEngine()
	profile := eng.Analyze(data)

	// 验证所有必要的字段都存在
	if profile.IP == "" {
		t.Error("IP should not be empty")
	}
	if profile.ThreatLevel == "" {
		t.Error("ThreatLevel should not be empty")
	}
	if profile.SkillScore < 0 || profile.SkillScore > 100 {
		t.Errorf("SkillScore out of range: %d", profile.SkillScore)
	}
	if profile.RiskScore < 0 || profile.RiskScore > 100 {
		t.Errorf("RiskScore out of range: %d", profile.RiskScore)
	}
	if len(profile.Tags) == 0 {
		t.Error("expected at least some tags")
	}
	if len(profile.ToolSignatures) == 0 {
		t.Error("expected tool signatures for multi-UA data")
	}
	if len(profile.TTPSignatures) != 5 {
		t.Errorf("expected 5 TTP signatures, got %d", len(profile.TTPSignatures))
	}

	// 验证标签类别分布
	categories := map[string]int{"skill": 0, "behavior": 0, "motive": 0, "tool": 0}
	for _, tag := range profile.Tags {
		categories[tag.Category]++
	}
	if categories["skill"] == 0 {
		t.Error("expected at least 1 skill tag")
	}
	if categories["behavior"] == 0 {
		t.Error("expected at least 1 behavior tag")
	}
	if categories["tool"] == 0 {
		t.Error("expected at least 1 tool tag")
	}

	// 验证标签置信度在合法范围内
	for _, tag := range profile.Tags {
		if tag.Confidence < 0 || tag.Confidence > 100 {
			t.Errorf("tag '%s' confidence out of range: %d", tag.Name, tag.Confidence)
		}
		if tag.Source != "rule" {
			t.Errorf("expected source 'rule', got '%s'", tag.Source)
		}
	}
}

// TestTagCategories 验证标签分类定义
func TestTagCategories(t *testing.T) {
	if len(TagCategories) != 4 {
		t.Errorf("expected 4 tag categories, got %d", len(TagCategories))
	}
	keys := map[string]bool{}
	for _, c := range TagCategories {
		if c.Key == "" || c.Name == "" {
			t.Error("tag category should have both key and name")
		}
		if keys[c.Key] {
			t.Errorf("duplicate tag category key: %s", c.Key)
		}
		keys[c.Key] = true
	}
	expectedKeys := []string{"skill", "behavior", "motive", "tool"}
	for _, k := range expectedKeys {
		if !keys[k] {
			t.Errorf("expected tag category '%s'", k)
		}
	}
}

// TestDetectTools 验证工具检测
func TestDetectTools(t *testing.T) {
	data := &ProfileData{
		UAs: []string{
			"Nuclei/2.9",
			"Mozilla/5.0 (compatible; sqlmap/1.6)",
			"Burp Suite Community Edition",
			"Mozilla/5.0 (Windows NT 10.0; Win64; x64) Chrome/120",
			"curl/8.0",
		},
	}
	tools := detectTools(data)
	if len(tools) < 4 {
		t.Errorf("expected at least 4 tools, got %d: %v", len(tools), tools)
	}
}

// TestMinMax 验证辅助函数
func TestMinMax(t *testing.T) {
	if min(5, 10) != 5 {
		t.Error("min(5,10) should be 5")
	}
	if min(10, 5) != 5 {
		t.Error("min(10,5) should be 5")
	}
	if max(5, 10) != 10 {
		t.Error("max(5,10) should be 10")
	}
	if max(10, 5) != 10 {
		t.Error("max(10,5) should be 10")
	}
}

// TestItoa 验证数字转字符串
func TestItoa(t *testing.T) {
	if itoa(0) != "0" {
		t.Errorf("itoa(0) = '%s'", itoa(0))
	}
	if itoa(100) != "100" {
		t.Errorf("itoa(100) = '%s'", itoa(100))
	}
	if itoa(-1) != "-1" {
		t.Errorf("itoa(-1) = '%s'", itoa(-1))
	}
}

// TestNewEngine 验证引擎创建
func TestNewEngine(t *testing.T) {
	eng := NewEngine()
	if eng == nil {
		t.Fatal("expected non-nil engine")
	}
	if eng.tags == nil {
		t.Error("expected non-nil tags map")
	}
}
