package profile

import (
	"testing"
	"time"
)

// mockStore 模拟 ProfileStore 接口
type mockStore struct {
	data      map[string]*ProfileData
	profiles  []*AttackerProfile
	summaries map[string][]CountermeasureSummary
}

func newMockStore() *mockStore {
	return &mockStore{
		data:      make(map[string]*ProfileData),
		profiles:  make([]*AttackerProfile, 0),
		summaries: make(map[string][]CountermeasureSummary),
	}
}

func (m *mockStore) AggregateProfileData(ip string) (*ProfileData, error) {
	if d, ok := m.data[ip]; ok {
		return d, nil
	}
	return &ProfileData{IP: ip}, nil
}

func (m *mockStore) AggregateProfileByIP(eng *Engine, ip string) (*AttackerProfile, error) {
	data, _ := m.AggregateProfileData(ip)
	return eng.Analyze(data), nil
}

func (m *mockStore) AggregateAllProfiles(eng *Engine, tagFilter string) ([]*AttackerProfile, error) {
	var results []*AttackerProfile
	for _, data := range m.data {
		p := eng.Analyze(data)
		if tagFilter != "" {
			matched := false
			for _, t := range p.Tags {
				if t.Category == tagFilter {
					matched = true
					break
				}
			}
			if !matched {
				continue
			}
		}
		results = append(results, p)
	}
	return results, nil
}

func (m *mockStore) GetCountermeasureSummariesByIP(ip string) ([]CountermeasureSummary, error) {
	if s, ok := m.summaries[ip]; ok {
		return s, nil
	}
	return []CountermeasureSummary{}, nil
}

// TestBuilder_BuildProfile 验证单个画像构建
func TestBuilder_BuildProfile(t *testing.T) {
	mock := newMockStore()

	// 准备测试数据
	now := time.Now()
	mock.data["10.0.0.1"] = &ProfileData{
		IP:               "10.0.0.1",
		FirstSeen:        now.Add(-24 * time.Hour),
		LastSeen:         now,
		TotalConnections: 50,
		TotalBreadcrumbs: 8,
		PortScanCount:    1,
		UniqueServices:   []string{"HTTP", "SSH", "MySQL"},
		UniquePaths:      []string{"/admin", "/.env", "/api", "/login", "/backup"},
		HourDistribution: map[int]int{3: 10, 14: 20, 22: 20},
		UAs:              []string{"Mozilla/5.0 Chrome", "sqlmap/1.0"},
		HasFingerprint:   true,
		FPBrowser:        "Chrome 120",
		FPOS:             "Linux",
	}

	mock.summaries["10.0.0.1"] = []CountermeasureSummary{
		{OpType: "screen_capture", Score: 25, Timestamp: now.Add(-1 * time.Hour), TargetIP: "10.0.0.1"},
		{OpType: "file_scan", Score: 15, Timestamp: now.Add(-2 * time.Hour), TargetIP: "10.0.0.1"},
	}

	builder := NewBuilder(mock)
	profile, err := builder.BuildProfile("10.0.0.1")
	if err != nil {
		t.Fatalf("BuildProfile failed: %v", err)
	}

	if profile.IP != "10.0.0.1" {
		t.Errorf("expected IP '10.0.0.1', got '%s'", profile.IP)
	}
	if profile.TotalConnections != 50 {
		t.Errorf("expected 50 connections, got %d", profile.TotalConnections)
	}
	if profile.TotalBreadcrumbs != 8 {
		t.Errorf("expected 8 breadcrumbs, got %d", profile.TotalBreadcrumbs)
	}
	if len(profile.UniqueServices) != 3 {
		t.Errorf("expected 3 services, got %d", len(profile.UniqueServices))
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

	// 验证反制措施摘要已附加
	if len(profile.Countermeasures) != 2 {
		t.Errorf("expected 2 countermeasures, got %d", len(profile.Countermeasures))
	}
	if len(profile.Countermeasures) > 0 {
		if profile.Countermeasures[0].OpType != "screen_capture" {
			t.Errorf("expected first countermeasure 'screen_capture', got '%s'", profile.Countermeasures[0].OpType)
		}
	}

	// 验证指纹摘要
	if profile.FingerprintSummary == nil {
		t.Error("expected FingerprintSummary, got nil")
	} else {
		if profile.FingerprintSummary.Browser != "Chrome 120" {
			t.Errorf("expected browser 'Chrome 120', got '%s'", profile.FingerprintSummary.Browser)
		}
	}

	// 验证标签
	if len(profile.Tags) == 0 {
		t.Error("expected at least some tags")
	}
}

// TestBuilder_BuildAllProfiles 验证批量画像构建
func TestBuilder_BuildAllProfiles(t *testing.T) {
	mock := newMockStore()

	now := time.Now()
	mock.data["10.0.0.1"] = &ProfileData{
		IP:               "10.0.0.1",
		FirstSeen:        now.Add(-48 * time.Hour),
		LastSeen:         now,
		TotalConnections: 100,
		TotalBreadcrumbs: 5,
		UniqueServices:   []string{"HTTP"},
		UniquePaths:      []string{"/"},
		HourDistribution: map[int]int{12: 50},
		UAs:              []string{"curl/8.0"},
	}
	mock.data["10.0.0.2"] = &ProfileData{
		IP:               "10.0.0.2",
		FirstSeen:        now.Add(-12 * time.Hour),
		LastSeen:         now,
		TotalConnections: 500,
		TotalBreadcrumbs: 50,
		PortScanCount:    3,
		UniqueServices:   []string{"HTTP", "SSH", "MySQL", "Redis", "FTP", "SMB"},
		UniquePaths: []string{
			"/admin", "/.env", "/etc/passwd", "/.git/config",
			"/swagger", "/actuator/heapdump", "/shell.jsp",
		},
		HourDistribution: map[int]int{2: 100, 3: 200, 4: 200},
		UAs: []string{
			"Nuclei/2.9", "sqlmap/1.6", "Burp Suite Pro",
		},
		HasFingerprint: true,
		FPBrowser:      "Chrome 124",
		FPOS:           "Windows 10",
		FPGPU:          "NVIDIA RTX 3060",
	}

	builder := NewBuilder(mock)

	// 测试无限制
	profiles, err := builder.BuildAllProfiles(0)
	if err != nil {
		t.Fatalf("BuildAllProfiles failed: %v", err)
	}
	if len(profiles) != 2 {
		t.Errorf("expected 2 profiles, got %d", len(profiles))
	}

	// 测试 limit
	profiles, err = builder.BuildAllProfiles(1)
	if err != nil {
		t.Fatalf("BuildAllProfiles with limit failed: %v", err)
	}
	if len(profiles) > 1 {
		t.Errorf("expected at most 1 profile with limit=1, got %d", len(profiles))
	}

	// 验证高风险攻击者画像
	if len(profiles) > 0 {
		p := profiles[0]
		if p.ThreatLevel == "" {
			t.Error("ThreatLevel should not be empty")
		}
		if p.RiskScore < 0 || p.RiskScore > 100 {
			t.Errorf("RiskScore out of range: %d", p.RiskScore)
		}
	}
}

// TestBuilder_BuildProfile_NoData 验证无数据 IP 场景
func TestBuilder_BuildProfile_NoData(t *testing.T) {
	mock := newMockStore()
	builder := NewBuilder(mock)

	profile, err := builder.BuildProfile("192.168.1.1")
	if err != nil {
		t.Fatalf("BuildProfile for unknown IP should not error: %v", err)
	}
	if profile == nil {
		t.Fatal("expected non-nil profile for unknown IP")
	}
	if profile.IP != "192.168.1.1" {
		t.Errorf("expected IP '192.168.1.1', got '%s'", profile.IP)
	}
	if profile.ThreatLevel != "low" {
		t.Errorf("expected 'low' threat level for unknown IP, got '%s'", profile.ThreatLevel)
	}
	// 无数据的 IP 不应有反制措施
	if len(profile.Countermeasures) != 0 {
		t.Errorf("expected 0 countermeasures for unknown IP, got %d", len(profile.Countermeasures))
	}
}

// TestBuilder_NewBuilder 验证 Builder 创建
func TestBuilder_NewBuilder(t *testing.T) {
	mock := newMockStore()
	builder := NewBuilder(mock)
	if builder == nil {
		t.Fatal("expected non-nil builder")
	}
	if builder.store == nil {
		t.Error("expected non-nil store")
	}
	if builder.engine == nil {
		t.Error("expected non-nil engine")
	}
}

// TestCountermeasureSummary 验证 CountermeasureSummary 类型
func TestCountermeasureSummary(t *testing.T) {
	now := time.Now()
	cs := CountermeasureSummary{
		OpType:    "screen_capture",
		Score:     25,
		Timestamp: now,
		TargetIP:  "10.0.0.1",
	}

	if cs.OpType != "screen_capture" {
		t.Errorf("expected OpType 'screen_capture', got '%s'", cs.OpType)
	}
	if cs.Score != 25 {
		t.Errorf("expected Score 25, got %d", cs.Score)
	}
	if cs.TargetIP != "10.0.0.1" {
		t.Errorf("expected TargetIP '10.0.0.1', got '%s'", cs.TargetIP)
	}
}
