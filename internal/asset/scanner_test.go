package asset

import (
	"testing"
	"time"
)

// TestNewScanner 验证扫描器创建
func TestNewScanner(t *testing.T) {
	s := NewScanner(nil)
	if s == nil {
		t.Fatal("expected non-nil scanner")
	}
	if s.timeout != 3*time.Second {
		t.Errorf("expected 3s timeout, got %v", s.timeout)
	}
	if len(s.hostTargets) != 1 || s.hostTargets[0] != "127.0.0.1" {
		t.Errorf("expected default host 127.0.0.1, got %v", s.hostTargets)
	}
}

// TestNewScanner_CustomHosts 验证自定义主机目标
func TestNewScanner_CustomHosts(t *testing.T) {
	s := NewScanner([]string{"192.168.1.1", "10.0.0.1"})
	if len(s.hostTargets) != 2 {
		t.Errorf("expected 2 hosts, got %d", len(s.hostTargets))
	}
}

// TestScan_EmptyTargets 验证空目标扫描（扫描所有已知端口）
func TestScan_EmptyTargets(t *testing.T) {
	s := NewScanner(nil)
	result := s.Scan(nil)
	if result.Total == 0 {
		t.Error("expected at least some scan targets")
	}
	// 应该扫描所有 knownPorts
	expectedMin := len(knownPorts)
	if result.Total < expectedMin {
		t.Errorf("expected at least %d scan targets, got %d", expectedMin, result.Total)
	}
}

// TestScan_SpecificTarget 验证特定目标扫描
func TestScan_SpecificTarget(t *testing.T) {
	s := NewScanner(nil)
	targets := []ScanTarget{{Host: "127.0.0.1", Port: 80}}
	result := s.Scan(targets)
	if result.Total != 1 {
		t.Errorf("expected 1 scan target, got %d", result.Total)
	}
	if len(result.Services) != 1 {
		t.Errorf("expected 1 service, got %d", len(result.Services))
	}
}

// TestScanResult_Duration 验证扫描耗时记录
func TestScanResult_Duration(t *testing.T) {
	s := NewScanner(nil)
	result := s.Scan([]ScanTarget{{Host: "127.0.0.1", Port: 9999}}) // 不可能开放的端口
	if result.Duration == "" {
		t.Error("expected non-empty duration")
	}
}

// TestServiceInfo_Fields 验证服务信息字段
func TestServiceInfo_Fields(t *testing.T) {
	s := NewScanner(nil)
	result := s.Scan([]ScanTarget{{Host: "127.0.0.1", Port: 9999}})
	svc := result.Services[0]
	if svc.Host != "127.0.0.1" {
		t.Errorf("expected host 127.0.0.1, got %s", svc.Host)
	}
	if svc.Port != 9999 {
		t.Errorf("expected port 9999, got %d", svc.Port)
	}
	if svc.Open {
		t.Error("port 9999 should not be open")
	}
	if svc.Protocol != "" {
		t.Errorf("closed port should have empty protocol, got %s", svc.Protocol)
	}
}

// TestKnownPorts_Completeness 验证端口映射的完整性
func TestKnownPorts_Completeness(t *testing.T) {
	requiredPorts := []int{21, 22, 80, 443, 3306, 6379, 8080, 27017}
	for _, p := range requiredPorts {
		if _, ok := knownPorts[p]; !ok {
			t.Errorf("knownPorts missing required port %d", p)
		}
	}
}

// TestGetKnownPorts 验证 GetKnownPorts 函数
func TestGetKnownPorts(t *testing.T) {
	m := GetKnownPorts()
	if m[80] != "HTTP" {
		t.Errorf("expected HTTP on port 80, got %s", m[80])
	}
	if len(m) != len(knownPorts) {
		t.Errorf("expected %d ports, got %d", len(knownPorts), len(m))
	}
}

// TestExtractVersion 测试 Banner 版本提取
func TestExtractVersion(t *testing.T) {
	tests := []struct {
		input    string
		contains string
	}{
		{"SSH-2.0-OpenSSH_8.9p1", "SSH-"},
		{"HTTP/1.1 200 OK Server: nginx/1.18.0", "nginx"},
		{"+PONG", "PONG"},
	}
	for _, tt := range tests {
		result := extractVersion(tt.input)
		if result == "" {
			t.Errorf("extractVersion(%q) returned empty", tt.input)
		}
	}
}

// TestScanResult_Stats 验证扫描统计
func TestScanResult_Stats(t *testing.T) {
	s := NewScanner(nil)
	result := s.Scan([]ScanTarget{
		{Host: "127.0.0.1", Port: 80},
		{Host: "127.0.0.1", Port: 9999},
	})
	if result.Total != 2 {
		t.Errorf("expected 2 total, got %d", result.Total)
	}
}
