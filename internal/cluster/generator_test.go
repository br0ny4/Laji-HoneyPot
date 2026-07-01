package cluster

import (
	"strings"
	"testing"

	"github.com/Laji-HoneyPot/honeypot/internal/honeypot/traps"
)

func TestGenerator_WebScenario(t *testing.T) {
	g := NewGenerator("0.10.1")
	req := AgentDeployRequest{
		ManagerAddr:  "10.0.0.1:8443",
		Scenario:     "web",
		BinarySource: "build",
	}

	artifact, err := g.Generate(req)
	if err != nil {
		t.Fatalf("Generate failed: %v", err)
	}

	// 验证场景
	if artifact.Scenario != "web" {
		t.Errorf("expected scenario web, got %s", artifact.Scenario)
	}

	// 验证仅 HTTP 服务
	if len(artifact.EnabledSvcs) != 1 || artifact.EnabledSvcs[0] != "http" {
		t.Errorf("expected only http service, got %v", artifact.EnabledSvcs)
	}

	// 验证配置 YAML 含关键字段
	if !strings.Contains(artifact.ConfigYAML, `manager_addr: "10.0.0.1:8443"`) {
		t.Error("config YAML missing manager_addr")
	}
	if !strings.Contains(artifact.ConfigYAML, `role: "node"`) {
		t.Error("config YAML missing role: node")
	}
	if !strings.Contains(artifact.ConfigYAML, `trap_scenario: "web"`) {
		t.Error("config YAML missing trap_scenario")
	}

	// 验证 CLI 命令含管理端地址
	if !strings.Contains(artifact.CLICommand, "10.0.0.1:8443") {
		t.Error("CLI command missing manager address")
	}

	// 验证部署脚本
	if !strings.Contains(artifact.DeployScript, "#!/bin/bash") {
		t.Error("deploy script should be a bash script")
	}
	if !strings.Contains(artifact.DeployScript, "10.0.0.1:8443") {
		t.Error("deploy script missing manager address")
	}

	// 验证校验提示
	if !strings.Contains(artifact.VerifyHint, "验证注册") {
		t.Error("verify hint should contain verification steps")
	}

	// 验证 Docker 命令
	if !strings.Contains(artifact.DockerCommand, "docker run") {
		t.Error("docker command should contain docker run")
	}
}

func TestGenerator_RemoteAccessScenario(t *testing.T) {
	g := NewGenerator("0.10.1")
	req := AgentDeployRequest{
		ManagerAddr:  "192.168.1.100:8443",
		Scenario:     "remote_access",
		BinarySource: "release",
	}

	artifact, err := g.Generate(req)
	if err != nil {
		t.Fatalf("Generate failed: %v", err)
	}

	// 验证场景
	if artifact.Scenario != "remote_access" {
		t.Errorf("expected scenario remote_access, got %s", artifact.Scenario)
	}

	// 验证 SSH, RDP, FTP 服务
	enabled := artifact.EnabledSvcs
	if len(enabled) != 3 {
		t.Errorf("expected 3 services, got %d: %v", len(enabled), enabled)
	}
	hasService := func(svc string) bool {
		for _, s := range enabled {
			if s == svc {
				return true
			}
		}
		return false
	}
	for _, svc := range []string{"ssh", "rdp", "ftp"} {
		if !hasService(svc) {
			t.Errorf("expected service %s to be enabled", svc)
		}
	}
	if hasService("http") {
		t.Error("HTTP should not be enabled in remote_access scenario")
	}

	// Release 命令应含 curl 下载
	if !strings.Contains(artifact.CLICommand, "curl -sSL") {
		t.Error("release CLI command should contain curl download")
	}
	if !strings.Contains(artifact.CLICommand, "releases/latest/download") {
		t.Error("release CLI command should reference release download URL")
	}
}

func TestGenerator_CustomScenario(t *testing.T) {
	g := NewGenerator("0.10.1")
	req := AgentDeployRequest{
		ManagerAddr:    "10.0.0.1:8443",
		Scenario:       "custom",
		CustomServices: []string{"http", "mysql", "ssh"},
		BinarySource:   "build",
	}

	artifact, err := g.Generate(req)
	if err != nil {
		t.Fatalf("Generate failed: %v", err)
	}

	// 验证自定义服务
	enabled := artifact.EnabledSvcs
	if len(enabled) != 3 {
		t.Errorf("expected 3 custom services, got %d: %v", len(enabled), enabled)
	}
}

func TestGenerator_MissingManagerAddr(t *testing.T) {
	g := NewGenerator("0.10.1")
	req := AgentDeployRequest{
		ManagerAddr: "",
		Scenario:    "web",
	}

	_, err := g.Generate(req)
	if err == nil {
		t.Fatal("expected error for missing manager_addr")
	}
}

func TestGenerator_FullScenarioBackwardCompat(t *testing.T) {
	g := NewGenerator("0.10.1")
	req := AgentDeployRequest{
		ManagerAddr:  "10.0.0.1:8443",
		Scenario:     "full",
		BinarySource: "build",
	}

	artifact, err := g.Generate(req)
	if err != nil {
		t.Fatalf("Generate failed: %v", err)
	}

	// 全量场景应启用所有 9 个服务
	if len(artifact.EnabledSvcs) != 9 {
		t.Errorf("expected 9 services, got %d: %v", len(artifact.EnabledSvcs), artifact.EnabledSvcs)
	}

	// 配置应含 trap_scenario: "full"
	if !strings.Contains(artifact.ConfigYAML, `trap_scenario: "full"`) {
		t.Error("config YAML should have trap_scenario: full")
	}
}

func TestGenerator_URLSource(t *testing.T) {
	g := NewGenerator("0.10.1")
	req := AgentDeployRequest{
		ManagerAddr:  "10.0.0.1:8443",
		Scenario:     "web",
		BinarySource: "url",
		CustomURL:    "https://cdn.example.com/honeypot",
	}

	artifact, err := g.Generate(req)
	if err != nil {
		t.Fatalf("Generate failed: %v", err)
	}

	// URL 命令应含自定义 URL
	if !strings.Contains(artifact.CLICommand, "https://cdn.example.com/honeypot") {
		t.Error("URL CLI command should contain custom URL")
	}
}

func TestGenerator_TLSInsecure(t *testing.T) {
	g := NewGenerator("0.10.1")
	req := AgentDeployRequest{
		ManagerAddr: "10.0.0.1:8443",
		Scenario:    "web",
		TLSInsecure: true,
	}

	artifact, err := g.Generate(req)
	if err != nil {
		t.Fatalf("Generate failed: %v", err)
	}

	// 配置应含 tls_insecure: true
	if !strings.Contains(artifact.ConfigYAML, "tls_insecure: true") {
		t.Error("config YAML should have tls_insecure: true")
	}
}

func TestGenerator_NodeName(t *testing.T) {
	g := NewGenerator("0.10.1")
	req := AgentDeployRequest{
		ManagerAddr: "10.0.0.1:8443",
		Scenario:    "web",
		NodeName:    "web-node-01",
	}

	artifact, err := g.Generate(req)
	if err != nil {
		t.Fatalf("Generate failed: %v", err)
	}

	if !strings.Contains(artifact.ConfigYAML, "web-node-01") {
		t.Error("config YAML should contain node name")
	}
}

func TestGenerator_DeployScriptSystemd(t *testing.T) {
	g := NewGenerator("0.10.1")
	req := AgentDeployRequest{
		ManagerAddr:  "10.0.0.1:8443",
		Scenario:     "database",
		BinarySource: "release",
	}

	artifact, err := g.Generate(req)
	if err != nil {
		t.Fatalf("Generate failed: %v", err)
	}

	// 部署脚本应含 systemd 服务定义
	if !strings.Contains(artifact.DeployScript, "systemctl") {
		t.Error("deploy script should include systemd configuration")
	}
	if !strings.Contains(artifact.DeployScript, "[Unit]") {
		t.Error("deploy script should include systemd unit section")
	}
	if !strings.Contains(artifact.DeployScript, "After=network.target") {
		t.Error("deploy script should include systemd After directive")
	}
}

func TestGenerator_AllScenarios(t *testing.T) {
	g := NewGenerator("0.10.1")
	scenarios := []traps.TrapScenario{"web", "database", "remote_access", "infrastructure", "full"}

	for _, s := range scenarios {
		req := AgentDeployRequest{
			ManagerAddr: "10.0.0.1:8443",
			Scenario:    s,
		}

		artifact, err := g.Generate(req)
		if err != nil {
			t.Errorf("Generate failed for scenario %s: %v", s, err)
			continue
		}

		if len(artifact.EnabledSvcs) == 0 {
			t.Errorf("scenario %s should have at least 1 enabled service", s)
		}

		if artifact.ConfigYAML == "" {
			t.Errorf("scenario %s should generate config YAML", s)
		}

		if artifact.CLICommand == "" {
			t.Errorf("scenario %s should generate CLI command", s)
		}
	}
}
