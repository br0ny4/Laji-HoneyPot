package cluster

import (
	"fmt"
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

// =========================================================================
// v0.17.0 跨平台 Agent 生成测试
// =========================================================================

func TestGenerator_OSDefaultLinux(t *testing.T) {
	g := NewGenerator("0.17.0")
	req := AgentDeployRequest{
		ManagerAddr: "10.0.0.1:8443",
		Scenario:    "web",
		OSTarget:    "", // 空值应默认 linux
	}

	artifact, err := g.Generate(req)
	if err != nil {
		t.Fatalf("Generate failed: %v", err)
	}

	if artifact.OSTarget != "linux" {
		t.Errorf("empty OSTarget should default to linux, got %s", artifact.OSTarget)
	}
	if artifact.BinaryName != "honeypot-linux-amd64" {
		t.Errorf("expected linux binary name, got %s", artifact.BinaryName)
	}
	if !strings.Contains(artifact.DeployScript, "#!/bin/bash") {
		t.Error("linux deploy script should be bash")
	}
	if !strings.Contains(artifact.DeployScript, "systemctl") {
		t.Error("linux deploy script should include systemctl")
	}
	if strings.Contains(artifact.DeployScript, "PowerShell") {
		t.Error("linux deploy script should not contain PowerShell references")
	}
}

func TestGenerator_OSWindows(t *testing.T) {
	g := NewGenerator("0.17.0")
	req := AgentDeployRequest{
		ManagerAddr: "10.0.0.1:8443",
		Scenario:    "web",
		OSTarget:    "windows",
	}

	artifact, err := g.Generate(req)
	if err != nil {
		t.Fatalf("Generate failed: %v", err)
	}

	// 验证 OS 目标
	if artifact.OSTarget != "windows" {
		t.Errorf("expected windows OSTarget, got %s", artifact.OSTarget)
	}

	// 验证 Windows 二进制文件名
	if artifact.BinaryName != "honeypot-windows-amd64.exe" {
		t.Errorf("expected windows binary name, got %s", artifact.BinaryName)
	}

	// 验证 PowerShell 安装脚本
	if artifact.InstallScriptPS == "" {
		t.Error("Windows should have InstallScriptPS")
	}
	if !strings.Contains(artifact.InstallScriptPS, "PowerShell") {
		t.Error("install script should be PowerShell")
	}
	if !strings.Contains(artifact.InstallScriptPS, `C:\Program Files\Honeypot`) {
		t.Error("Windows script should use Program Files path")
	}

	// 验证 Windows 服务配置
	if artifact.ServiceConfig == "" {
		t.Error("Windows should have ServiceConfig")
	}
	if !strings.Contains(artifact.ServiceConfig, "sc.exe create HoneypotAgent") {
		t.Error("Windows service config should use sc.exe")
	}

	// 验证 CLI 命令使用 PowerShell
	if !strings.Contains(artifact.CLICommand, "Invoke-WebRequest") {
		t.Error("Windows CLI should use Invoke-WebRequest")
	}
	if !strings.Contains(artifact.CLICommand, ".exe") {
		t.Error("Windows CLI should reference .exe binary")
	}

	// 验证部署脚本是 PowerShell 格式
	if !strings.Contains(artifact.DeployScript, "Write-Host") {
		t.Error("Windows deploy script should contain Write-Host")
	}
	if !strings.Contains(artifact.DeployScript, "sc.exe") {
		t.Error("Windows deploy script should contain sc.exe service registration")
	}

	// 验证 VerifyHint 是 Windows 风格
	if !strings.Contains(artifact.VerifyHint, "sc.exe query") {
		t.Error("Windows verify hint should include sc.exe query")
	}
	if !strings.Contains(artifact.VerifyHint, "PowerShell") {
		t.Error("Windows verify hint should mention PowerShell")
	}

	// 验证 ConfigYAML 使用 Windows 路径
	if !strings.Contains(artifact.ConfigYAML, `C:\Program Files\Honeypot\data`) {
		t.Error("Windows config should use Program Files data dir")
	}

	// 确保 Windows 脚本不含 bash
	if strings.Contains(artifact.DeployScript, "#!/bin/bash") {
		t.Error("Windows deploy script should not be bash")
	}
}

func TestGenerator_WindowsAllScenarios(t *testing.T) {
	g := NewGenerator("0.17.0")
	scenarios := []traps.TrapScenario{"web", "database", "remote_access", "infrastructure", "full"}

	for _, s := range scenarios {
		req := AgentDeployRequest{
			ManagerAddr: "10.0.0.1:8443",
			Scenario:    s,
			OSTarget:    "windows",
		}

		artifact, err := g.Generate(req)
		if err != nil {
			t.Errorf("Windows Generate failed for scenario %s: %v", s, err)
			continue
		}

		// 所有场景都应生成有效的 Windows 产物
		if artifact.BinaryName != "honeypot-windows-amd64.exe" {
			t.Errorf("scenario %s: wrong binary name %s", s, artifact.BinaryName)
		}
		if artifact.InstallScriptPS == "" {
			t.Errorf("scenario %s: missing PowerShell install script", s)
		}
		if artifact.ServiceConfig == "" {
			t.Errorf("scenario %s: missing service config", s)
		}
		if artifact.OSTarget != "windows" {
			t.Errorf("scenario %s: wrong OSTarget %s", s, artifact.OSTarget)
		}
	}
}

func TestGenerator_LinuxWindowsComparison(t *testing.T) {
	g := NewGenerator("0.17.0")
	scenario := AgentDeployRequest{
		ManagerAddr: "10.0.0.1:8443",
		Scenario:    "remote_access",
	}

	// Linux
	linuxReq := scenario
	linuxReq.OSTarget = "linux"
	linuxArtifact, _ := g.Generate(linuxReq)

	// Windows
	winReq := scenario
	winReq.OSTarget = "windows"
	winArtifact, _ := g.Generate(winReq)

	// 二者使用不同的二进制名
	if linuxArtifact.BinaryName == winArtifact.BinaryName {
		t.Error("Linux and Windows should have different binary names")
	}

	// 二者使用不同的部署脚本格式
	if strings.Contains(winArtifact.DeployScript, "#!/bin/bash") {
		t.Error("Windows should not use bash")
	}
	if !strings.Contains(linuxArtifact.DeployScript, "#!/bin/bash") {
		t.Error("Linux should use bash")
	}

	// Linux 应无 PowerShell 安装脚本
	if linuxArtifact.InstallScriptPS != "" {
		t.Error("Linux should not have PowerShell install script")
	}

	// Windows 应有 PowerShell 安装脚本
	if winArtifact.InstallScriptPS == "" {
		t.Error("Windows should have PowerShell install script")
	}

	// 验证两种系统都包含了启用的服务列表
	if len(linuxArtifact.EnabledSvcs) != len(winArtifact.EnabledSvcs) {
		t.Errorf("same scenario should enable same services: linux=%v, windows=%v",
			linuxArtifact.EnabledSvcs, winArtifact.EnabledSvcs)
	}

	// ConfigYAML 中 Windows 路径与 Linux 不同
	if !strings.Contains(winArtifact.ConfigYAML, `C:\Program Files\Honeypot`) {
		t.Error("Windows config should contain Program Files path")
	}
	if !strings.Contains(linuxArtifact.ConfigYAML, `./data`) {
		t.Error("Linux config should contain ./data path")
	}
}

func TestGenerator_LinuxExplicit(t *testing.T) {
	g := NewGenerator("0.17.0")

	for _, osTarget := range []string{"linux", "Linux", "LINUX"} {
		req := AgentDeployRequest{
			ManagerAddr: "10.0.0.1:8443",
			Scenario:    "web",
			OSTarget:    osTarget,
		}

		artifact, err := g.Generate(req)
		if err != nil {
			t.Fatalf("Generate failed for OSTarget=%s: %v", osTarget, err)
		}

		// "Linux" / "LINUX" 目前被当作非 windows，所以应使用 linux 二进制
		// 只有值完全等于 "windows" 才会启用 Windows 模式
		if strings.Contains(artifact.CLICommand, "Invoke-WebRequest") {
			t.Errorf("OSTarget=%s should not generate PowerShell", osTarget)
		}
	}
}

func TestGenerator_WindowsTLSInsecure(t *testing.T) {
	g := NewGenerator("0.17.0")
	req := AgentDeployRequest{
		ManagerAddr: "10.0.0.1:8443",
		Scenario:    "web",
		OSTarget:    "windows",
		TLSInsecure: true,
	}

	artifact, err := g.Generate(req)
	if err != nil {
		t.Fatalf("Generate failed: %v", err)
	}

	// Windows 服务配置应包含 TLS insecure 标志
	if !strings.Contains(artifact.ServiceConfig, "--tls-insecure") {
		t.Error("Windows service config should include --tls-insecure flag")
	}

	// PowerShell 安装脚本也应包含
	if !strings.Contains(artifact.InstallScriptPS, "--tls-insecure") {
		t.Error("PowerShell install script should include --tls-insecure flag")
	}
}

func TestGenerator_WindowsNodeName(t *testing.T) {
	g := NewGenerator("0.17.0")
	req := AgentDeployRequest{
		ManagerAddr: "10.0.0.1:8443",
		Scenario:    "database",
		OSTarget:    "windows",
		NodeName:    "DB-Node-Win01",
	}

	artifact, err := g.Generate(req)
	if err != nil {
		t.Fatalf("Generate failed: %v", err)
	}

	// ConfigYAML 应包含节点名称
	if !strings.Contains(artifact.ConfigYAML, "DB-Node-Win01") {
		t.Error("Windows config should contain node name")
	}
}

func TestGenerator_WindowsPathSafety(t *testing.T) {
	// 确保 Windows 路径中不出现 Linux 路径分隔符问题
	g := NewGenerator("0.17.0")

	for _, scenario := range []traps.TrapScenario{"web", "database", "remote_access", "full"} {
		req := AgentDeployRequest{
			ManagerAddr: "10.0.0.1:8443",
			Scenario:    scenario,
			OSTarget:    "windows",
		}

		artifact, err := g.Generate(req)
		if err != nil {
			t.Fatalf("Generate failed: %v", err)
		}

		// Windows 脚本中不应出现 unix 风格的 /opt/ 路径
		if strings.Contains(artifact.DeployScript, "/opt/") {
			t.Errorf("scenario %s: Windows script should not contain /opt/", scenario)
		}
		if strings.Contains(artifact.DeployScript, "/usr/local/bin") {
			t.Errorf("scenario %s: Windows script should not contain /usr/local/bin", scenario)
		}
	}
}

func TestGenerator_WindowsSourceTypes(t *testing.T) {
	g := NewGenerator("0.17.0")

	for _, source := range []string{"release", "build", "url"} {
		req := AgentDeployRequest{
			ManagerAddr:  "10.0.0.1:8443",
			Scenario:     "web",
			OSTarget:     "windows",
			BinarySource: source,
			CustomURL:    "https://cdn.example.com/honeypot-windows.exe",
		}

		artifact, err := g.Generate(req)
		if err != nil {
			t.Fatalf("Generate failed for source=%s: %v", source, err)
		}

		// Windows 统一使用 Invoke-WebRequest 下载 .exe，不区分 source 类型
		if !strings.Contains(artifact.CLICommand, "Invoke-WebRequest") {
			t.Errorf("source=%s: Windows CLI should use Invoke-WebRequest, got: %s", source, artifact.CLICommand[:100])
		}

		if !strings.Contains(artifact.CLICommand, ".exe") {
			t.Errorf("source=%s: Windows CLI should download .exe", source)
		}
	}
}

func TestGenerator_BackwardCompatibilityBeforeV017(t *testing.T) {
	// 旧版请求中不含 OSTarget 字段，默认应为 linux
	g := NewGenerator("0.16.0")
	req := AgentDeployRequest{
		ManagerAddr: "10.0.0.1:8443",
		Scenario:    "full",
	}

	artifact, err := g.Generate(req)
	if err != nil {
		t.Fatalf("Generate failed: %v", err)
	}

	// 默认为 linux
	if artifact.OSTarget != "linux" {
		t.Errorf("default OSTarget should be linux, got %s", artifact.OSTarget)
	}
	if artifact.BinaryName != "honeypot-linux-amd64" {
		t.Errorf("default binary should be linux, got %s", artifact.BinaryName)
	}
	if artifact.InstallScriptPS != "" {
		t.Error("Linux should not have PowerShell install script")
	}
	if artifact.ServiceConfig != "" {
		t.Error("Linux should not have Windows service config")
	}
}

func TestGenerator_AllScenariosCrossPlatform(t *testing.T) {
	// 对每个场景在 Linux 和 Windows 上都验证生成成功
	g := NewGenerator("0.17.0")
	scenarios := []string{"web", "database", "remote_access", "infrastructure", "full"}

	for _, scenario := range scenarios {
		for _, os := range []string{"linux", "windows"} {
			name := fmt.Sprintf("%s/%s", scenario, os)
			t.Run(name, func(t *testing.T) {
				req := AgentDeployRequest{
					ManagerAddr: "10.0.0.1:8443",
					Scenario:    traps.TrapScenario(scenario),
					OSTarget:    os,
				}

				artifact, err := g.Generate(req)
				if err != nil {
					t.Fatalf("Generate failed: %v", err)
				}

				// 验证所有必需的产物字段存在
				if artifact.ConfigYAML == "" {
					t.Error("ConfigYAML should not be empty")
				}
				if artifact.CLICommand == "" {
					t.Error("CLICommand should not be empty")
				}
				if artifact.DeployScript == "" {
					t.Error("DeployScript should not be empty")
				}
				if artifact.VerifyHint == "" {
					t.Error("VerifyHint should not be empty")
				}
				if len(artifact.EnabledSvcs) == 0 {
					t.Error("EnabledSvcs should not be empty")
				}

				// 验证 OS 特定字段
				if os == "windows" {
					if artifact.InstallScriptPS == "" {
						t.Error("Windows should have InstallScriptPS")
					}
					if artifact.ServiceConfig == "" {
						t.Error("Windows should have ServiceConfig")
					}
				} else {
					if artifact.InstallScriptPS != "" {
						t.Error("Linux should not have InstallScriptPS")
					}
					if artifact.ServiceConfig != "" {
						t.Error("Linux should not have ServiceConfig")
					}
				}
			})
		}
	}
}
