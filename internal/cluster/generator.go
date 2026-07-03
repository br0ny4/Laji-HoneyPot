// Package cluster Agent 生成引擎
//
// 在 Management Node 平台上，用户可通过前端选择目标部署场景和服务模块，
// 引擎自动生成标准化的 Agent 配置文件与部署命令，支持：
//   - 自动填写 Management Node 地址到 agent 配置模板
//   - 支持用户自主选配 agent 功能模块（场景 + 服务）
//   - 生成一键部署命令与完整部署脚本
//   - Agent 部署后自动完成注册校验
package cluster

import (
	"fmt"
	"strings"

	"github.com/Laji-HoneyPot/honeypot/internal/honeypot/traps"
)

// AgentDeployRequest 前端提交的 Agent 部署配置请求
type AgentDeployRequest struct {
	ManagerAddr    string             `json:"manager_addr"`    // 管理端地址 (必填)
	Scenario       traps.TrapScenario `json:"scenario"`        // 陷阱场景选配
	CustomServices []string           `json:"custom_services"` // 自定义服务 (scenario=custom 时生效)
	TLSInsecure    bool               `json:"tls_insecure"`    // 跳过 TLS 验证 (仅测试用)
	BinarySource   string             `json:"binary_source"`   // 二进制下载来源: release | build | url
	CustomURL      string             `json:"custom_url"`      // 自定义下载 URL (binary_source=url 时生效)
	NodeName       string             `json:"node_name"`       // 节点显示名称 (可选)
	OSTarget       string             `json:"os_target"`       // 目标操作系统: "linux" 或 "windows", 默认 "linux"
}

// AgentDeployArtifact Agent 部署产出物
type AgentDeployArtifact struct {
	ManagerAddr     string             `json:"manager_addr"`      // 管理端地址
	Scenario        traps.TrapScenario `json:"scenario"`          // 陷阱场景
	EnabledSvcs     []string           `json:"enabled_svcs"`      // 启用的服务列表
	ConfigYAML      string             `json:"config_yaml"`       // 生成的 config.yaml 内容
	CLICommand      string             `json:"cli_command"`       // 一键命令行（适用于目标主机直接执行）
	DeployScript    string             `json:"deploy_script"`     // 完整部署脚本
	DockerCommand   string             `json:"docker_command"`    // Docker 部署命令 (可选)
	VerifyHint      string             `json:"verify_hint"`       // 注册校验提示
	OSTarget        string             `json:"os_target"`         // 目标操作系统
	InstallScriptPS string             `json:"install_script_ps"` // Windows PowerShell 安装脚本
	ServiceConfig   string             `json:"service_config"`    // 平台特定的服务配置
	BinaryName      string             `json:"binary_name"`       // 平台特定的二进制文件名
}

// BinarySource 二进制获取方式
type BinarySource string

const (
	SourceRelease BinarySource = "release" // 从 GitHub Releases 下载预编译二进制
	SourceBuild   BinarySource = "build"   // 从源码编译 (go build)
	SourceURL     BinarySource = "url"     // 自定义下载 URL
)

// Generator Agent 生成引擎
type Generator struct {
	Version    string // 当前版本号
	RepoURL    string // 源码仓库地址 (用于 go build / release download)
	ReleaseURL string // Release 下载基础 URL
}

// NewGenerator 创建 Agent 生成引擎
func NewGenerator(version string) *Generator {
	return &Generator{
		Version: version,
		RepoURL: "https://github.com/Laji-HoneyPot/honeypot.git",
	}
}

// getBinaryName 根据目标平台返回对应的二进制文件名
func (g *Generator) getBinaryName(req AgentDeployRequest) string {
	if req.OSTarget == "windows" {
		return "honeypot-windows-amd64.exe"
	}
	return "honeypot-linux-amd64"
}

// Generate 根据请求生成 Agent 部署产出物
func (g *Generator) Generate(req AgentDeployRequest) (*AgentDeployArtifact, error) {
	if req.ManagerAddr == "" {
		return nil, fmt.Errorf("manager_addr is required")
	}

	// 默认 OS 目标为 linux
	if req.OSTarget == "" {
		req.OSTarget = "linux"
	}

	// 解析陷阱注册中心（复用以确定启用哪些服务）
	scenario := traps.ParseScenario(string(req.Scenario))
	if scenario == traps.ScenarioFull {
		scenario = req.Scenario // 保留用户输入的场景名
	}
	if scenario == "" || scenario == "full" {
		scenario = traps.ScenarioFull
	}

	reg := traps.New(scenario, req.CustomServices)
	enabledSvcs := reg.EnabledServices()

	// 生成 config.yaml
	configYAML := g.buildConfig(req, enabledSvcs)

	// 生成命令行
	cliCommand := g.buildCLICommand(req, enabledSvcs)

	// 生成部署脚本
	deployScript := g.buildDeployScript(req, enabledSvcs)

	// 生成 Docker 命令
	dockerCommand := g.buildDockerCommand(req, enabledSvcs)

	// 平台特定的安装脚本和服务配置
	binaryName := g.getBinaryName(req)
	installScriptPS := ""
	serviceConfig := ""
	if req.OSTarget == "windows" {
		installScriptPS = deployScript // PowerShell 脚本就是安装脚本
		serviceConfig = g.buildWindowsServiceConfig(req)
	}

	return &AgentDeployArtifact{
		ManagerAddr:     req.ManagerAddr,
		Scenario:        scenario,
		EnabledSvcs:     enabledSvcs,
		ConfigYAML:      configYAML,
		CLICommand:      cliCommand,
		DeployScript:    deployScript,
		DockerCommand:   dockerCommand,
		VerifyHint:      g.buildVerifyHint(req),
		OSTarget:        req.OSTarget,
		InstallScriptPS: installScriptPS,
		ServiceConfig:   serviceConfig,
		BinaryName:      binaryName,
	}, nil
}

// buildConfig 生成 agent 的 config.yaml
func (g *Generator) buildConfig(req AgentDeployRequest, services []string) string {
	tlsInsecure := "false"
	if req.TLSInsecure {
		tlsInsecure = "true"
	}

	customServices := ""
	if len(req.CustomServices) > 0 {
		customServices = "\n  custom_services:\n"
		for _, s := range req.CustomServices {
			customServices += fmt.Sprintf("    - %s\n", s)
		}
	}

	dataDir := "./data"
	if req.OSTarget == "windows" {
		dataDir = `C:\Program Files\Honeypot\data`
	}

	return fmt.Sprintf(`# Laji-HoneyPot Agent Configuration
# Generated by Management Node: %s
# Generated at: auto
# Agent Node: %s

plugins:
  honeypot-engine:
    enabled: true
    trap_scenario: "%s"%s
    # 以下端口按需调整，设为 0 禁用
    # Windows 上端口冲突时建议修改默认值
    http_port: 8081
    mysql_port: 3306
    redis_port: 6379
    ssh_port: 2222
    ftp_port: 2121
    ldap_port: 3890
    dns_port: 5354
    smb_port: 4450
    rdp_port: 33890

cluster:
  enabled: true
  role: "node"
  manager_addr: "%s"
  tls_insecure: %s
  cert_file: ""
  key_file: ""
  ca_file: ""

api:
  addr: ":8080"
  api_key: "YOUR_AGENT_API_KEY"
  log_level: "info"

data_dir: "%s"
`, req.ManagerAddr, req.NodeName, req.Scenario, customServices, req.ManagerAddr, tlsInsecure, dataDir)
}

// buildCLICommand 生成一键部署命令行
func (g *Generator) buildCLICommand(req AgentDeployRequest, services []string) string {
	if req.OSTarget == "windows" {
		return g.buildCLICommandWindows(req, services)
	}
	switch BinarySource(req.BinarySource) {
	case SourceBuild:
		return g.buildSourceCommand(req, services)
	case SourceURL:
		if req.CustomURL != "" {
			return g.buildURLCommand(req, services)
		}
		return g.buildReleaseCommand(req, services)
	default: // release
		return g.buildReleaseCommand(req, services)
	}
}

// buildReleaseCommand 从 GitHub Release 下载二进制的一键命令
func (g *Generator) buildReleaseCommand(req AgentDeployRequest, services []string) string {
	tlsFlag := ""
	if req.TLSInsecure {
		tlsFlag = " --tls-insecure"
	}

	binaryName := g.getBinaryName(req)

	return fmt.Sprintf(
		`curl -sSL %s/releases/latest/download/%s -o honeypot && chmod +x honeypot && mkdir -p data && cat > config.yaml <<'HPEOF'
%s
HPEOF
./honeypot%s`,
		g.RepoURL, binaryName, g.buildConfig(req, services), tlsFlag,
	)
}

// buildSourceCommand 从源码编译的一键命令
func (g *Generator) buildSourceCommand(req AgentDeployRequest, services []string) string {
	return fmt.Sprintf(
		`git clone %s /tmp/honeypot-agent && cd /tmp/honeypot-agent && go build -o /usr/local/bin/honeypot ./cmd/honeypot/ && mkdir -p /opt/honeypot/data && cat > /opt/honeypot/config.yaml <<'HPEOF'
%s
HPEOF
cd /opt/honeypot && /usr/local/bin/honeypot`,
		g.RepoURL, g.buildConfig(req, services),
	)
}

// buildURLCommand 从自定义 URL 下载
func (g *Generator) buildURLCommand(req AgentDeployRequest, services []string) string {
	return fmt.Sprintf(
		`curl -sSL %s -o honeypot && chmod +x honeypot && mkdir -p data && cat > config.yaml <<'HPEOF'
%s
HPEOF
./honeypot`,
		req.CustomURL, g.buildConfig(req, services),
	)
}

// buildDeployScript 生成完整部署脚本
func (g *Generator) buildDeployScript(req AgentDeployRequest, services []string) string {
	if req.OSTarget == "windows" {
		return g.buildDeployScriptWindows(req, services)
	}

	tlsFlag := ""
	if req.TLSInsecure {
		tlsFlag = " --tls-insecure"
	}

	svcList := strings.Join(services, ", ")
	binaryName := g.getBinaryName(req)

	return fmt.Sprintf(`#!/bin/bash
# ==========================================
# Laji-HoneyPot Agent 自动部署脚本
# 管理端: %s
# 启用服务: %s
# 陷阱场景: %s
# ==========================================
set -e

INSTALL_DIR="/opt/honeypot"
BIN_PATH="/usr/local/bin/honeypot"
DATA_DIR="$INSTALL_DIR/data"

echo "[1/4] 创建目录..."
sudo mkdir -p $INSTALL_DIR $DATA_DIR

echo "[2/4] 下载二进制..."
curl -sSL %s/releases/latest/download/%s -o /tmp/honeypot
sudo mv /tmp/honeypot $BIN_PATH
sudo chmod +x $BIN_PATH

echo "[3/4] 写入配置..."
sudo tee $INSTALL_DIR/config.yaml > /dev/null <<'HPEOF'
%s
HPEOF

echo "[4/4] 启动 Agent..."
cd $INSTALL_DIR
if command -v systemctl &> /dev/null; then
  # systemd 服务
  sudo tee /etc/systemd/system/honeypot-agent.service > /dev/null <<'SVCEOF'
[Unit]
Description=Laji-HoneyPot Agent
After=network.target

[Service]
Type=simple
User=nobody
WorkingDirectory=/opt/honeypot
ExecStart=/usr/local/bin/honeypot%s
Restart=always
RestartSec=10

[Install]
WantedBy=multi-user.target
SVCEOF
  sudo systemctl daemon-reload
  sudo systemctl enable honeypot-agent
  sudo systemctl start honeypot-agent
  echo "Agent 已通过 systemd 启动 | systemctl status honeypot-agent"
else
  # 前台运行
  nohup $BIN_PATH%s > $INSTALL_DIR/agent.log 2>&1 &
  echo "Agent 已后台启动 (PID: $!)"
fi

echo ""
echo "=== 部署完成 ==="
echo "日志: $INSTALL_DIR/agent.log"
echo "管理端: %s"
echo "启用服务: %s"
`, req.ManagerAddr, svcList, req.Scenario, g.RepoURL, binaryName, g.buildConfig(req, services),
		tlsFlag, tlsFlag, req.ManagerAddr, svcList)
}

// buildDockerCommand 生成 Docker 部署命令
func (g *Generator) buildDockerCommand(req AgentDeployRequest, services []string) string {
	tlsInsecure := "false"
	if req.TLSInsecure {
		tlsInsecure = "true"
	}
	return fmt.Sprintf(
		`docker run -d \
  --name honeypot-agent \
  -p 8080:8080 -p 8081:8081 -p 2222:2222 \
  -e MANAGER_ADDR=%s \
  -e TRAP_SCENARIO=%s \
  -e TLS_INSECURE=%s \
  -v $PWD/data:/app/data \
  ghcr.io/laji-honeypot/honeypot:%s`,
		req.ManagerAddr, req.Scenario, tlsInsecure, g.Version,
	)
}

// buildVerifyHint 生成注册校验提示
func (g *Generator) buildVerifyHint(req AgentDeployRequest) string {
	if req.OSTarget == "windows" {
		return fmt.Sprintf(
			`Agent 部署后请按以下步骤验证注册：
1. 在 Management Node 前端"集群管理"面板确认节点已上线
2. 检查 Windows 服务状态：sc.exe query HoneypotAgent
3. 查看 Agent 日志确认无连接错误：Get-Content "C:\Program Files\Honeypot\data\honeypot.log" -Tail 20
4. 用 PowerShell 测试 Agent API：Invoke-WebRequest http://<agent-ip>:8080/healthz
5. 确认心跳正常：管理端集群面板中节点状态应为"在线"，LastSeen 持续更新
`)
	}
	return fmt.Sprintf(
		`Agent 部署后请按以下步骤验证注册：
1. 在 Management Node 前端"集群管理"面板确认节点已上线
2. 查看 Agent 日志确认无连接错误：tail -f data/honeypot.log
3. 用 curl 测试 Agent API：curl http://<agent-ip>:8080/healthz
4. 确认心跳正常：管理端集群面板中节点状态应为"在线"，LastSeen 持续更新
`)
}

// buildCLICommandWindows 生成 Windows PowerShell 一键部署命令行
func (g *Generator) buildCLICommandWindows(req AgentDeployRequest, services []string) string {
	binaryName := g.getBinaryName(req)
	configYAML := g.buildConfig(req, services)
	// 转义 PowerShell 字符串中的特殊字符
	configEscaped := strings.ReplaceAll(configYAML, "`", "``")
	configEscaped = strings.ReplaceAll(configEscaped, "\"", "`\"")
	configEscaped = strings.ReplaceAll(configEscaped, "$", "`$")

	return fmt.Sprintf(
		`Invoke-WebRequest -Uri "%s/releases/latest/download/%s" -OutFile honeypot.exe; New-Item -ItemType Directory -Force -Path data | Out-Null; @"
%s
"@ | Out-File -Encoding utf8 config.yaml; .\honeypot.exe`,
		g.RepoURL, binaryName, configEscaped,
	)
}

// buildDeployScriptWindows 生成 Windows PowerShell 完整部署脚本
func (g *Generator) buildDeployScriptWindows(req AgentDeployRequest, services []string) string {
	tlsFlag := ""
	if req.TLSInsecure {
		tlsFlag = " --tls-insecure"
	}

	binaryName := g.getBinaryName(req)
	svcList := strings.Join(services, ", ")
	configYAML := g.buildConfig(req, services)

	return fmt.Sprintf(`# ==========================================
# Laji-HoneyPot Agent Windows 部署脚本
# 管理端: %s
# 启用服务: %s
# 陷阱场景: %s
# 需要以管理员权限运行 PowerShell
# ==========================================

$ErrorActionPreference = "Stop"

$InstallDir = "C:\Program Files\Honeypot"
$BinPath = "$InstallDir\honeypot.exe"
$DataDir = "$InstallDir\data"
$ConfigPath = "$InstallDir\config.yaml"

Write-Host "[1/4] 创建目录..."
New-Item -ItemType Directory -Force -Path $InstallDir | Out-Null
New-Item -ItemType Directory -Force -Path $DataDir | Out-Null

Write-Host "[2/4] 下载二进制..."
Invoke-WebRequest -Uri "%s/releases/latest/download/%s" -OutFile $BinPath

Write-Host "[3/4] 写入配置..."
@"
%s
"@ | Out-File -Encoding utf8 $ConfigPath

Write-Host "[4/4] 注册并启动 Windows 服务..."
sc.exe create HoneypotAgent binPath= "$BinPath -config $ConfigPath%s" start= auto displayname= "Laji-HoneyPot Agent"
sc.exe start HoneypotAgent

Write-Host ""
Write-Host "=== 部署完成 ==="
Write-Host "服务: HoneypotAgent"
Write-Host "日志: $DataDir\honeypot.log"
Write-Host "管理端: %s"
Write-Host "启用服务: %s"
Write-Host ""
Write-Host "验证命令: sc.exe query HoneypotAgent"
`, req.ManagerAddr, svcList, req.Scenario, g.RepoURL, binaryName, configYAML, tlsFlag, req.ManagerAddr, svcList)
}

// buildWindowsServiceConfig 生成 Windows 服务注册的 sc.exe 命令
func (g *Generator) buildWindowsServiceConfig(req AgentDeployRequest) string {
	tlsFlag := ""
	if req.TLSInsecure {
		tlsFlag = " --tls-insecure"
	}

	return fmt.Sprintf(
		`sc.exe create HoneypotAgent binPath= "C:\Program Files\Honeypot\honeypot.exe -config C:\Program Files\Honeypot\config.yaml%s" start= auto displayname= "Laji-HoneyPot Agent"
sc.exe start HoneypotAgent`,
		tlsFlag,
	)
}
