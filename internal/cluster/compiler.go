// Package cluster Agent 编译引擎 (v0.17.2)
//
// 基于"目标机器零依赖"前提设计：
//   - 管理端完成交叉编译，生成独立可执行文件 (CGO_ENABLED=0, 静态链接)
//   - 所有配置文件、认证凭证、部署脚本自包含在同一个打包产物中
//   - 输出可直接复制执行的无依赖部署命令
//   - 目标机器仅需基础操作系统（Linux: bash + systemd, Windows: PowerShell），无需安装任何运行时
package cluster

import (
	"archive/tar"
	"archive/zip"
	"compress/gzip"
	"crypto/rand"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"fmt"
	"io"
	"math/big"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"
	"time"
)

// CompileRequest 编译请求
type CompileRequest struct {
	AgentDeployRequest
	GOARCH string `json:"goarch"` // amd64 | arm64, 默认 amd64
}

// CompileResult 编译产出物
type CompileResult struct {
	JobID       string          `json:"job_id"`
	Status      string          `json:"status"` // "compiling" | "complete" | "failed"
	Progress    int             `json:"progress"`
	Error       string          `json:"error,omitempty"`
	OSTarget    string          `json:"os_target"`
	GOARCH      string          `json:"goarch"`
	BinaryName  string          `json:"binary_name"`
	BinarySize  int64           `json:"binary_size"`
	PackageSize int64           `json:"package_size"`
	PackageName string          `json:"package_name"`
	PackagePath string          `json:"package_path"`
	Files       []CompileFile   `json:"files"`
	Commands    []DeployCommand `json:"commands"`
	Duration    float64         `json:"duration_sec"`
	StartedAt   time.Time       `json:"started_at"`
	FinishedAt  *time.Time      `json:"finished_at,omitempty"`
}

// CompileFile 编译产出文件
type CompileFile struct {
	Name        string `json:"name"`
	Description string `json:"description"`
	Path        string `json:"path"`
	Size        int64  `json:"size"`
}

// DeployCommand 部署命令步骤
type DeployCommand struct {
	Step        int    `json:"step"`
	Title       string `json:"title"`
	Command     string `json:"command"`
	Description string `json:"description,omitempty"`
}

// Compiler Agent 编译引擎
type Compiler struct {
	mu         sync.RWMutex
	projectDir string
	outputDir  string
	jobs       map[string]*CompileResult
}

// NewCompiler 创建编译引擎
func NewCompiler(projectDir string) *Compiler {
	return &Compiler{
		projectDir: projectDir,
		outputDir:  filepath.Join(projectDir, "data", "agents"),
		jobs:       make(map[string]*CompileResult),
	}
}

// Compile 异步交叉编译 Agent 二进制并打包
func (c *Compiler) Compile(req CompileRequest) (*CompileResult, error) {
	if req.OSTarget == "" {
		req.OSTarget = "linux"
	}
	if req.GOARCH == "" {
		req.GOARCH = "amd64"
	}

	jobID := fmt.Sprintf("agent-%d", time.Now().UnixNano())
	result := &CompileResult{
		JobID:     jobID,
		Status:    "compiling",
		Progress:  0,
		OSTarget:  req.OSTarget,
		GOARCH:    req.GOARCH,
		Files:     make([]CompileFile, 0),
		Commands:  make([]DeployCommand, 0),
		StartedAt: time.Now(),
	}

	c.mu.Lock()
	c.jobs[jobID] = result
	c.mu.Unlock()

	go c.doCompile(req, result)
	return result, nil
}

// GetJob 查询编译任务状态
func (c *Compiler) GetJob(jobID string) *CompileResult {
	c.mu.RLock()
	defer c.mu.RUnlock()
	return c.jobs[jobID]
}

// CleanJob 清理已完成任务的临时文件（保留打包产物）
func (c *Compiler) CleanJob(jobID string) {
	c.mu.Lock()
	defer c.mu.Unlock()
	// 保留 result 但不保留 build dir
	if _, ok := c.jobs[jobID]; ok {
		workDir := filepath.Join(c.outputDir, jobID)
		// 保留 .tar.gz/.zip 文件，删除其余中间产物
		entries, _ := os.ReadDir(workDir)
		for _, e := range entries {
			if e.IsDir() {
				continue
			}
			name := e.Name()
			if !strings.HasSuffix(name, ".tar.gz") && !strings.HasSuffix(name, ".zip") {
				os.Remove(filepath.Join(workDir, name))
			}
		}
	}
}

func (c *Compiler) doCompile(req CompileRequest, r *CompileResult) {
	defer func() {
		finishedAt := time.Now()
		r.FinishedAt = &finishedAt
		r.Duration = finishedAt.Sub(r.StartedAt).Seconds()
	}()

	// 创建工作目录
	workDir := filepath.Join(c.outputDir, r.JobID)
	if err := os.MkdirAll(workDir, 0755); err != nil {
		r.Status = "failed"
		r.Error = fmt.Sprintf("create work dir: %v", err)
		return
	}
	r.Progress = 5

	// Step 1: 确定目标平台和二进制名称
	goos := req.OSTarget
	goarch := req.GOARCH
	binaryName := "honeypot-agent"
	if goos == "windows" {
		binaryName = "honeypot-agent.exe"
	}
	r.BinaryName = binaryName

	// Step 2: 交叉编译 (Progress: 5 → 40)
	r.Progress = 10
	binaryPath := filepath.Join(workDir, binaryName)
	if err := c.crossCompile(goos, goarch, binaryPath); err != nil {
		r.Status = "failed"
		r.Error = fmt.Sprintf("cross-compile (%s/%s): %v", goos, goarch, err)
		return
	}
	r.Progress = 40

	// 记录二进制信息
	info, _ := os.Stat(binaryPath)
	if info != nil {
		r.BinarySize = info.Size()
	}
	r.Files = append(r.Files, CompileFile{
		Name: binaryName, Description: fmt.Sprintf("Agent 独立可执行文件 (%s/%s, CGO_ENABLED=0, 静态链接, 无外部依赖)", goos, goarch),
		Path: binaryPath, Size: r.BinarySize,
	})

	// Step 3: 生成 TLS 客户端证书 (用于 Agent 连接管理端认证)
	r.Progress = 50
	certPath := filepath.Join(workDir, "agent-cert.pem")
	keyPath := filepath.Join(workDir, "agent-key.pem")
	caCertPath := filepath.Join(workDir, "ca-cert.pem")
	if err := c.generateAgentTLS(req, certPath, keyPath, caCertPath); err != nil {
		// TLS 证书生成失败不阻塞编译，仅记录警告
		// 目标机器可后续通过管理端更新证书
		_ = err
		// 生成占位证书提示
		certHint := "# TLS 证书文件 — 请从管理端获取正式证书替换此文件\n"
		os.WriteFile(certPath, []byte(certHint), 0644)
		os.WriteFile(keyPath, []byte(certHint), 0644)
		caPath := filepath.Join(c.projectDir, "data", "cluster-ca.pem")
		if caData, err := os.ReadFile(caPath); err == nil {
			os.WriteFile(caCertPath, caData, 0644)
		} else {
			os.WriteFile(caCertPath, []byte(certHint), 0644)
		}
	}
	r.Progress = 55

	// Step 4: 生成 config.yaml
	configPath := filepath.Join(workDir, "config.yaml")
	configContent := c.buildAgentConfig(req, certPath, keyPath, caCertPath)
	if err := os.WriteFile(configPath, []byte(configContent), 0644); err != nil {
		r.Status = "failed"
		r.Error = fmt.Sprintf("write config: %v", err)
		return
	}
	r.Files = append(r.Files, CompileFile{
		Name: "config.yaml", Description: "Agent 运行配置文件 — 包含管理端地址、陷阱场景、蜜罐端口、TLS 证书路径",
		Path: configPath, Size: int64(len(configContent)),
	})
	r.Progress = 65

	// Step 5: 生成部署脚本和自启动配置
	if goos == "windows" {
		c.generateWindowsScripts(workDir, req.AgentDeployRequest, r)
	} else {
		c.generateLinuxScripts(workDir, req.AgentDeployRequest, r)
	}
	r.Progress = 80

	// Step 6: 打包
	packageName := fmt.Sprintf("honeypot-agent-%s-%s", goos, goarch)
	packagePath := filepath.Join(workDir, packageName)
	if goos == "windows" {
		packageName += ".zip"
		packagePath += ".zip"
		if err := c.packZip(workDir, packagePath); err != nil {
			r.Status = "failed"
			r.Error = fmt.Sprintf("pack zip: %v", err)
			return
		}
	} else {
		packageName += ".tar.gz"
		packagePath += ".tar.gz"
		if err := c.packTarGz(workDir, packagePath); err != nil {
			r.Status = "failed"
			r.Error = fmt.Sprintf("pack tar.gz: %v", err)
			return
		}
	}

	pkgInfo, _ := os.Stat(packagePath)
	if pkgInfo != nil {
		r.PackageSize = pkgInfo.Size()
	}
	r.PackageName = packageName
	r.PackagePath = packagePath
	r.Progress = 90

	// Step 7: 生成部署命令
	r.Commands = c.buildDeployCommands(req.AgentDeployRequest, binaryName, packageName, r.JobID)
	r.Progress = 100
	r.Status = "complete"
}

// crossCompile 执行交叉编译
func (c *Compiler) crossCompile(goos, goarch, output string) error {
	cmd := exec.Command("go", "build",
		"-ldflags=-s -w",
		"-o", output,
		"./cmd/honeypot/",
	)
	cmd.Dir = c.projectDir
	cmd.Env = append(os.Environ(),
		"GOOS="+goos,
		"GOARCH="+goarch,
		"CGO_ENABLED=0",
	)
	output_, err := cmd.CombinedOutput()
	if err != nil {
		return fmt.Errorf("%v: %s", err, string(output_))
	}
	return nil
}

// generateAgentTLS 生成 Agent 端 TLS 客户端证书（由管理端 CA 签发）
func (c *Compiler) generateAgentTLS(req CompileRequest, certPath, keyPath, caCertPath string) error {
	// 生成 RSA 私钥
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return fmt.Errorf("generate key: %w", err)
	}

	// 写入私钥文件
	keyPEM := pem.EncodeToMemory(&pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(key)})
	if err := os.WriteFile(keyPath, keyPEM, 0600); err != nil {
		return fmt.Errorf("write key: %w", err)
	}

	nodeName := req.NodeName
	if nodeName == "" {
		nodeName = "agent-node"
	}

	// 生成证书模板
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(time.Now().UnixNano()),
		Subject: pkix.Name{
			CommonName:   nodeName,
			Organization: []string{"Laji-HoneyPot"},
		},
		NotBefore: time.Now(),
		NotAfter:  time.Now().Add(365 * 24 * time.Hour), // 1 年有效期
		KeyUsage:  x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment,
		ExtKeyUsage: []x509.ExtKeyUsage{
			x509.ExtKeyUsageClientAuth,
		},
		IPAddresses: []net.IP{net.ParseIP("127.0.0.1")},
	}

	// 尝试加载管理端 CA 证书和私钥来签发 Agent 证书
	caCertPEM, err := os.ReadFile(filepath.Join(c.projectDir, "data", "cluster-ca.pem"))
	if err != nil {
		// 无 CA，生成自签名证书（Agent 端使用 TLSInsecure 连接）
		certDER, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
		if err != nil {
			return fmt.Errorf("create self-signed cert: %w", err)
		}
		certPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: certDER})
		if err := os.WriteFile(certPath, certPEM, 0644); err != nil {
			return fmt.Errorf("write cert: %w", err)
		}
		// 写入 CA 占位
		os.WriteFile(caCertPath, []byte("# CA 证书 — 请从管理端获取正式 CA 证书替换此文件\n"), 0644)
		return nil
	}

	caKeyPEM, err := os.ReadFile(filepath.Join(c.projectDir, "data", "cluster-ca-key.pem"))
	if err != nil {
		return fmt.Errorf("read CA key: %w", err)
	}

	caCertBlock, _ := pem.Decode(caCertPEM)
	if caCertBlock == nil {
		return fmt.Errorf("decode CA cert PEM failed")
	}
	caCert, err := x509.ParseCertificate(caCertBlock.Bytes)
	if err != nil {
		return fmt.Errorf("parse CA cert: %w", err)
	}

	caKeyBlock, _ := pem.Decode(caKeyPEM)
	if caKeyBlock == nil {
		return fmt.Errorf("decode CA key PEM failed")
	}
	caKey, err := x509.ParsePKCS1PrivateKey(caKeyBlock.Bytes)
	if err != nil {
		return fmt.Errorf("parse CA key: %w", err)
	}

	// 用 CA 签发 Agent 证书
	certDER, err := x509.CreateCertificate(rand.Reader, tmpl, caCert, &key.PublicKey, caKey)
	if err != nil {
		return fmt.Errorf("sign agent cert: %w", err)
	}

	certPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: certDER})
	if err := os.WriteFile(certPath, certPEM, 0644); err != nil {
		return fmt.Errorf("write cert: %w", err)
	}

	// 复制 CA 证书到工作目录
	os.WriteFile(caCertPath, caCertPEM, 0644)

	return nil
}

// generateLinuxScripts 生成 Linux 部署脚本和 systemd 服务文件
func (c *Compiler) generateLinuxScripts(workDir string, req AgentDeployRequest, r *CompileResult) {
	tlsFlag := ""
	if req.TLSInsecure {
		tlsFlag = " --tls-insecure"
	}

	nodeName := req.NodeName
	if nodeName == "" {
		nodeName = "agent-node"
	}

	managerAddr := req.ManagerAddr

	deployScript := fmt.Sprintf(`#!/bin/bash
# ============================================================
# Laji-HoneyPot Agent 零依赖部署脚本 (v0.17.2)
# 适用于: Linux (amd64/arm64)
# 目标机器要求: 仅需 bash + systemd (Linux 标准组件, 无需额外安装)
# 管理端: %s
# 节点名: %s
# ============================================================
set -e

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
INSTALL_DIR="/opt/honeypot"
DATA_DIR="$INSTALL_DIR/data"

echo ""
echo "  Laji-HoneyPot Agent 部署中..."
echo "  管理端: %s"
echo "  节点名: %s"
echo ""

echo "[1/5] 创建安装目录..."
mkdir -p "$INSTALL_DIR" "$DATA_DIR"

echo "[2/5] 安装可执行文件..."
cp "$SCRIPT_DIR/honeypot-agent" "$INSTALL_DIR/"
chmod +x "$INSTALL_DIR/honeypot-agent"

echo "[3/5] 安装配置文件..."
cp "$SCRIPT_DIR/config.yaml" "$INSTALL_DIR/"
# 安装 TLS 证书（如存在）
if [ -f "$SCRIPT_DIR/agent-cert.pem" ]; then
    cp "$SCRIPT_DIR/agent-cert.pem" "$INSTALL_DIR/"
    cp "$SCRIPT_DIR/agent-key.pem" "$INSTALL_DIR/"
    cp "$SCRIPT_DIR/ca-cert.pem" "$INSTALL_DIR/"
    chmod 600 "$INSTALL_DIR/agent-key.pem"
fi

echo "[4/5] 注册 systemd 服务 (开机自启)..."
cat > /etc/systemd/system/honeypot-agent.service << 'SVC_EOF'
[Unit]
Description=Laji-HoneyPot Agent (%s)
After=network.target
Documentation=https://github.com/Laji-HoneyPot/honeypot

[Service]
Type=simple
User=root
WorkingDirectory=%s
ExecStart=%s/honeypot-agent -config %s/config.yaml%s
Restart=always
RestartSec=10
LimitNOFILE=65536
StandardOutput=append:%s/agent.log
StandardError=append:%s/agent.log

[Install]
WantedBy=multi-user.target
SVC_EOF

systemctl daemon-reload
systemctl enable honeypot-agent

echo "[5/5] 启动 Agent..."
systemctl start honeypot-agent
sleep 2

echo ""
echo "============================================"
echo "  部署完成!"
echo "============================================"
echo "  服务状态: systemctl status honeypot-agent"
echo "  查看日志: journalctl -u honeypot-agent -f"
echo "  管理端:   %s"
echo "  节点名:   %s"
echo "============================================"
`, managerAddr, nodeName, managerAddr, nodeName,
		nodeName,
		"$INSTALL_DIR", "$INSTALL_DIR", "$INSTALL_DIR", tlsFlag,
		"$INSTALL_DIR", "$INSTALL_DIR",
		managerAddr, nodeName)

	deployPath := filepath.Join(workDir, "deploy.sh")
	os.WriteFile(deployPath, []byte(deployScript), 0755)
	r.Files = append(r.Files, CompileFile{
		Name: "deploy.sh", Description: "Linux 零依赖部署脚本 — 含 systemd 自启动配置, 一键完成安装",
		Path: deployPath, Size: int64(len(deployScript)),
	})
}

// generateWindowsScripts 生成 Windows 部署脚本
func (c *Compiler) generateWindowsScripts(workDir string, req AgentDeployRequest, r *CompileResult) {
	tlsFlag := ""
	if req.TLSInsecure {
		tlsFlag = " --tls-insecure"
	}

	nodeName := req.NodeName
	if nodeName == "" {
		nodeName = "WIN-AGENT"
	}

	managerAddr := req.ManagerAddr
	installDir := `$env:ProgramFiles\Honeypot`

	deployScript := fmt.Sprintf(`<#
.SYNOPSIS
    Laji-HoneyPot Agent 零依赖部署脚本 (v0.17.2)
    Windows (amd64), 无需预装任何运行环境
    要求: PowerShell 5.1+ (Windows 自带)
#>
$ErrorActionPreference = "Stop"
$Host.UI.RawUI.WindowTitle = "Laji-HoneyPot Agent 部署"

$InstallDir = "%s"
$BinPath = "$InstallDir\honeypot-agent.exe"
$CfgPath = "$InstallDir\config.yaml"
$DataDir = "$InstallDir\data"
$ScriptDir = Split-Path -Parent $MyInvocation.MyCommand.Path

Write-Host ""
Write-Host "  Laji-HoneyPot Agent 部署中..." -ForegroundColor Cyan
Write-Host "  节点: %s | 管理端: %s" -ForegroundColor Green
Write-Host ""

Write-Host "[1/5] 创建安装目录..."
New-Item -ItemType Directory -Force -Path $InstallDir | Out-Null
New-Item -ItemType Directory -Force -Path $DataDir | Out-Null

Write-Host "[2/5] 安装可执行文件..."
Copy-Item -Force "$ScriptDir\honeypot-agent.exe" $BinPath

Write-Host "[3/5] 安装配置文件..."
Copy-Item -Force "$ScriptDir\config.yaml" $CfgPath
# 安装 TLS 证书（如存在）
if (Test-Path "$ScriptDir\agent-cert.pem") {
    Copy-Item -Force "$ScriptDir\agent-cert.pem" $InstallDir
    Copy-Item -Force "$ScriptDir\agent-key.pem" $InstallDir
    Copy-Item -Force "$ScriptDir\ca-cert.pem" $InstallDir
}

Write-Host "[4/5] 注册 Windows 服务 (开机自启)..."
$svc = Get-Service -Name HoneypotAgent -ErrorAction SilentlyContinue
if ($svc) {
    Stop-Service HoneypotAgent -Force -ErrorAction SilentlyContinue
    sc.exe delete HoneypotAgent
    Start-Sleep -Seconds 2
}
sc.exe create HoneypotAgent binPath= "$BinPath -config $CfgPath%s" start= auto displayname= "Laji-HoneyPot Agent (%s)" 2>$null
if ($LASTEXITCODE -ne 0) {
    sc.exe config HoneypotAgent binPath= "$BinPath -config $CfgPath%s" start= auto
}

# 配置服务失败自动重启
sc.exe failure HoneypotAgent reset= 86400 actions= restart/10000/restart/10000/restart/10000 2>$null

Write-Host "[5/5] 启动 Agent..."
sc.exe start HoneypotAgent
Start-Sleep -Seconds 3

$svcStatus = sc.exe query HoneypotAgent 2>$null
Write-Host ""
Write-Host "============================================" -ForegroundColor Green
Write-Host "  部署完成!" -ForegroundColor Green
Write-Host "============================================" -ForegroundColor Green
Write-Host "  服务状态: sc.exe query HoneypotAgent"
Write-Host "  日志目录: $DataDir"
Write-Host "  管理端:   %s"
Write-Host "============================================" -ForegroundColor Green
`, installDir, nodeName, managerAddr, tlsFlag, nodeName, tlsFlag, managerAddr)

	deployPath := filepath.Join(workDir, "deploy.ps1")
	os.WriteFile(deployPath, []byte(deployScript), 0644)
	r.Files = append(r.Files, CompileFile{
		Name: "deploy.ps1", Description: "Windows 零依赖部署脚本 — 含 sc.exe 服务自启动, 一键完成安装",
		Path: deployPath, Size: int64(len(deployScript)),
	})
}

// buildAgentConfig 生成 agent config.yaml（集成 TLS 证书路径）
func (c *Compiler) buildAgentConfig(req CompileRequest, certPath, keyPath, caCertPath string) string {
	tlsInsecure := "false"
	if req.TLSInsecure {
		tlsInsecure = "true"
	}

	dataDir := "./data"
	certLine := ""
	if req.OSTarget == "windows" {
		dataDir = `C:\Program Files\Honeypot\data`
	}

	// 检查证书文件是否存在，有则配置证书路径
	if _, err := os.Stat(certPath); err == nil {
		if req.OSTarget == "windows" {
			certLine = fmt.Sprintf(`  cert_file: "C:\\Program Files\\Honeypot\\agent-cert.pem"
  key_file: "C:\\Program Files\\Honeypot\\agent-key.pem"
  ca_file: "C:\\Program Files\\Honeypot\\ca-cert.pem"`)
		} else {
			certLine = `  cert_file: "/opt/honeypot/agent-cert.pem"
  key_file: "/opt/honeypot/agent-key.pem"
  ca_file: "/opt/honeypot/ca-cert.pem"`
		}
	} else {
		certLine = `  cert_file: ""
  key_file: ""
  ca_file: ""`
	}

	customServices := ""
	if len(req.CustomServices) > 0 {
		customServices = "\n  custom_services:\n"
		for _, s := range req.CustomServices {
			customServices += fmt.Sprintf("    - %s\n", s)
		}
	}

	scenario := req.Scenario
	if scenario == "" || scenario == "full" {
		scenario = "full"
	}

	nodeName := req.NodeName
	if nodeName == "" {
		nodeName = "agent-node"
	}

	return fmt.Sprintf(`# Laji-HoneyPot Agent Configuration (v0.17.2)
# 管理端编译生成 — 所有配置自包含，目标机器无需额外配置
# 节点名: %s
# 目标平台: %s/%s

plugins:
  honeypot-engine:
    enabled: true
    trap_scenario: "%s"%s
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
%s

api:
  addr: ":8080"
  log_level: "info"

data_dir: "%s"
`, nodeName, req.OSTarget, req.GOARCH, scenario, customServices, req.ManagerAddr, tlsInsecure, certLine, dataDir)
}

// buildDeployCommands 生成完整的无依赖部署命令列表
func (c *Compiler) buildDeployCommands(req AgentDeployRequest, binaryName, packageName, jobID string) []DeployCommand {
	// 下载地址使用 API 服务器地址（而非集群 ManagerAddr 的 8443 端口）
	downloadHost := req.APIAddr
	if downloadHost == "" {
		downloadHost = req.ManagerAddr // 兜底：用 ManagerAddr
	}

	if req.OSTarget == "windows" {
		return []DeployCommand{
			{
				Step: 1, Title: "下载部署包",
				Command: fmt.Sprintf(
					`curl -o %s http://%s/api/cluster/agent/compile/download?job_id=%s`,
					packageName, downloadHost, jobID),
				Description: "从管理端下载编译好的部署包（或通过 Web UI 下载按钮直接下载）",
			},
			{
				Step: 2, Title: "解压部署包",
				Command: fmt.Sprintf(
					`Expand-Archive -Path %s -DestinationPath .\honeypot-agent\ -Force`, packageName),
				Description: "解压到当前目录",
			},
			{
				Step: 3, Title: "以管理员权限运行部署脚本",
				Command:     `powershell -ExecutionPolicy Bypass -File .\honeypot-agent\deploy.ps1`,
				Description: "部署脚本自动完成: 安装文件 → 注册 Windows 服务 → 配置开机自启 → 启动 Agent",
			},
			{
				Step: 4, Title: "验证 Agent 运行状态",
				Command:     `sc.exe query HoneypotAgent`,
				Description: "确认服务状态为 RUNNING",
			},
		}
	}

	return []DeployCommand{
		{
			Step: 1, Title: "下载部署包",
			Command: fmt.Sprintf(
				`curl -o %s http://%s/api/cluster/agent/compile/download?job_id=%s`,
				packageName, downloadHost, jobID),
			Description: "从管理端下载编译好的部署包（也可通过 Web UI 下载按钮直接下载）",
		},
		{
			Step: 2, Title: "解压部署包",
			Command:     fmt.Sprintf(`mkdir -p ./honeypot-agent/ && tar xzf %s -C ./honeypot-agent/`, packageName),
			Description: "解压到 ./honeypot-agent/ 目录",
		},
		{
			Step: 3, Title: "以 root 权限运行部署脚本",
			Command:     `sudo bash ./honeypot-agent/deploy.sh`,
			Description: "部署脚本自动完成: 安装文件 → 注册 systemd 服务 → 配置开机自启 → 启动 Agent。目标机器仅需 bash 和 systemd（Linux 标准组件），无需任何额外依赖。",
		},
		{
			Step: 4, Title: "验证 Agent 运行状态",
			Command: `systemctl status honeypot-agent`,
		},
		{
			Step: 5, Title: "查看实时日志",
			Command: `journalctl -u honeypot-agent -f`,
		},
	}
}

// packTarGz 打包为 tar.gz
func (c *Compiler) packTarGz(srcDir, outputPath string) error {
	f, err := os.Create(outputPath)
	if err != nil {
		return err
	}
	defer f.Close()

	gw := gzip.NewWriter(f)
	defer gw.Close()

	tw := tar.NewWriter(gw)
	defer tw.Close()

	return filepath.Walk(srcDir, func(path string, info os.FileInfo, err error) error {
		if err != nil {
			return err
		}
		if path == outputPath || info.IsDir() {
			return nil
		}

		relPath, _ := filepath.Rel(srcDir, path)
		header, err := tar.FileInfoHeader(info, "")
		if err != nil {
			return err
		}
		header.Name = relPath
		if err := tw.WriteHeader(header); err != nil {
			return err
		}

		file, err := os.Open(path)
		if err != nil {
			return err
		}
		_, copyErr := io.Copy(tw, file)
		file.Close() // 立即关闭, 避免 Walk 闭包内 defer 堆积 FD
		return copyErr
	})
}

// packZip 打包为 zip
func (c *Compiler) packZip(srcDir, outputPath string) error {
	f, err := os.Create(outputPath)
	if err != nil {
		return err
	}
	defer f.Close()

	zw := zip.NewWriter(f)
	defer zw.Close()

	return filepath.Walk(srcDir, func(path string, info os.FileInfo, err error) error {
		if err != nil {
			return err
		}
		if path == outputPath || info.IsDir() {
			return nil
		}

		relPath, _ := filepath.Rel(srcDir, path)
		relPath = strings.ReplaceAll(relPath, "/", "\\")

		w, err := zw.Create(relPath)
		if err != nil {
			return err
		}

		file, err := os.Open(path)
		if err != nil {
			return err
		}
		_, copyErr := io.Copy(w, file)
		file.Close() // 立即关闭, 避免 Walk 闭包内 defer 堆积 FD
		return copyErr
	})
}

// tls 导入使用
var _ = tls.VersionTLS13
