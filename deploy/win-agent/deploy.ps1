<#
.SYNOPSIS
    Laji-HoneyPot Windows Agent v0.17.1 部署脚本
.DESCRIPTION
    Windows 11 上部署 Agent 蜜罐节点。
    支持两种模式:
      1. 一键拉取: .\deploy.ps1 -MgmtUrl "http://MANAGER_IP:8080"
         (自动从管理端下载配置包+二进制, 完成部署并启动)
      2. 手动部署: .\deploy.ps1
         (本地已有 honeypot-agent.exe 和 config.yaml)
.NOTES
    必须以管理员身份运行 PowerShell
.PARAMETER MgmtUrl
    管理端 URL, 可选。指定后自动从管理端拉取部署包
.EXAMPLE
    # 一键拉取部署
    .\deploy.ps1 -MgmtUrl "http://10.0.0.1:8080"
.EXAMPLE
    # 手动部署
    .\deploy.ps1
#>

param(
    [string]$MgmtUrl = ""
)

$ErrorActionPreference = "Stop"
$Host.UI.RawUI.WindowTitle = "Laji-HoneyPot Agent v0.17.1"

Write-Host "==============================================" -ForegroundColor Cyan
Write-Host "  Laji-HoneyPot Agent v0.17.1" -ForegroundColor Cyan
Write-Host "==============================================" -ForegroundColor Cyan
Write-Host ""

# ---- 检测管理员权限 ----
$isAdmin = ([Security.Principal.WindowsPrincipal] [Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole] "Administrator")
if (-not $isAdmin) {
    Write-Host "[WARN] 未以管理员运行，防火墙规则配置将跳过" -ForegroundColor Yellow
    Write-Host "       右键 PowerShell → 以管理员身份运行 以获取完整功能" -ForegroundColor Yellow
    Write-Host ""
}

# ---- 一键拉取模式 ----
if ($MgmtUrl -ne "") {
    Write-Host "[INFO] 一键拉取模式 — 从管理端下载部署包..." -ForegroundColor Cyan
    Write-Host "  管理端: $MgmtUrl" -ForegroundColor Green
    
    try {
        $pkgUrl = "$MgmtUrl/api/cluster/agent/package?os=windows&scenario=full"
        $pkgFile = "$env:TEMP\honeypot-agent-pkg.zip"
        
        Write-Host "  [→] 下载部署包: $pkgUrl"
        Invoke-WebRequest -Uri $pkgUrl -OutFile $pkgFile -ErrorAction Stop
        
        Write-Host "  [→] 解压到当前目录..."
        Expand-Archive -Path $pkgFile -DestinationPath "." -Force
        
        Write-Host "  [OK] 部署包解压完成" -ForegroundColor Green
        
        # 下载预编译二进制
        $binaryUrl = "https://github.com/br0ny4/Laji-HoneyPot/releases/latest/download/honeypot-windows-amd64.exe"
        Write-Host "  [→] 下载 Agent 二进制..."
        try {
            Invoke-WebRequest -Uri $binaryUrl -OutFile "honeypot-agent.exe" -ErrorAction Stop
            Write-Host "  [OK] 二进制下载完成" -ForegroundColor Green
        } catch {
            Write-Host "  [WARN] 二进制下载失败, 需要手动放置 honeypot-agent.exe" -ForegroundColor Yellow
            Write-Host "  编译命令: GOOS=windows GOARCH=amd64 go build -o honeypot-agent.exe ./cmd/honeypot/"
        }
    } catch {
        Write-Host "  [FAIL] 部署包下载失败: $_" -ForegroundColor Red
        Write-Host "  回退到手动部署模式..." -ForegroundColor Yellow
    }
}

# ---- 查找可执行文件 ----
$exe = $null
$possibleExes = @("honeypot-agent.exe", "honeypot.exe")
foreach ($name in $possibleExes) {
    if (Test-Path $name) {
        $exe = $name
        break
    }
}

if (-not $exe) {
    Write-Host "[ERROR] 未找到 honeypot-agent.exe 或 honeypot.exe!" -ForegroundColor Red
    Write-Host ""
    Write-Host "获取二进制文件的方式:" -ForegroundColor Yellow
    Write-Host "  【方式1: 一键拉取】" -ForegroundColor Cyan
    Write-Host "    .\deploy.ps1 -MgmtUrl 'http://MANAGER_IP:8080'"
    Write-Host ""
    Write-Host "  【方式2: 本地编译】" -ForegroundColor Cyan
    Write-Host "    在 macOS 上: GOOS=windows GOARCH=amd64 go build -o honeypot-agent.exe ./cmd/honeypot/"
    Write-Host "    将 honeypot-agent.exe 复制到当前目录"
    Write-Host ""
    pause
    exit 1
}

Write-Host "[OK] 找到: $exe" -ForegroundColor Green

# ---- 检查 config.yaml ----
if (-not (Test-Path "config.yaml")) {
    Write-Host "[WARN] 未找到 config.yaml" -ForegroundColor Yellow
    if ($MgmtUrl -ne "") {
        Write-Host "  正在从管理端下载 config.yaml..."
        $cfgUrl = "$MgmtUrl/api/cluster/agent/package?os=windows"
        try {
            Invoke-WebRequest -Uri $cfgUrl -OutFile "config-pkg.zip"
            Expand-Archive -Path "config-pkg.zip" -DestinationPath "." -Force
        } catch {
            Write-Host "  [FAIL] 配置下载失败"
        }
    }
}

# ---- 配置 Windows 防火墙 ----
if ($isAdmin) {
    Write-Host "[INFO] 配置 Windows 防火墙入站规则..." -ForegroundColor Cyan
    $ports = @(
        @{Port=80; Name="Honeypot_HTTP"},
        @{Port=3306; Name="Honeypot_MySQL"},
        @{Port=6379; Name="Honeypot_Redis"},
        @{Port=2222; Name="Honeypot_SSH"},
        @{Port=2121; Name="Honeypot_FTP"},
        @{Port=3890; Name="Honeypot_LDAP"},
        @{Port=4450; Name="Honeypot_SMB"},
        @{Port=33890; Name="Honeypot_RDP"}
    )
    foreach ($rule in $ports) {
        try {
            New-NetFirewallRule -DisplayName $rule.Name `
                -Direction Inbound `
                -LocalPort $rule.Port `
                -Protocol TCP `
                -Action Allow `
                -ErrorAction SilentlyContinue | Out-Null
            Write-Host "  [OK] $($rule.Name) :$($rule.Port)/TCP" -ForegroundColor Green
        } catch {
            Write-Host "  [SKIP] $($rule.Name) 已存在或配置失败" -ForegroundColor Yellow
        }
    }
}

# ---- 创建数据目录 ----
if (-not (Test-Path "data")) {
    New-Item -ItemType Directory -Path "data" -Force | Out-Null
    Write-Host "[OK] 数据目录: data/" -ForegroundColor Green
}

# ---- 启动 Agent ----
Write-Host ""
Write-Host "[INFO] 正在启动 Laji-HoneyPot Agent v0.17.1..." -ForegroundColor Green
Write-Host "==============================" -ForegroundColor Cyan
Write-Host ""

& ".\$exe"
