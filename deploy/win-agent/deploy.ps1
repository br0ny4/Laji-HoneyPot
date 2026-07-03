<#
.SYNOPSIS
    Laji-HoneyPot Windows Agent v0.12.0 部署脚本
.DESCRIPTION
    在 Windows 11 (AGENT_IP_PLACEHOLDER) 上部署 Agent 蜜罐节点
    自动配置防火墙规则，连接 macOS Manager
.NOTES
    必须以管理员身份运行 PowerShell
    需要 honeypot-agent.exe 在同一目录
#>

$ErrorActionPreference = "Stop"
$Host.UI.RawUI.WindowTitle = "Laji-HoneyPot Agent"

Write-Host "==============================================" -ForegroundColor Cyan
Write-Host "  Laji-HoneyPot Agent v0.12.0" -ForegroundColor Cyan
Write-Host "  Manager: $(Get-Content config.yaml | Select-String 'manager_addr')" -ForegroundColor Green
Write-Host "==============================================" -ForegroundColor Cyan
Write-Host ""

# ---- 检测管理员权限 ----
$isAdmin = ([Security.Principal.WindowsPrincipal] [Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole] "Administrator")
if (-not $isAdmin) {
    Write-Host "[WARN] 未以管理员运行，防火墙规则配置将跳过" -ForegroundColor Yellow
    Write-Host "       右键 PowerShell → 以管理员身份运行 以获取完整功能" -ForegroundColor Yellow
    Write-Host ""
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
    Write-Host "请将编译好的 Windows Agent 二进制文件放置到当前目录:"
    Write-Host "  1. 在 macOS 上交叉编译: GOOS=windows GOARCH=amd64 go build -o honeypot-agent.exe ./cmd/honeypot/"
    Write-Host "  2. 将 honeypot-agent.exe 复制到本目录"
    Write-Host "  3. 重新运行本脚本"
    Write-Host ""
    pause
    exit 1
}

Write-Host "[OK] 找到: $exe" -ForegroundColor Green

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
Write-Host "[INFO] 正在启动 Laji-HoneyPot Agent..." -ForegroundColor Green
Write-Host "==============================" -ForegroundColor Cyan
Write-Host ""

& ".\$exe"
