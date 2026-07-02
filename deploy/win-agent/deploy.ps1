# ==========================================
# Laji-HoneyPot Agent PowerShell Deploy Script
# Manager: 10.111.31.103:8443 (macOS)
# Agent:   10.111.29.4 (Windows 11)
# Usage:   右键 -> "使用 PowerShell 运行"
#          or: powershell -ExecutionPolicy Bypass -File deploy.ps1
# ==========================================

$ErrorActionPreference = "Stop"
$Host.UI.RawUI.WindowTitle = "Laji-HoneyPot Agent"

Write-Host "==========================================" -ForegroundColor Cyan
Write-Host "  Laji-HoneyPot Agent Deployment" -ForegroundColor White
Write-Host "  Manager: 10.111.31.103:8443" -ForegroundColor Gray
Write-Host "  Agent:   10.111.29.4" -ForegroundColor Gray
Write-Host "==========================================" -ForegroundColor Cyan
Write-Host ""

# 1. Check config.yaml
if (-not (Test-Path "config.yaml")) {
    Write-Host "[ERROR] config.yaml not found! Place it alongside honeypot-agent.exe" -ForegroundColor Red
    Read-Host "Press Enter to exit"
    exit 1
}
Write-Host "[OK] config.yaml ready" -ForegroundColor Green

# 2. Check binary
if (-not (Test-Path "honeypot-agent.exe")) {
    Write-Host "[ERROR] honeypot-agent.exe not found!" -ForegroundColor Red
    Read-Host "Press Enter to exit"
    exit 1
}
Write-Host "[OK] honeypot-agent.exe ready" -ForegroundColor Green

# 3. Create data directory
if (-not (Test-Path "data")) {
    New-Item -ItemType Directory -Path "data" | Out-Null
}
Write-Host "[OK] data directory ready" -ForegroundColor Green

# 4. Create logs directory
if (-not (Test-Path "logs")) {
    New-Item -ItemType Directory -Path "logs" | Out-Null
}
Write-Host "[OK] logs directory ready" -ForegroundColor Green

Write-Host ""
Write-Host "==========================================" -ForegroundColor Cyan
Write-Host "  Starting Agent..." -ForegroundColor Yellow
Write-Host "  Manager API:  http://10.111.31.103:8080" -ForegroundColor Gray
Write-Host "  Cluster TLS:  10.111.31.103:8443" -ForegroundColor Gray
Write-Host "  Trap HTTP:    http://10.111.29.4:8081" -ForegroundColor Gray
Write-Host "==========================================" -ForegroundColor Cyan
Write-Host ""

# 5. Start Agent
& .\honeypot-agent.exe

Write-Host "Agent exited." -ForegroundColor Yellow
Read-Host "Press Enter to exit"
