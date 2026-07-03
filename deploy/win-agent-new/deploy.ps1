$MANAGER_IP = if ($env:MANAGER_IP) { $env:MANAGER_IP } else { "127.0.0.1" }
Write-Host "=== Laji-HoneyPot Agent v0.12.0 ===" -ForegroundColor Cyan
Write-Host "Manager: ${MANAGER_IP}:8443" -ForegroundColor Green
Write-Host ""

$exe = "honeypot-agent.exe"

if (-not (Test-Path $exe)) {
    Write-Host "[ERROR] $exe not found!" -ForegroundColor Red
    exit 1
}

try {
    New-NetFirewallRule -DisplayName "Honeypot_HTTP" -Direction Inbound -LocalPort 80 -Protocol TCP -Action Allow -ErrorAction SilentlyContinue
    New-NetFirewallRule -DisplayName "Honeypot_MySQL" -Direction Inbound -LocalPort 3306 -Protocol TCP -Action Allow -ErrorAction SilentlyContinue
    Write-Host "[OK] Firewall rules configured" -ForegroundColor Green
} catch {
    Write-Host "[WARN] Run as Administrator for auto firewall config" -ForegroundColor Yellow
}

Write-Host "[INFO] Starting agent..." -ForegroundColor Green
Write-Host "=============================="
& ".\$exe"
