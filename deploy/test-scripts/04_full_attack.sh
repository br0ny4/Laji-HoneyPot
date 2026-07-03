#!/bin/bash
# ==========================================
# 04 — 全量模拟攻击测试
# 从 macOS 攻击者角度攻击管理端 + Agent 端
# ==========================================
set -e

MANAGER_IP="${MANAGER_IP:-127.0.0.1}"
AGENT_IP="${AGENT_IP:-127.0.0.1}"
MGR_TRAP="http://${MANAGER_IP}:8081"
AGENT_TRAP="http://${AGENT_IP}:8081"
MGR_API="http://${MANAGER_IP}:8080"
KEY="hp-admin-2024"

echo "===================================================================="
echo "  Laji-HoneyPot — 全量模拟攻击测试"
echo "  管理端: ${MANAGER_IP} (macOS)"
echo "  Agent:  ${AGENT_IP} (Windows)"
echo "===================================================================="
echo ""

# ----- 1. 端口扫描 (模拟 Nmap) -----
echo ">>> 1. 端口扫描 (管理端 8081)"
for port in 8081 3306 6379 2222 2121 3890 4450 33890; do
  timeout 2 bash -c "echo >/dev/tcp/${MANAGER_IP}/$port" 2>/dev/null && echo "  $port: OPEN" || echo "  $port: closed/filtered"
done

# ----- 2. 多工具 UA 面包屑访问 -----
echo ""
echo ">>> 2. 多工具 UA 触发面包屑"

# Burp Suite (should get full implant)
curl -s -A "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36 BurpSuite/2024.1" \
  "$MGR_TRAP/admin/config.php" -o /tmp/burp_resp.html
echo "  Burp (/admin/config.php): $(wc -c < /tmp/burp_resp.html) bytes"

# Nuclei scanner
curl -s -A "Nuclei - Open-source project (github.com/projectdiscovery/nuclei)" \
  "$MGR_TRAP/.env" -o /tmp/nuclei_resp.html
echo "  Nuclei (/.env): $(wc -c < /tmp/nuclei_resp.html) bytes"

# SQLMap
curl -s -A "sqlmap/1.7" "$MGR_TRAP/actuator/health" -o /tmp/sqlmap_resp.html
echo "  SQLMap (/actuator/health): $(wc -c < /tmp/sqlmap_resp.html) bytes"

# Chrome (no implant expected)
curl -s -A "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36" \
  "$MGR_TRAP/admin/config.php" -o /tmp/chrome_resp.html
echo "  Chrome (/admin/config.php): $(wc -c < /tmp/chrome_resp.html) bytes"

# ----- 3. 多面包屑路径攻击 -----
echo ""
echo ">>> 3. 面包屑全覆盖"
BREADCRUMBS=("/admin/config.php" "/wp-admin/setup-config.php" "/.env" "/swagger-ui.html" "/api/v1/users" "/actuator/health" "/phpinfo.php" "/.git/config" "/jenkins/script" "/grafana/login")
for path in "${BREADCRUMBS[@]}"; do
  code=$(curl -s -o /dev/null -w "%{http_code}" -A "Mozilla/5.0 BurpSuite/2024.1" "$MGR_TRAP$path")
  echo "  $path -> HTTP $code"
done

# ----- 4. 协议级攻击 (管理端) -----
echo ""
echo ">>> 4. 协议级攻击模拟"

# MySQL
echo "  MySQL (port 3306)..."
echo -e '\x00\x00\x00\x01\x85\xa6\x3f\x20\x00\x00\x00\x01\x08\x00\x00\x00\x00\x00\x00\x00\x00' | timeout 2 nc ${MANAGER_IP} 3306 > /tmp/mysql_banner.hex 2>&1 &
sleep 0.5; kill %1 2>/dev/null
echo "  MySQL: done"

# SSH banner
echo "  SSH (port 2222)..."
echo "SSH-2.0-test" | timeout 2 nc ${MANAGER_IP} 2222 > /tmp/ssh_banner.txt 2>&1 &
sleep 0.5; kill %1 2>/dev/null
head -1 /tmp/ssh_banner.txt 2>/dev/null && echo "  SSH: connected" || echo "  SSH: timeout OK"

# FTP
echo "  FTP (port 2121)..."
timeout 2 bash -c "echo -e 'USER admin\r\nPASS test123\r\n' | nc ${MANAGER_IP} 2121" > /tmp/ftp_banner.txt 2>&1 &
sleep 0.5; kill %1 2>/dev/null
grep -q "220" /tmp/ftp_banner.txt 2>/dev/null && echo "  FTP: banner received" || echo "  FTP: timeout OK"

# DNS (UDP)
echo "  DNS (port 5354)..."
echo "test" | timeout 2 nc -u ${MANAGER_IP} 5354 > /tmp/dns_resp.hex 2>&1 &
sleep 0.5; kill %1 2>/dev/null
echo "  DNS: probe sent"

# ----- 5. Defender Hits (Agent端攻击) -----
echo ""
echo ">>> 5. Agent 端攻击 (${AGENT_TRAP}) — 若 Agent 已上线"
agent_code=$(curl -s -o /dev/null -w "%{http_code}" "$AGENT_TRAP/" 2>/dev/null)
if [ "$agent_code" = "200" ]; then
  echo "  Agent ONLINE — 发起攻击"
  for path in "/admin/login" "/.env" "/api/keys"; do
    curl -s -A "python-requests/2.31.0" "$AGENT_TRAP$path" -o /dev/null
    echo "  > $path"
  done
else
  echo "  Agent OFFLINE ($agent_code) — 跳过"
fi

# ----- 6. API 状态验证 -----
echo ""
echo ">>> 6. 测试后状态"
curl -s -H "X-API-Key: $KEY" "$MGR_API/api/stats" | python3 -c "
import sys,json; d=json.load(sys.stdin)
print(f'  Attackers: {d.get(\"attackers\",0)}, Today Conn: {d.get(\"today_conns\",0)}, Hits: {d.get(\"counter_hits\",0)}')
"
curl -s -H "X-API-Key: $KEY" "$MGR_API/api/countermeasure/scoreboard" | python3 -c "
import sys,json; d=json.load(sys.stdin)
print(f'  Score: {d[\"total_score\"]}, Events: {len(d[\"events\"])}')
"

echo ""
echo "=== 全量攻击测试完成 ==="
