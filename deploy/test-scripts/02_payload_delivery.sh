#!/bin/bash
# ==========================================
# 02 — Payload 投递 & 面包屑测试
# 攻击目标: 管理端 HTTP 蜜罐
# ==========================================
MANAGER_IP="${MANAGER_IP:-127.0.0.1}"
AGENT_IP="${AGENT_IP:-127.0.0.1}"
MGR_TRAP="http://${MANAGER_IP}:8081"
AGENT_TRAP="http://${AGENT_IP}:8081"
MGR_API="http://${MANAGER_IP}:8080"
KEY="hp-admin-2024"

echo "=========================================="
echo "  面包屑路径 + Payload 投递测试"
echo "=========================================="
echo ""

# 7 种典型攻击者 UA
declare -A ATTACKER_UAS=(
  ["burp"]="Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36 BurpSuite/2024.1"
  ["chrome"]="Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36"
  ["firefox"]="Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:121.0) Gecko/20100101 Firefox/121.0"
  ["sqlmap"]="sqlmap/1.7.10#stable (https://sqlmap.org)"
  ["nuclei"]="Nuclei - Open-source project (github.com/projectdiscovery/nuclei)"
  ["curl"]="curl/8.4.0"
  ["python"]="python-requests/2.31.0"
)

# 关键面包屑路径
BREADCRUMBS=(
  "/admin/config.php"
  "/wp-admin/setup-config.php"
  "/.env"
  "/swagger-ui.html"
  "/api/v1/users"
  "/actuator/health"
  "/phpinfo.php"
  "/.git/config"
  "/jenkins/script"
)

echo ">>> 测试管理端蜜罐 (${MGR_TRAP})"
echo ""

for label in burp chrome firefox sqlmap nuclei curl python; do
  ua="${ATTACKER_UAS[$label]}"
  size=$(curl -s -A "$ua" "$MGR_TRAP${BREADCRUMBS[0]}" 2>/dev/null | wc -c | tr -d ' ')
  echo "  [$label] ${BREADCRUMBS[0]}: ${size} bytes"
done

echo ""
echo ">>> Burp UA 走所有面包屑路径"
for path in "${BREADCRUMBS[@]}"; do
  size=$(curl -s -A "${ATTACKER_UAS[burp]}" "$MGR_TRAP$path" 2>/dev/null | wc -c | tr -d ' ')
  echo "  $path: ${size} bytes"
done

echo ""
echo ">>> Chrome UA 走所有面包屑路径"
for path in "${BREADCRUMBS[@]}"; do
  size=$(curl -s -A "${ATTACKER_UAS[chrome]}" "$MGR_TRAP$path" 2>/dev/null | wc -c | tr -d ' ')
  echo "  $path: ${size} bytes"
done

echo ""
echo ">>> 对比 Burp vs Chrome Payload 大小差异"
burp_size=$(curl -s -A "${ATTACKER_UAS[burp]}" "$MGR_TRAP/admin/config.php" 2>/dev/null | wc -c | tr -d ' ')
chrome_size=$(curl -s -A "${ATTACKER_UAS[chrome]}" "$MGR_TRAP/admin/config.php" 2>/dev/null | wc -c | tr -d ' ')
diff=$((burp_size - chrome_size))
echo "  Burp:   ${burp_size} bytes"
echo "  Chrome: ${chrome_size} bytes"
echo "  Diff:   ${diff} bytes (>=15KB = implant delivered)"

echo ""
echo ">>> Agent 蜜罐验证 (${AGENT_TRAP}) — 需 Agent 已部署"
agent_resp=$(curl -s -o /dev/null -w "%{http_code}" "$AGENT_TRAP/" 2>/dev/null)
if [ "$agent_resp" = "200" ]; then
  echo "  Agent HTTP: OK (200)"
else
  echo "  Agent HTTP: UNREACHABLE ($agent_resp)"
fi

echo ""
echo ">>> 攻击事件记录"
curl -s -H "X-API-Key: $KEY" "$MGR_API/api/stats" | python3 -c "import sys,json; d=json.load(sys.stdin); print(f'  Attackers: {d.get(\"attackers\",0)}, Conn: {d.get(\"today_conns\",0)}, Hits: {d.get(\"counter_hits\",0)}')"
