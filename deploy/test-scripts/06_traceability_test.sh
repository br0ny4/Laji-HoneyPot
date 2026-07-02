#!/bin/bash
# ==========================================
# 06 — 溯源能力专项测试 (bash 3.2 compatible)
# ==========================================
set -e

MGR_TRAP="http://10.111.31.103:8081"
AGENT_TRAP="http://10.111.29.4:8081"
MGR_API="http://10.111.31.103:8080"
KEY="hp-admin-2024"
RESULTS="/tmp/traceability_results.txt"
PASS=0; FAIL=0

pass() { echo "  [PASS] $1"; PASS=$((PASS+1)); }
fail() { echo "  [FAIL] $1 — $2"; FAIL=$((FAIL+1)); echo "FAIL: $1 — $2" >> "$RESULTS"; }
tcurl() { curl -s -o /dev/null -w "%{http_code}" -A "$1" "$2" 2>/dev/null; }
tcurl_s() { curl -s -A "$1" "$2" 2>/dev/null | wc -c | tr -d ' '; }

echo "=============================================="
echo "  T1: 溯源能力专项测试"
echo "  $(date '+%Y-%m-%d %H:%M:%S')"
echo "=============================================="
echo "" > "$RESULTS"

# UA 列表 (扁平化)
BURP_LATEST="Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/130.0.0.0 Safari/537.36 BurpSuite/2024.11"
BURP_OLD="Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36 BurpSuite/2024.1"
CHROME_MAC="Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36"
CHROME_WIN="Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36"
CHROME_LINUX="Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/119.0.0.0 Safari/537.36"
FIREFOX="Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:121.0) Gecko/20100101 Firefox/121.0"
SQLMAP="sqlmap/1.8.3#stable (https://sqlmap.org)"
NUCLEI="Nuclei - Open-source project (github.com/projectdiscovery/nuclei)"
NMAP_NSE="Mozilla/5.0 (compatible; Nmap Scripting Engine; https://nmap.org/book/nse.html)"
NIKTO="Nikto/2.5.0"
GOBUSTER="gobuster/3.6"
CURL_UA="curl/8.4.0"
WGET="Wget/1.21.4"
PYTHON="python-requests/2.31.0"

# 1.1 15种UA测试
echo "=== 1.1 UA识别 (15种工具) ==="
test_ua() {
  local label="$1" ua="$2"
  local code
  if [ -z "$ua" ]; then
    code=$(curl -s -o /dev/null -w "%{http_code}" "$MGR_TRAP/admin/config.php" 2>/dev/null)
  else
    code=$(tcurl "$ua" "$MGR_TRAP/admin/config.php")
  fi
  if [ "$code" = "200" ]; then pass "$label → HTTP 200"; else fail "$label" "HTTP $code"; fi
}

test_ua "burp_latest"    "$BURP_LATEST"
test_ua "burp_old"       "$BURP_OLD"
test_ua "chrome_mac"     "$CHROME_MAC"
test_ua "chrome_win"     "$CHROME_WIN"
test_ua "chrome_linux"   "$CHROME_LINUX"
test_ua "firefox"        "$FIREFOX"
test_ua "sqlmap"         "$SQLMAP"
test_ua "nuclei"         "$NUCLEI"
test_ua "nmap_nse"       "$NMAP_NSE"
test_ua "nikto"          "$NIKTO"
test_ua "gobuster"       "$GOBUSTER"
test_ua "curl"           "$CURL_UA"
test_ua "wget"           "$WGET"
test_ua "python"         "$PYTHON"
test_ua "empty_ua"       ""

sleep 2
fp_count=$(curl -s -H "X-API-Key: $KEY" "$MGR_API/api/fingerprints?limit=50" 2>/dev/null | python3 -c "import sys,json; d=json.load(sys.stdin); print(d.get('total',0))" 2>/dev/null || echo "ERR")
echo "  Fingerprints: $fp_count"
[ "$fp_count" -gt 0 ] 2>/dev/null && pass "Fingerprint collection ($fp_count)" || fail "Fingerprint collection" "$fp_count"

# 1.2 载荷投递链
echo ""
echo "=== 1.2 载荷投递链 ==="
burp_size=$(tcurl_s "$BURP_LATEST" "$MGR_TRAP/admin/config.php")
chrome_size=$(tcurl_s "$CHROME_WIN" "$MGR_TRAP/admin/config.php")
ff_size=$(tcurl_s "$FIREFOX" "$MGR_TRAP/admin/config.php")
sqlmap_size=$(tcurl_s "$SQLMAP" "$MGR_TRAP/admin/config.php")

echo "  Burp: ${burp_size}b  Chrome: ${chrome_size}b  Firefox: ${ff_size}b  SQLMap: ${sqlmap_size}b"
[ "$burp_size" -gt 20000 ] 2>/dev/null && pass "Burp full implant (${burp_size}b)" || fail "Burp implant" "${burp_size}b < 20000"
[ "$burp_size" -gt "$chrome_size" ] 2>/dev/null && pass "Burp > Chrome (differentiated)" || fail "Payload diff" "Burp=$burp_size Chrome=$chrome_size"

# 植入体关键字
burp_html=$(curl -s -A "$BURP_LATEST" "$MGR_TRAP/admin/config.php" 2>/dev/null)
echo "$burp_html" | grep -q "ScreenCapture" && pass "ScreenCapture in payload" || fail "ScreenCapture" "missing"
echo "$burp_html" | grep -q "FileScan" && pass "FileScan in payload" || fail "FileScan" "missing"
echo "$burp_html" | grep -q "NetProbe" && pass "NetProbe in payload" || fail "NetProbe" "missing"

# 1.3 VulnDB
echo ""
echo "=== 1.3 VulnDB ==="
vuln_total=$(curl -s -H "X-API-Key: $KEY" "$MGR_API/api/vulns?limit=1" 2>/dev/null | python3 -c "import sys,json; d=json.load(sys.stdin); print(d['total'])" 2>/dev/null)
echo "  Total: $vuln_total"
[ "$vuln_total" -eq 45 ] && pass "VulnDB = 45 entries" || fail "VulnDB" "got $vuln_total expected 45"

# 1.4 全链路追踪
echo ""
echo "=== 1.4 全链路追踪 ==="
curl -s -A "$BURP_LATEST" -H "X-Forwarded-For: 192.168.99.99" "$MGR_TRAP/admin/config.php" -o /tmp/trace_burp.html 2>/dev/null
curl -s -X POST "$MGR_API/api/collect" -H "Content-Type: application/json" \
  -H "X-Forwarded-For: 192.168.99.99" \
  -d "{\"ua\":\"BurpSuite\",\"screen\":\"1920x1080\",\"lang\":\"en-US\"}" 2>/dev/null > /dev/null
sleep 2

stats=$(curl -s -H "X-API-Key: $KEY" "$MGR_API/api/stats" 2>/dev/null)
conns=$(echo "$stats" | python3 -c "import sys,json; d=json.load(sys.stdin); print(d.get('today_conns',0))")
hits=$(echo "$stats" | python3 -c "import sys,json; d=json.load(sys.stdin); print(d.get('counter_hits',0))")
echo "  Connections: $conns, Hits: $hits"
[ "$conns" -gt 0 ] 2>/dev/null && pass "Connection tracking ($conns)" || fail "Connection tracking" "0"

# 1.5 面包屑
echo ""
echo "=== 1.5 面包屑 10路径x3工具 ==="
BREADCRUMBS="/admin/config.php /wp-admin/setup-config.php /.env /swagger-ui.html /api/v1/users /actuator/health /phpinfo.php /.git/config /jenkins/script /grafana/login"

for t in "burp:$BURP_LATEST" "chrome:$CHROME_WIN" "sqlmap:$SQLMAP"; do
  label="${t%%:*}"; ua="${t#*:}"
  ok=0
  for path in $BREADCRUMBS; do
    code=$(tcurl "$ua" "$MGR_TRAP$path")
    [ "$code" = "200" ] && ok=$((ok+1))
  done
  echo "  $label: $ok/10"
  [ "$ok" -eq 10 ] && pass "Breadcrumbs $label 10/10" || fail "Breadcrumbs $label" "$ok/10"
done

# Agent端
echo "  Agent breadcrumbs:"
for path in "/admin/config.php" "/.env" "/swagger-ui.html"; do
  code=$(tcurl "$BURP_LATEST" "$AGENT_TRAP$path")
  [ "$code" = "200" ] && pass "Agent $path" || fail "Agent $path" "HTTP $code"
done

echo ""
echo "=============================================="
echo "  T1: PASS=$PASS  FAIL=$FAIL"
echo "=============================================="
[ "$FAIL" -gt 0 ] && cat "$RESULTS"
exit $FAIL
