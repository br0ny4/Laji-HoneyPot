#!/usr/bin/env bash
#===============================================================================
# Laji-HoneyPot 快速验证命令集
# 
# 确保 Manager 已启动 (./bin/honeypot) 后执行:
#   bash deploy/quick-verify.sh
#===============================================================================
set -e

MGR="${1:-http://localhost:8080}"
AGENT="${2:-127.0.0.1}"
TOKEN=""

GREEN='\033[0;32m'; RED='\033[0;31m'; YELLOW='\033[1;33m'; NC='\033[0m'
ok() { echo -e "  ${GREEN}[OK]${NC} $1"; }
bad() { echo -e "  ${RED}[FAIL]${NC} $1"; }
info() { echo -e "  ${YELLOW}[→]${NC} $1"; }

echo "=========================================="
echo "  Laji-HoneyPot 快速验证"
echo "  Manager: $MGR"
echo "  Agent:   $AGENT"
echo "=========================================="
echo ""

# JWT登录
info "JWT登录..."
TOKEN=$(curl -s -X POST "$MGR/api/auth/login" -H 'Content-Type: application/json' -d '{"username":"admin","password":"admin123"}' | python3 -c "import sys,json; print(json.load(sys.stdin).get('access_token',''))" 2>/dev/null)
[ -n "$TOKEN" ] && ok "JWT Token获取 (${#TOKEN}chars)" || bad "JWT登录失败"
AUTH="Authorization: Bearer $TOKEN"

# 1. 健康检查
echo ""
info "=== 健康检查 ==="
curl -s "$MGR/healthz" | python3 -m json.tool 2>/dev/null && ok "健康检查" || bad "健康检查"

# 2. 指纹采集
echo ""
info "=== 指纹采集 (Chrome Win) ==="
HTTP=$(curl -s -o /dev/null -w "%{http_code}" -X POST "$MGR/api/collect" \
    -H 'Content-Type: application/json' \
    -H 'User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) Chrome/131.0' \
    -d '{"canvas":"verify123","gpu":"NVIDIA","scr":"1920x1080","tz":"Asia/Shanghai","lang":"zh-CN"}' 2>/dev/null)
[ "$HTTP" = "200" ] && ok "指纹采集 HTTP $HTTP" || bad "指纹采集 HTTP $HTTP"

# 3. 截屏外传
echo ""
info "=== 截屏外传 (50pts) ==="
RESP=$(curl -s -X POST "$MGR/api/countermeasure/exfil" -H "Content-Type: application/json" \
    -d "{\"type\":\"screen_capture\",\"target_ip\":\"${AGENT}_verify\",\"data_type\":\"screen_capture\",\"data\":{\"width\":1920,\"height\":1080}}" 2>/dev/null)
SCORE=$(echo "$RESP" | python3 -c "import sys,json; print(json.load(sys.stdin).get('score',0))" 2>/dev/null)
[ "$SCORE" -ge 50 ] && ok "截屏外传 score=$SCORE" || bad "截屏外传 score=$SCORE"

# 4. 文件扫描外传
echo ""
info "=== 文件扫描外传 (30pts) ==="
RESP=$(curl -s -X POST "$MGR/api/countermeasure/exfil" -H "Content-Type: application/json" \
    -d "{\"type\":\"file_scan\",\"target_ip\":\"${AGENT}_verify\",\"data_type\":\"file_scan\",\"data\":[{\"path\":\"C:\\\\test.txt\",\"name\":\"test.txt\",\"size\":100,\"category\":\"credentials\",\"sensitive\":true}]}" 2>/dev/null)
SCORE=$(echo "$RESP" | python3 -c "import sys,json; print(json.load(sys.stdin).get('score',0))" 2>/dev/null)
[ "$SCORE" -ge 30 ] && ok "文件扫描外传 score=$SCORE" || bad "文件扫描外传 score=$SCORE"

# 5. 网络探测外传
echo ""
info "=== 网络探测外传 (40pts) ==="
RESP=$(curl -s -X POST "$MGR/api/countermeasure/exfil" -H "Content-Type: application/json" \
    -d "{\"type\":\"net_probe\",\"target_ip\":\"${AGENT}_verify\",\"data_type\":\"net_probe\",\"data\":{\"internal_ips\":[\"$AGENT\",\"10.0.0.5\"],\"peer_assets\":[{\"ip\":\"10.0.0.5\",\"open_ports\":[22],\"services\":[\"ssh\"],\"role\":\"attacker\",\"confidence\":0.8}]}}" 2>/dev/null)
SCORE=$(echo "$RESP" | python3 -c "import sys,json; print(json.load(sys.stdin).get('score',0))" 2>/dev/null)
[ "$SCORE" -ge 40 ] && ok "网络探测外传 score=$SCORE" || bad "网络探测外传 score=$SCORE"

# 6. 得分板
echo ""
info "=== 得分板 ==="
curl -s -H "$AUTH" "$MGR/api/countermeasure/scoreboard" | python3 -c "
import sys,json
d=json.load(sys.stdin)
print(f'  Total Score: {d[\"total_score\"]}')
print(f'  By Category: {json.dumps(d.get(\"by_category\",{}), indent=2)}')
print(f'  Targets: {len(d.get(\"by_target\",{}))}')
" 2>/dev/null && ok "得分板查询" || bad "得分板"

# 7. VulnDB
echo ""
info "=== VulnDB ==="
TOTAL=$(curl -s -H "$AUTH" "$MGR/api/vulns?limit=1" | python3 -c "import sys,json; print(json.load(sys.stdin).get('total',0))" 2>/dev/null)
[ "$TOTAL" -ge 30 ] && ok "VulnDB total=$TOTAL" || bad "VulnDB total=$TOTAL"

# 8. 审计链
echo ""
info "=== 审计链完整性 ==="
curl -s -H "$AUTH" "$MGR/api/audit/chain/verify" | python3 -m json.tool 2>/dev/null && ok "审计链" || bad "审计链"

# 9. MFA
echo ""
info "=== MFA ==="
CHALLENGE=$(curl -s -X POST "$MGR/api/mfa/challenge" -H "$AUTH" -H "Content-Type: application/json" -d '{"user":"admin"}' | python3 -c "import sys,json; print(json.load(sys.stdin).get('challenge',''))" 2>/dev/null)
[ -n "$CHALLENGE" ] && ok "MFA Challenge: $CHALLENGE" || bad "MFA"

# 10. Agent 部署包端点
echo ""
info "=== Agent 部署包 (v0.17.1) ==="
LINUX_PKG=$(curl -s -o /dev/null -w "%{http_code}" "$MGR/api/cluster/agent/package?os=linux" 2>/dev/null)
WIN_PKG=$(curl -s -o /dev/null -w "%{http_code}" "$MGR/api/cluster/agent/package?os=windows" 2>/dev/null)
if [ "$LINUX_PKG" = "200" ] && [ "$WIN_PKG" = "200" ]; then
    ok "Agent 部署包端点 (linux HTTP $LINUX_PKG, windows HTTP $WIN_PKG)"
else
    bad "Agent 部署包端点 (linux=$LINUX_PKG, windows=$WIN_PKG)"
fi

echo ""
echo "=========================================="
echo "  快速验证完成"
echo "  全量测试: bash deploy/test-scripts/00_full_traceability_test.sh"
echo "=========================================="
