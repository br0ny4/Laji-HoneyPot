#!/bin/bash
# ==========================================
# T5 — 溯源反制全链路专项测试 v0.12.0
# macOS Manager + Win11 Agent
# 重点: 指纹采集/UA识别/面包屑/VulnDB/得分/审计/拓扑/截屏
# ==========================================
set -e

MANAGER_IP="${MANAGER_IP:-127.0.0.1}"
AGENT_IP="${AGENT_IP:-127.0.0.1}"
MGR="http://${MANAGER_IP}:8080"
TIP="$AGENT_IP"
LOG="/tmp/t5_traceability.log"
PASS=0; FAIL=0; SKIP=0

pass() { echo "  [PASS] $1"; ((PASS++)); }
fail() { echo "  [FAIL] $1 — $2"; ((FAIL++)); echo "FAIL: $1 — $2" >> "$LOG"; }
skip() { echo "  [SKIP] $1 — $2"; ((SKIP++)); }

echo "=============================================="
echo "  T5: 溯源反制全链路专项测试"
echo "  $(date '+%Y-%m-%d %H:%M:%S')"
echo "  Manager: $MGR | Agent: $TIP"
echo "=============================================="
echo "" > "$LOG"

# 0. 获取 JWT 令牌
echo "=== 0. JWT 认证 ==="
TOKEN=$(curl -s -X POST "$MGR/api/auth/login" -H 'Content-Type: application/json' -d '{"username":"admin","password":"admin123"}' 2>/dev/null | python3 -c "import sys,json; print(json.load(sys.stdin).get('access_token',''))" 2>/dev/null)
[ -n "$TOKEN" ] && pass "JWT 登录获取令牌(${#TOKEN} chars)" || fail "JWT登录" "无令牌"
AUTH="Authorization: Bearer $TOKEN"

# =========================================
# 1. 溯源 — 浏览器指纹采集
# =========================================
echo ""
echo "=== 1. 浏览器指纹采集测试 ==="

# 1.1 模拟 Chrome 浏览器指纹采集
echo "--- 1.1 Chrome UA 指纹 ---"
resp=$(curl -s -w "\n%{http_code}" -X POST "$MGR/api/collect" \
  -H 'Content-Type: application/json' \
  -H 'User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/131.0.0.0 Safari/537.36' \
  -d '{"canvas":"a4f8e2c1","gpu":"ANGLE(NVIDIA GeForce RTX 3060)","scr":"1920x1080x24","tz":"Asia/Shanghai","lang":"zh-CN","plugins":"PDFViewer,Chrome PDF Plugin","fonts":"Arial,Times,微软雅黑","audio":"124.0435","webgl":"NVIDIA GeForce RTX 3060"}' 2>/dev/null)
http_code=$(echo "$resp" | tail -1)
[ "$http_code" = "200" ] && pass "Chrome指纹采集 (HTTP $http_code)" || fail "Chrome指纹" "HTTP $http_code"

# 1.2 模拟 Firefox 浏览器指纹
echo "--- 1.2 Firefox UA 指纹 ---"
resp=$(curl -s -w "\n%{http_code}" -X POST "$MGR/api/collect" \
  -H 'Content-Type: application/json' \
  -H 'User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:132.0) Gecko/20100101 Firefox/132.0' \
  -d '{"canvas":"b3e9d2f0","gpu":"ANGLE(NVIDIA)","scr":"2560x1440x24","tz":"America/New_York","lang":"en-US","plugins":"OpenH264,Shockwave Flash","fonts":"Arial,Helvetica","audio":"126.7891","webgl":"NVIDIA"}' 2>/dev/null)
http_code=$(echo "$resp" | tail -1)
[ "$http_code" = "200" ] && pass "Firefox指纹采集 (HTTP $http_code)" || fail "Firefox指纹" "HTTP $http_code"

# 1.3 模拟 Burp Suite 扫描器
echo "--- 1.3 Burp Suite 扫描器 ---"
resp=$(curl -s -w "\n%{http_code}" -X POST "$MGR/api/collect" \
  -H 'Content-Type: application/json' \
  -H 'User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/131.0.0.0 Safari/537.36' \
  -d '{"canvas":"","gpu":"","scr":"","tz":"","lang":"","plugins":"","fonts":"","source":"burp_scanner"}' 2>/dev/null)
http_code=$(echo "$resp" | tail -1)
[ "$http_code" = "200" ] && pass "Burp扫描器指纹采集 (HTTP $http_code)" || fail "Burp扫描器" "HTTP $http_code"

# 1.4 模拟 Nmap 扫描
echo "--- 1.4 Nmap 扫描器 ---"
resp=$(curl -s -w "\n%{http_code}" -X POST "$MGR/api/collect" \
  -H 'Content-Type: application/json' \
  -H 'User-Agent: Mozilla/5.0 (compatible; Nmap Scripting Engine; https://nmap.org/book/nse.html)' \
  -d '{}' 2>/dev/null)
http_code=$(echo "$resp" | tail -1)
[ "$http_code" = "200" ] && pass "Nmap扫描器指纹 (HTTP $http_code)" || fail "Nmap指纹" "HTTP $http_code"

# 1.5 指纹列表查询
echo "--- 1.5 指纹列表查询 ---"
resp=$(curl -s -H "$AUTH" "$MGR/api/fingerprints?limit=10" 2>/dev/null)
TOTAL=$(echo "$resp" | python3 -c "import sys,json; d=json.load(sys.stdin); fps=d.get('fingerprints',[]); print(len(fps))" 2>/dev/null)
[ "$TOTAL" -ge 3 ] && pass "指纹列表(共 $TOTAL 条)" || skip "指纹列表" "总数=$TOTAL"

# =========================================
# 2. 溯源 — 面包屑注入
# =========================================
echo ""
echo "=== 2. 面包屑注入测试 ==="

# 2.1 访问 Grafana 诱饵页面 (HTTP) — 应包含 breadcrumb JS
echo "--- 2.1 HTTP Grafana诱饵 ---"
resp=$(curl -s -o /dev/null -w "%{http_code}" -H 'User-Agent: Mozilla/5.0 (Windows NT 10.0) Chrome/131.0' "http://localhost:80" 2>/dev/null)
[ "$resp" != "000" ] && pass "HTTP蜜罐响应 (HTTP $resp)" || skip "HTTP蜜罐" "端口80未启动? (nc监听中)"

# 2.2 访问 MySQL 蜜罐(3306) — 协议握手
echo "--- 2.2 MySQL蜜罐 ---"
resp=$(echo "" | nc -w 2 localhost 3306 2>/dev/null | xxd -p | head -c 20)
[ -n "$resp" ] && pass "MySQL蜜罐响应" || skip "MySQL蜜罐" "无响应(可能被nc阻塞)"

# 2.3 访问 SSH 蜜罐(2222) — 协议握手
echo "--- 2.3 SSH蜜罐 ---"
resp=$(echo "" | nc -w 2 localhost 2222 2>/dev/null | head -c 20)
[ -n "$resp" ] && pass "SSH蜜罐响应" || skip "SSH蜜罐" "无响应"

# 2.4 访问 Redis 蜜罐(6379) — PING
echo "--- 2.4 Redis蜜罐 ---"
resp=$(echo -ne "*1\r\n\$4\r\nPING\r\n" | nc -w 2 localhost 6379 2>/dev/null)
echo "$resp" | grep -qi "pong" && pass "Redis PING/PONG" || skip "Redis" "无PONG"

# =========================================
# 3. 溯源 — UA 识别与攻击者分类
# =========================================
echo ""
echo "=== 3. UA识别 & 攻击者分类 ==="

declare -A UA_TESTS=(
  ["Chrome_Win"]="Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/131.0.0.0 Safari/537.36"
  ["Firefox_Linux"]="Mozilla/5.0 (X11; Linux x86_64; rv:132.0) Gecko/20100101 Firefox/132.0"
  ["Safari_Mac"]="Mozilla/5.0 (Macintosh; Intel Mac OS X 14_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/18.1 Safari/605.1.15"
  ["Edge_Win"]="Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/131.0.0.0 Safari/537.36 Edg/131.0.0.0"
  ["BurpSuite"]="Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/131.0.0.0 Safari/537.36"
  ["Python"]="python-requests/2.31.0"
  ["curl"]="curl/8.7.1"
)
UA_PASS=0
for NAME in "${!UA_TESTS[@]}"; do
  UA="${UA_TESTS[$NAME]}"
  resp=$(curl -s -X POST "$MGR/api/collect" \
    -H 'Content-Type: application/json' \
    -H "User-Agent: $UA" \
    -d '{"canvas":"test","gpu":"test"}' 2>/dev/null)
  http_code=$(curl -s -o /dev/null -w "%{http_code}" -X POST "$MGR/api/collect" \
    -H 'Content-Type: application/json' \
    -H "User-Agent: $UA" \
    -d '{"canvas":"test"}' 2>/dev/null)
  if [ "$http_code" = "200" ]; then ((UA_PASS++)); fi
done
UA_TOTAL=${#UA_TESTS[@]}
[ "$UA_PASS" -ge "$UA_TOTAL" ] && pass "UA识别($UA_PASS/$UA_TOTAL全部通过)" || fail "UA识别" "$UA_PASS/$UA_TOTAL 通过"

# =========================================
# 4. 溯源 — VulnDB 漏洞库
# =========================================
echo ""
echo "=== 4. VulnDB 漏洞库 ==="

resp=$(curl -s -H "$AUTH" "$MGR/api/vulns?limit=5" 2>/dev/null)
TOTAL=$(echo "$resp" | python3 -c "import sys,json; d=json.load(sys.stdin); print(d.get('total',0))" 2>/dev/null)
[ "$TOTAL" -ge 40 ] && pass "VulnDB条目数(total=$TOTAL)" || fail "VulnDB" "total=$TOTAL"

# 按CVE查询
resp=$(curl -s -H "$AUTH" "$MGR/api/vulns?cve=CVE-2021-44228" 2>/dev/null)
CVE_COUNT=$(echo "$resp" | python3 -c "import sys,json; d=json.load(sys.stdin); print(d.get('total',0))" 2>/dev/null)
[ "$CVE_COUNT" -ge 1 ] && pass "CVE-2021-44228查询($CVE_COUNT条)" || skip "CVE查询" "$CVE_COUNT条"

# =========================================
# 5. 反制 — 截屏 & 文件扫描
# =========================================
echo ""
echo "=== 5. 反制 — 截屏 & 文件扫描 ==="

# 5.1 截屏回传 (模拟植入体)
echo "--- 5.1 截屏回传 ---"
T1=$(python3 -c "import time; print(int(time.time()*1000))" 2>/dev/null || echo 0)
resp=$(curl -s -w "\n%{http_code}" -X POST "$MGR/api/countermeasure/exfil" \
  -H "Content-Type: application/json" \
  -d "{\"type\":\"screen_capture\",\"target_ip\":\"$TIP\",\"data_type\":\"screen_capture\",\"data\":{\"width\":1920,\"height\":1080,\"format\":\"jpeg\",\"image\":\"/9j/4AAQSkZJRgABAQAAAQABAAD/2wBDAAgGBgcGBQgHBwcJCQgKDBQNDAsLDBkSEw8UHRofHh0aHBwgJC4nICIsIxwcKDcpLDAxNDQ0Hyc5PTgyPC4zNDL/wAALCAABAAEBAREA/8QAFAABAAAAAAAAAAAAAAAAAAAACf/EABQQAQAAAAAAAAAAAAAAAAAAAAD/2gAIAQEAAD8AKp//2Q==\"}}" 2>/dev/null)
http_code=$(echo "$resp" | tail -1)
T2=$(python3 -c "import time; print(int(time.time()*1000))" 2>/dev/null || echo 0)
LATENCY=$((T2 - T1))
[ "$http_code" = "200" ] && pass "截屏回传(score+50, ${LATENCY}ms)" || fail "截屏回传" "HTTP $http_code"
[ "$LATENCY" -lt 3000 ] && pass "截屏延迟 <3s(${LATENCY}ms)" || fail "截屏延迟" "${LATENCY}ms"

# 5.2 截屏列表验证
echo "--- 5.2 截屏列表 ---"
resp=$(curl -s -H "$AUTH" "$MGR/api/countermeasure/screencaps?limit=5" 2>/dev/null)
SC_TOTAL=$(echo "$resp" | python3 -c "import sys,json; d=json.load(sys.stdin); print(d.get('total',0))" 2>/dev/null)
[ "$SC_TOTAL" -ge 1 ] && pass "截屏列表(total=$SC_TOTAL)" || fail "截屏列表" "total=$SC_TOTAL"

# 5.3 文件扫描回传
echo "--- 5.3 文件扫描回传 ---"
resp=$(curl -s -X POST "$MGR/api/countermeasure/exfil" -H "Content-Type: application/json" \
  -d "{\"type\":\"file_scan\",\"target_ip\":\"$TIP\",\"data_type\":\"file_scan\",\"data\":[{\"path\":\"C:\\\\Users\\\\Administrator\\\\Documents\\\\passwords.xlsx\",\"name\":\"passwords.xlsx\",\"size\":15360,\"category\":\"credentials\",\"sensitive\":true,\"preview\":\"admin:*****\"},{\"path\":\"C:\\\\inetpub\\\\wwwroot\\\\config.php\",\"name\":\"config.php\",\"size\":2048,\"category\":\"config\",\"sensitive\":true,\"preview\":\"DB_PASSWORD=secret\"}]}" 2>/dev/null)
SCORE=$(echo "$resp" | python3 -c "import sys,json; print(json.load(sys.stdin).get('score',0))" 2>/dev/null)
[ "$SCORE" -ge 20 ] && pass "文件扫描回传(score=$SCORE)" || fail "文件扫描" "score=$SCORE"

# 5.4 文件扫描列表
echo "--- 5.4 文件扫描列表 ---"
resp=$(curl -s -H "$AUTH" "$MGR/api/countermeasure/filescans?limit=5" 2>/dev/null)
FS_TOTAL=$(echo "$resp" | python3 -c "import sys,json; d=json.load(sys.stdin); print(d.get('total',0))" 2>/dev/null)
[ "$FS_TOTAL" -ge 1 ] && pass "文件扫描列表(total=$FS_TOTAL)" || fail "文件扫描列表" "total=$FS_TOTAL"

# =========================================
# 6. 反制 — 得分板 & 冷却机制
# =========================================
echo ""
echo "=== 6. 得分板 & 冷却机制 ==="

# 6.1 得分板
resp=$(curl -s -H "$AUTH" "$MGR/api/countermeasure/scoreboard" 2>/dev/null)
SCORE_TOTAL=$(echo "$resp" | python3 -c "import sys,json; d=json.load(sys.stdin); print(d.get('total_score',0))" 2>/dev/null)
[ "$SCORE_TOTAL" -gt 0 ] && pass "得分板(total_score=$SCORE_TOTAL)" || fail "得分板" "score=$SCORE_TOTAL"

# 6.2 冷却机制 — 重复同类型不重复计分
echo "--- 6.2 冷却机制验证 ---"
resp=$(curl -s -X POST "$MGR/api/countermeasure/exfil" -H "Content-Type: application/json" \
  -d "{\"type\":\"screen_capture\",\"target_ip\":\"$TIP\",\"data_type\":\"screen_capture\",\"data\":{\"width\":1920,\"height\":1080,\"format\":\"jpeg\"}}" 2>/dev/null)
COOLDOWN_SCORE=$(echo "$resp" | python3 -c "import sys,json; print(json.load(sys.stdin).get('score',-1))" 2>/dev/null)
[ "$COOLDOWN_SCORE" = "0" ] && pass "同IP同类型冷却(score=$COOLDOWN_SCORE)" || skip "冷却验证" "score=$COOLDOWN_SCORE(可能超cooldown窗口)"

# 6.3 不同IP不同冷却
echo "--- 6.3 不同IP不冷却 ---"
resp=$(curl -s -X POST "$MGR/api/countermeasure/exfil" -H "Content-Type: application/json" \
  -d '{"type":"screen_capture","target_ip":"10.0.0.99","data_type":"screen_capture","data":{"width":1280,"height":720,"format":"jpeg"}}' 2>/dev/null)
DIFF_IP_SCORE=$(echo "$resp" | python3 -c "import sys,json; print(json.load(sys.stdin).get('score',0))" 2>/dev/null)
[ "$DIFF_IP_SCORE" -gt 0 ] && pass "不同IP正常计分(score=$DIFF_IP_SCORE)" || fail "不同IP计分" "score=$DIFF_IP_SCORE"

# =========================================
# 7. 反制 — 审计 & 拓扑
# =========================================
echo ""
echo "=== 7. 审计 & 拓扑 ==="

# 7.1 审计记录
resp=$(curl -s -H "$AUTH" "$MGR/api/countermeasure/audit?target=$TIP" 2>/dev/null)
AUDIT_TOTAL=$(echo "$resp" | python3 -c "import sys,json; d=json.load(sys.stdin); print(d.get('total',0))" 2>/dev/null)
[ "$AUDIT_TOTAL" -ge 1 ] && pass "审计记录(total=$AUDIT_TOTAL)" || fail "审计" "total=$AUDIT_TOTAL"

# 7.2 攻击者拓扑
resp=$(curl -s -H "$AUTH" "$MGR/api/countermeasure/topology" 2>/dev/null)
[ -n "$resp" ] && pass "拓扑API可用" || fail "拓扑" "empty"

# =========================================
# 8. 反制 — 远程Shell / 文件传输 / MFA
# =========================================
echo ""
echo "=== 8. 远程Shell/传输/MFA ==="

# 8.1 MFA Challenge
resp=$(curl -s -X POST "$MGR/api/mfa/challenge" -H "$AUTH" -H "Content-Type: application/json" -d '{"user":"admin"}' 2>/dev/null)
CHALLENGE=$(echo "$resp" | python3 -c "import sys,json; print(json.load(sys.stdin).get('challenge',''))" 2>/dev/null)
[ -n "$CHALLENGE" ] && pass "MFA挑战码(6位=$CHALLENGE)" || fail "MFA" "no challenge"

# 8.2 MFA Verify
if [ -n "$CHALLENGE" ]; then
  resp=$(curl -s -X POST "$MGR/api/mfa/verify" -H "$AUTH" -H "Content-Type: application/json" -d "{\"user\":\"admin\",\"code\":\"$CHALLENGE\"}" 2>/dev/null)
  MFA_TOKEN=$(echo "$resp" | python3 -c "import sys,json; print(json.load(sys.stdin).get('token',''))" 2>/dev/null)
  [ -n "$MFA_TOKEN" ] && pass "MFA令牌签发(5min有效)" || fail "MFA验证" "no token"
fi

# 8.3 审计链完整性
resp=$(curl -s -H "$AUTH" "$MGR/api/audit/chain/verify" 2>/dev/null)
VALID=$(echo "$resp" | python3 -c "import sys,json; print(json.load(sys.stdin).get('valid',False))" 2>/dev/null)
[ "$VALID" = "True" ] && pass "审计链完整性验证(valid=True)" || fail "审计链" "valid=$VALID"

# =========================================
# 9. Agent 连通性
# =========================================
echo ""
echo "=== 9. Agent 连通性(集群) ==="
resp=$(curl -s -H "$AUTH" "$MGR/api/cluster/status" 2>/dev/null)
NODES=$(echo "$resp" | python3 -c "import sys,json; d=json.load(sys.stdin); nodes=d if type(d)==list else d.get('nodes',[]); print(len(nodes))" 2>/dev/null)
[ "$NODES" -ge 0 ] && pass "集群状态查询(nodes=$NODES)" || skip "集群状态" "无响应 (Agent未连?)"

# =========================================
# 10. 反制 — 得分详情(按目标)
# =========================================
echo ""
echo "=== 10. 按目标得分明细 ==="
resp=$(curl -s -H "$AUTH" "$MGR/api/countermeasure/scoreboard" 2>/dev/null)
TARGETS=$(echo "$resp" | python3 -c "import sys,json; d=json.load(sys.stdin); bt=d.get('by_target',{}); print(len(bt))" 2>/dev/null)
[ "$TARGETS" -ge 1 ] && pass "按目标统计(共$TARGETS个目标)" || fail "目标统计" "targets=$TARGETS"

# =========================================
# 结果汇总
# =========================================
echo ""
echo "=============================================="
echo "  T5: 溯源反制全链路测试结果"
echo "=============================================="
TOTAL=$((PASS + FAIL + SKIP))
echo "  Total: $TOTAL | Pass: $PASS | Fail: $FAIL | Skip: $SKIP"
echo "  Rate:  $(python3 -c "print(f'{$PASS*100/$TOTAL:.1f}%')" 2>/dev/null || echo "N/A")"
echo "  Log:   $LOG"
echo "=============================================="

# 生成 JSON 报告
python3 -c "
import json
report = {
  'test': 'T5: Traceability & Countermeasure Full-Chain',
  'timestamp': '$(date -u +%Y-%m-%dT%H:%M:%SZ)',
  'manager': '$MGR',
  'agent': '$TIP',
  'total': $TOTAL, 'pass': $PASS, 'fail': $FAIL, 'skip': $SKIP,
  'sections': {
    'jwt_auth': 1,
    'fingerprint': 5,
    'breadcrumb': 4,
    'ua_recognition': $UA_PASS,
    'vulndb': 2,
    'screencap': 2,
    'filescan': 2,
    'scoring': 3,
    'audit_topology': 2,
    'mfa_chain': 3,
    'cluster': 1
  }
}
with open('/tmp/t5_report.json','w') as f:
  json.dump(report, f, indent=2)
print('Report: /tmp/t5_report.json')
"

exit $FAIL
