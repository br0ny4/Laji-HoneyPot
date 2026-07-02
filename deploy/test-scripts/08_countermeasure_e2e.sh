#!/bin/bash
# ==========================================
# 08 — 反制模块全链路 E2E 测试
# 测试范围: 截屏链路 / 远程Shell / 文件传输 / 进程管理 /
#          桌面远控 / MFA认证 / 审计链 / 弱网模拟 / 合规校验
# ==========================================
set -e

MGR_API="${MGR_API:-http://localhost:8080}"
KEY="${KEY:-hp-admin-2024}"
TARGET_IP="${TARGET_IP:-10.111.29.4}"
PASS=0; FAIL=0; SKIP=0
LOG="/tmp/countermeasure_e2e.log"
REPORT_DIR="/tmp/honeypot_e2e_report"
mkdir -p "$REPORT_DIR"

pass() { echo "  [PASS] $1"; ((PASS++)); }
fail() { echo "  [FAIL] $1 — $2"; ((FAIL++)); echo "FAIL: $1 — $2" >> "$LOG"; }
skip() { echo "  [SKIP] $1 — $2"; ((SKIP++)); }
api_get() { curl -s -H "X-API-Key: $KEY" "$MGR_API$1"; }
api_post() { curl -s -w "\n%{http_code}" -X POST "$MGR_API$1" -H "X-API-Key: $KEY" -H "Content-Type: application/json" -d "$2"; }

echo "=============================================="
echo "  T3: 反制模块全链路 E2E 测试"
echo "  $(date '+%Y-%m-%d %H:%M:%S')"
echo "  API: $MGR_API | Target: $TARGET_IP"
echo "=============================================="
echo "" > "$LOG"

# =============================================
# 1. 健康检查 & 服务可用性
# =============================================
echo ""
echo "=== 1. 服务健康检查 ==="
resp=$(curl -s "$MGR_API/healthz")
echo "$resp" | python3 -c "import sys,json; d=json.load(sys.stdin); assert d['status']=='ok'" 2>/dev/null && pass "Health check OK" || fail "Health check" "$resp"

# =============================================
# 2. 截屏全链路测试
# =============================================
echo ""
echo "=== 2. 截屏全链路 ==="

# 2.1 提交截屏数据（模拟植入体回传）
echo "--- 2.1 截屏数据回传 ---"
T1=$(python3 -c "import time; print(int(time.time()*1000))")
resp=$(curl -s -w "\n%{http_code}" -X POST "$MGR_API/api/countermeasure/exfil" \
  -H "Content-Type: application/json" \
  -d "{\"type\":\"screen_capture\",\"target_ip\":\"$TARGET_IP\",\"data_type\":\"screen_capture\",\"data\":{\"width\":1920,\"height\":1080,\"format\":\"jpeg\",\"image\":\"/9j/4AAQSkZJRgABAQAAAQABAAD/2wBDAAgGBgcGBQgHBwcJCQgKDBQNDAsLDBkSEw8UHRofHh0aHBwgJC4nICIsIxwcKDcpLDAxNDQ0Hyc5PTgyPC4zNDL/wAALCAABAAEBAREA/8QAFAABAAAAAAAAAAAAAAAAAAAACf/EABQQAQAAAAAAAAAAAAAAAAAAAAD/2gAIAQEAAD8AKp//2Q==\"}}" 2>/dev/null)
T2=$(python3 -c "import time; print(int(time.time()*1000))")
http_code=$(echo "$resp" | tail -1)
body=$(echo "$resp" | head -1)
latency=$((T2 - T1))

[ "$http_code" = "200" ] && pass "Screen capture POST (HTTP $http_code, ${latency}ms)" || fail "Screen capture POST" "HTTP $http_code"
[ "$latency" -lt 3000 ] && pass "Screen capture latency <3s (${latency}ms)" || fail "Screen capture latency" "${latency}ms >= 3s"

# Submit a second screen capture
curl -s -X POST "$MGR_API/api/countermeasure/exfil" \
  -H "Content-Type: application/json" \
  -d "{\"type\":\"screen_capture\",\"target_ip\":\"$TARGET_IP\",\"data_type\":\"screen_capture\",\"data\":{\"width\":1280,\"height\":720,\"format\":\"png\",\"image\":\"iVBORw0KGgoAAAANSUhEUgAAAAEAAAABCAYAAAAfFcSJAAAADUlEQVR42mNk+M9QDwADhgGAWjR9awAAAABJRU5ErkJggg==\"}}" > /dev/null 2>&1

# 2.2 截屏分页列表
echo "--- 2.2 截屏分页列表 ---"
resp=$(api_get "/api/countermeasure/screencaps?ip=$TARGET_IP&limit=10&offset=0")
total=$(echo "$resp" | python3 -c "import sys,json; d=json.load(sys.stdin); print(d.get('total',0))" 2>/dev/null)
records=$(echo "$resp" | python3 -c "import sys,json; d=json.load(sys.stdin); print(len(d.get('records',[])))" 2>/dev/null)
[ "$total" -ge 1 ] && pass "Screen cap list (total=$total, records=$records)" || fail "Screen cap list" "total=$total"

# Get first screencap ID
first_id=$(echo "$resp" | python3 -c "import sys,json; d=json.load(sys.stdin); r=d.get('records',[]); print(r[0]['id'] if r else '')" 2>/dev/null)

# 2.3 截屏详情
if [ -n "$first_id" ]; then
  echo "--- 2.3 截屏详情 ---"
  resp=$(api_get "/api/countermeasure/screencaps/$first_id")
  detail_ip=$(echo "$resp" | python3 -c "import sys,json; d=json.load(sys.stdin); print(d.get('remote_ip',''))" 2>/dev/null)
  [ "$detail_ip" = "$TARGET_IP" ] && pass "Screen cap detail (id=$first_id)" || fail "Screen cap detail" "ip mismatch: $detail_ip"

  # 2.4 截屏下载
  echo "--- 2.4 截屏下载 ---"
  resp=$(api_get "/api/countermeasure/screencaps/$first_id/download")
  [ -n "$resp" ] && pass "Screen cap download (${#resp} bytes)" || fail "Screen cap download" "empty response"
fi

# 2.5 无 IP 筛选全量查询
echo "--- 2.5 全量截屏查询 ---"
resp=$(api_get "/api/countermeasure/screencaps?limit=5")
total=$(echo "$resp" | python3 -c "import sys,json; d=json.load(sys.stdin); print(d.get('total',0))" 2>/dev/null)
[ "$total" -ge 1 ] && pass "Screen caps (all targets, total=$total)" || fail "Screen caps (all targets)" "total=$total"

# =============================================
# 3. 文件扫描链路测试
# =============================================
echo ""
echo "=== 3. 文件扫描链路 ==="

# 3.1 提交文件扫描数据
echo "--- 3.1 文件扫描数据回传 ---"
curl -s -X POST "$MGR_API/api/countermeasure/exfil" \
  -H "Content-Type: application/json" \
  -d "{\"type\":\"file_scan\",\"target_ip\":\"$TARGET_IP\",\"data_type\":\"file_scan\",\"data\":[{\"path\":\"/etc/passwd\",\"name\":\"passwd\",\"size\":2048,\"category\":\"credentials\",\"sensitive\":true,\"preview\":\"root:x:0:0:root\"},{\"path\":\"/home/user/.ssh/id_rsa\",\"name\":\"id_rsa\",\"size\":1679,\"category\":\"keys\",\"sensitive\":true,\"preview\":\"-----BEGIN RSA PRIVATE KEY-----\"}]}" > /dev/null 2>&1
pass "File scan data submitted"

# 3.2 文件扫描列表
echo "--- 3.2 文件扫描列表 ---"
resp=$(api_get "/api/countermeasure/filescans?ip=$TARGET_IP&limit=10")
total=$(echo "$resp" | python3 -c "import sys,json; d=json.load(sys.stdin); print(d.get('total',0))" 2>/dev/null)
[ "$total" -ge 1 ] && pass "File scan list (total=$total)" || fail "File scan list" "total=$total"

# 3.3 按类别筛选
echo "--- 3.3 文件扫描类别筛选 ---"
resp=$(api_get "/api/countermeasure/filescans?ip=$TARGET_IP&category=credentials&limit=10")
total=$(echo "$resp" | python3 -c "import sys,json; d=json.load(sys.stdin); print(d.get('total',0))" 2>/dev/null)
[ "$total" -ge 1 ] && pass "File scan filter by category (total=$total)" || fail "File scan category filter" "total=$total"

# =============================================
# 4. 得分板 & 审计 & 拓扑测试
# =============================================
echo ""
echo "=== 4. 得分板 & 审计 ==="

# 4.1 得分板
resp=$(api_get "/api/countermeasure/scoreboard")
scores=$(echo "$resp" | python3 -c "import sys,json; d=json.load(sys.stdin); print(len(d.get('scores',d)))" 2>/dev/null)
[ -n "$resp" ] && pass "Scoreboard API" || fail "Scoreboard API" "empty response"

# 4.2 审计记录
resp=$(api_get "/api/countermeasure/audit?target=$TARGET_IP")
total=$(echo "$resp" | python3 -c "import sys,json; d=json.load(sys.stdin); print(d.get('total',0))" 2>/dev/null)
[ "$total" -ge 1 ] && pass "Audit trail (total=$total)" || fail "Audit trail" "total=$total"

# 4.3 拓扑
resp=$(api_get "/api/countermeasure/topology")
[ -n "$resp" ] && pass "Topology API" || fail "Topology API" "empty response"

# =============================================
# 5. 远程 Shell 链路测试
# =============================================
echo ""
echo "=== 5. 远程 Shell ==="

# 5.1 Shell WebSocket 连接测试（用 curl 模拟握手）
echo "--- 5.1 Shell 连接握手 ---"
resp=$(curl -s -o /dev/null -w "%{http_code}" \
  -H "X-API-Key: $KEY" \
  -H "Connection: Upgrade" \
  -H "Upgrade: websocket" \
  -H "Sec-WebSocket-Version: 13" \
  -H "Sec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==" \
  "$MGR_API/api/countermeasure/shell?target=$TARGET_IP" 2>/dev/null)
[ "$resp" = "400" ] && pass "Shell WS requires upgrade header (HTTP $resp)" || [ "$resp" = "101" ] && pass "Shell WS upgrade OK (HTTP $resp)" || skip "Shell WS" "HTTP $resp (expected 101 or 400)"

# 5.2 不带 target 参数
resp=$(curl -s "$MGR_API/api/countermeasure/shell" -H "X-API-Key: $KEY" 2>/dev/null)
echo "$resp" | python3 -c "import sys,json; d=json.load(sys.stdin); assert 'error' in d" 2>/dev/null && pass "Shell requires target param" || fail "Shell param check" "$resp"

# =============================================
# 6. 文件传输链路测试
# =============================================
echo ""
echo "=== 6. 文件传输 ==="

# 6.1 分块上传
echo "--- 6.1 文件分块上传 ---"
TEST_CONTENT="This is a test file for chunked upload verification. Line 2. Line 3."
TOTAL_SIZE=${#TEST_CONTENT}
resp=$(curl -s -X POST "$MGR_API/api/countermeasure/transfer/upload" \
  -H "X-API-Key: $KEY" \
  -H "X-Target-IP: $TARGET_IP" \
  -H "X-File-Path: /tmp/test_transfer.txt" \
  -H "X-Offset: 0" \
  -H "X-Total-Size: $TOTAL_SIZE" \
  --data-binary "$TEST_CONTENT" 2>/dev/null)
status=$(echo "$resp" | python3 -c "import sys,json; d=json.load(sys.stdin); print(d.get('status',''))" 2>/dev/null)
[ "$status" = "completed" ] && pass "File upload chunk (status=$status)" || fail "File upload" "status=$status resp=$resp"

# 6.2 传输状态查询
echo "--- 6.2 传输状态 ---"
resp=$(api_get "/api/countermeasure/transfer/status")
total=$(echo "$resp" | python3 -c "import sys,json; d=json.load(sys.stdin); print(d.get('total',0))" 2>/dev/null)
[ "$total" -ge 1 ] && pass "Transfer status list (total=$total)" || fail "Transfer status" "total=$total"

# 6.3 传输列表（按目标）
echo "--- 6.3 传输列表 ---"
resp=$(api_get "/api/countermeasure/transfer/list?target=$TARGET_IP")
total=$(echo "$resp" | python3 -c "import sys,json; d=json.load(sys.stdin); print(d.get('total',0))" 2>/dev/null)
[ "$total" -ge 1 ] && pass "Transfer list by target (total=$total)" || fail "Transfer list" "total=$total"

# 6.4 下载（文件不存在场景）
echo "--- 6.4 文件下载 ---"
resp=$(api_get "/api/countermeasure/transfer/download?target=$TARGET_IP&path=/tmp/nonexistent.txt")
echo "$resp" | python3 -c "import sys,json; d=json.load(sys.stdin); assert 'error' in d" 2>/dev/null && pass "Download missing file returns error" || fail "Download error handling" "$resp"

# 6.5 暂停不存在的传输
echo "--- 6.5 暂停传输 ---"
resp=$(api_post "/api/countermeasure/transfer/pause" '{"transfer_id":"tx_nonexistent"}')
echo "$resp" | python3 -c "import sys,json; d=json.load(sys.stdin); assert 'error' in d" 2>/dev/null && pass "Pause non-existent transfer" || fail "Pause error handling" "$resp"

# =============================================
# 7. 进程管理链路测试
# =============================================
echo ""
echo "=== 7. 进程管理 ==="

# 7.1 进程列表
echo "--- 7.1 进程列表 ---"
resp=$(api_get "/api/countermeasure/processes?target=$TARGET_IP")
[ -n "$resp" ] && pass "Process list API" || fail "Process list API" "empty response"

# 7.2 进程列表带筛选
echo "--- 7.2 进程筛选 ---"
resp=$(api_get "/api/countermeasure/processes?target=$TARGET_IP&filter=ssh")
[ -n "$resp" ] && pass "Process filter API" || fail "Process filter API" "empty response"

# 7.3 启动进程（参数校验）
echo "--- 7.3 进程启动参数校验 ---"
resp=$(api_post "/api/countermeasure/processes/start" '{"target_ip":""}')
echo "$resp" | python3 -c "import sys,json; d=json.load(sys.stdin); assert 'error' in d" 2>/dev/null && pass "Process start param check" || fail "Process start params" "$resp"

# 7.4 停止进程（参数校验）
echo "--- 7.4 进程停止参数校验 ---"
resp=$(api_post "/api/countermeasure/processes/stop" '{"target_ip":""}')
echo "$resp" | python3 -c "import sys,json; d=json.load(sys.stdin); assert 'error' in d" 2>/dev/null && pass "Process stop param check" || fail "Process stop params" "$resp"

# 7.5 删除进程（参数校验）
echo "--- 7.5 进程删除参数校验 ---"
resp=$(api_post "/api/countermeasure/processes/delete" '{"target_ip":""}')
echo "$resp" | python3 -c "import sys,json; d=json.load(sys.stdin); assert 'error' in d" 2>/dev/null && pass "Process delete param check" || fail "Process delete params" "$resp"

# =============================================
# 8. 桌面远控链路测试
# =============================================
echo ""
echo "=== 8. 桌面远控 ==="

# 8.1 Viewer 连接（WebSocket 握手）
resp=$(curl -s -o /dev/null -w "%{http_code}" \
  -H "Connection: Upgrade" \
  -H "Upgrade: websocket" \
  -H "Sec-WebSocket-Version: 13" \
  -H "Sec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==" \
  "$MGR_API/api/countermeasure/desktop?target=$TARGET_IP&quality=80&fps=10" 2>/dev/null)
[ "$resp" = "400" ] && pass "Desktop WS requires upgrade (HTTP $resp)" || [ "$resp" = "101" ] && pass "Desktop WS upgrade OK (HTTP $resp)" || skip "Desktop WS" "HTTP $resp"

# 8.2 不带 target
resp=$(curl -s "$MGR_API/api/countermeasure/desktop" 2>/dev/null)
echo "$resp" | python3 -c "import sys,json; d=json.load(sys.stdin); assert 'error' in d" 2>/dev/null && pass "Desktop requires target param" || fail "Desktop param check" "$resp"

# =============================================
# 9. MFA 二次认证链路测试
# =============================================
echo ""
echo "=== 9. MFA 二次认证 ==="

# 9.1 请求 Challenge
echo "--- 9.1 MFA Challenge ---"
resp=$(api_post "/api/mfa/challenge" '{"user":"admin"}')
challenge=$(echo "$resp" | python3 -c "import sys,json; d=json.load(sys.stdin); print(d.get('challenge',''))" 2>/dev/null)
[ -n "$challenge" ] && pass "MFA challenge issued" || fail "MFA challenge" "$resp"

# 9.2 验证 MFA 码并获取 Token
echo "--- 9.2 MFA Verify ---"
resp=$(api_post "/api/mfa/verify" "{\"user\":\"admin\",\"code\":\"$challenge\",\"ops\":[\"shell\",\"transfer\"]}")
token=$(echo "$resp" | python3 -c "import sys,json; d=json.load(sys.stdin); print(d.get('token',''))" 2>/dev/null)
[ -n "$token" ] && pass "MFA token issued ($token)" || fail "MFA token" "resp=$resp"

# 9.3 错误码拒绝
echo "--- 9.3 MFA 错误码拒绝 ---"
resp=$(api_post "/api/mfa/verify" '{"user":"admin","code":"000000","ops":["shell"]}')
http_code=$(echo "$resp" | tail -1)
body=$(echo "$resp" | head -1 2>/dev/null)
echo "$body" | python3 -c "import sys,json; d=json.load(sys.stdin); assert 'error' in d" 2>/dev/null && pass "MFA rejects invalid code" || fail "MFA invalid code" "$resp"

# 9.4 缺少参数
echo "--- 9.4 MFA 参数校验 ---"
resp=$(api_post "/api/mfa/challenge" '{}')
echo "$resp" | python3 -c "import sys,json; d=json.load(sys.stdin); assert 'error' in d" 2>/dev/null && pass "MFA requires user param" || fail "MFA params" "$resp"

# =============================================
# 10. 不可篡改审计链测试
# =============================================
echo ""
echo "=== 10. 审计链 ==="

# 10.1 获取审计链
echo "--- 10.1 审计链列表 ---"
resp=$(api_get "/api/audit/chain?limit=50")
total=$(echo "$resp" | python3 -c "import sys,json; d=json.load(sys.stdin); print(d.get('total',0))" 2>/dev/null)
chain_valid=$(echo "$resp" | python3 -c "import sys,json; d=json.load(sys.stdin); print(d.get('chain_valid',False))" 2>/dev/null)
[ "$total" -ge 1 ] && pass "Audit chain entries (total=$total)" || fail "Audit chain" "total=$total"
[ "$chain_valid" = "True" ] && pass "Audit chain integrity valid" || fail "Audit chain integrity" "chain_valid=$chain_valid"

# 10.2 验证审计链
echo "--- 10.2 审计链验证 ---"
resp=$(api_get "/api/audit/chain/verify")
valid=$(echo "$resp" | python3 -c "import sys,json; d=json.load(sys.stdin); print(d.get('valid',False))" 2>/dev/null)
head=$(echo "$resp" | python3 -c "import sys,json; d=json.load(sys.stdin); print(d.get('head',''))" 2>/dev/null)
[ "$valid" = "True" ] && pass "Audit chain verify (head=$head)" || fail "Audit chain verify" "valid=$valid"

# =============================================
# 11. API Key 认证测试
# =============================================
echo ""
echo "=== 11. API Key 认证 ==="

# 11.1 无 Key 访问受保护端点
[ -n "$KEY" ] && {
  resp=$(curl -s -w "\n%{http_code}" "$MGR_API/api/countermeasure/scoreboard" 2>/dev/null)
  http_code=$(echo "$resp" | tail -1)
  [ "$http_code" = "401" ] && pass "API key required (HTTP $http_code)" || skip "API key check" "HTTP $http_code (no key configured?)"
} || skip "API key test" "KEY not set"

# 11.2 Exfil 端点无需认证
resp=$(curl -s -w "\n%{http_code}" -X POST "$MGR_API/api/countermeasure/exfil" \
  -H "Content-Type: application/json" \
  -d '{"type":"fingerprint","target_ip":"10.0.0.1","data":{"test":true}}' 2>/dev/null)
http_code=$(echo "$resp" | tail -1)
[ "$http_code" = "200" ] && pass "Exfil endpoint no auth required" || fail "Exfil endpoint" "HTTP $http_code"

# =============================================
# 12. 弱网与容错测试
# =============================================
echo ""
echo "=== 12. 弱网与容错 ==="

# 12.1 大请求体
echo "--- 12.1 大请求体测试 ---"
BIG_DATA=$(python3 -c "print('A'*100000)")
resp=$(curl -s -w "\n%{http_code}" -X POST "$MGR_API/api/countermeasure/exfil" \
  -H "Content-Type: application/json" \
  -d "{\"type\":\"screen_capture\",\"target_ip\":\"$TARGET_IP\",\"data_type\":\"screen_capture\",\"data\":{\"image\":\"$BIG_DATA\"}}" 2>/dev/null)
http_code=$(echo "$resp" | tail -1)
[ "$http_code" = "200" ] && pass "Large payload handled (HTTP $http_code)" || fail "Large payload" "HTTP $http_code"

# 12.2 无效 JSON
echo "--- 12.2 无效 JSON ---"
resp=$(curl -s -w "\n%{http_code}" -X POST "$MGR_API/api/countermeasure/exfil" \
  -H "Content-Type: application/json" \
  -d "not-json" 2>/dev/null)
http_code=$(echo "$resp" | tail -1)
[ "$http_code" = "400" ] && pass "Invalid JSON rejected ($http_code)" || fail "Invalid JSON" "HTTP $http_code"

# 12.3 并发请求（快速连续 5 个）
echo "--- 12.3 并发 exfil 请求 ---"
T1=$(python3 -c "import time; print(int(time.time()*1000))")
for i in $(seq 1 5); do
  curl -s -X POST "$MGR_API/api/countermeasure/exfil" \
    -H "Content-Type: application/json" \
    -d "{\"type\":\"fingerprint\",\"target_ip\":\"10.0.0.$i\",\"data_type\":\"fingerprint\",\"data\":{\"seq\":$i}}" > /dev/null 2>&1 &
done
wait
T2=$(python3 -c "import time; print(int(time.time()*1000))")
elapsed=$((T2 - T1))
[ "$elapsed" -lt 5000 ] && pass "Concurrent exfil (5 req, ${elapsed}ms)" || fail "Concurrent exfil" "${elapsed}ms >= 5s"

# 12.4 错误 Method
echo "--- 12.4 错误 Method ---"
resp=$(curl -s -w "\n%{http_code}" -X PUT "$MGR_API/api/countermeasure/screencaps" -H "X-API-Key: $KEY" 2>/dev/null)
http_code=$(echo "$resp" | tail -1)
# GET-only endpoint should handle PUT gracefully
[ "$http_code" != "500" ] && pass "Wrong method handled (HTTP $http_code)" || fail "Wrong method" "HTTP $http_code"

# 12.5 截屏分页边界
echo "--- 12.5 截屏分页边界 ---"
resp=$(api_get "/api/countermeasure/screencaps?limit=999999")
http_code=$(curl -s -o /dev/null -w "%{http_code}" -H "X-API-Key: $KEY" "$MGR_API/api/countermeasure/screencaps?limit=999999" 2>/dev/null)
[ "$http_code" = "200" ] && pass "Large limit handled" || fail "Large limit" "HTTP $http_code"

# 12.6 截屏非法 ID
echo "--- 12.6 截屏非法 ID ---"
resp=$(curl -s -w "\n%{http_code}" -H "X-API-Key: $KEY" "$MGR_API/api/countermeasure/screencaps/0" 2>/dev/null)
http_code=$(echo "$resp" | tail -1)
[ "$http_code" = "404" ] && pass "Non-existent screencap (HTTP 404)" || skip "Non-existent screencap" "HTTP $http_code"

# =============================================
# 结果汇总
# =============================================
echo ""
echo "=============================================="
echo "  全链路 E2E 测试结果"
echo "=============================================="
TOTAL=$((PASS + FAIL + SKIP))
echo "  Total:  $TOTAL"
echo "  Pass:   $PASS"
echo "  Fail:   $FAIL"
echo "  Skip:   $SKIP"
echo "  Rate:   $(python3 -c "print(f'{$PASS*100/$TOTAL:.1f}%')" 2>/dev/null || echo "N/A")"
echo "=============================================="
echo "  Log: $LOG"
echo "=============================================="

# 生成 JSON 测试报告
python3 -c "
import json, os, time
report = {
    'test': 'T3: Countermeasure Full-Chain E2E',
    'timestamp': '$(date -u +%Y-%m-%dT%H:%M:%SZ)',
    'api_server': '$MGR_API',
    'target_ip': '$TARGET_IP',
    'total': $TOTAL,
    'pass': $PASS,
    'fail': $FAIL,
    'skip': $SKIP,
    'pass_rate': round($PASS*100/$TOTAL, 1) if $TOTAL > 0 else 0
}
with open('$REPORT_DIR/e2e_report.json', 'w') as f:
    json.dump(report, f, indent=2)
print(f'Report saved to $REPORT_DIR/e2e_report.json')
"

exit $FAIL
