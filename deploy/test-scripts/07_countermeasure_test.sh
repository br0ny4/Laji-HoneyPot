#!/bin/bash
# ==========================================
# 07 — 反制效果专项测试
# 测试范围: 触发条件匹配 / 响应速度 / 冷却机制 / 边界场景 / 异常处理
# ==========================================
set -e

MGR_API="http://10.111.31.103:8080"
KEY="hp-admin-2024"
PASS=0; FAIL=0
LOG="/tmp/countermeasure_test.log"

pass() { echo "  [PASS] $1"; ((PASS++)); }
fail() { echo "  [FAIL] $1 — $2"; ((FAIL++)); echo "FAIL: $1 — $2" >> "$LOG"; }

echo "=============================================="
echo "  T2: 反制效果专项测试"
echo "  $(date '+%Y-%m-%d %H:%M:%S')"
echo "=============================================="
echo "" > "$LOG"

# =========================================
# 2.1 Screen Capture — 触发与响应
# =========================================
echo "=== 2.1 Screen Capture Exfil ==="
T1=$(python3 -c "import time; print(int(time.time()*1000))")
resp=$(curl -s -w "\n%{http_code}" -X POST "$MGR_API/api/countermeasure/exfil" \
  -H "Content-Type: application/json" \
  -d '{"type":"screen_capture","target_ip":"10.111.29.4","data_type":"screen_capture","data":{"width":1920,"height":1080,"dpr":2,"captured_at":"2026-07-02T11:00:00Z"}}')
T2=$(python3 -c "import time; print(int(time.time()*1000))")
http_code=$(echo "$resp" | tail -1)
body=$(echo "$resp" | head -1)
latency=$((T2 - T1))

echo "  Latency: ${latency}ms, HTTP: $http_code"
echo "  Response: $body"

echo "$body" | python3 -c "import sys,json; d=json.load(sys.stdin); assert d['status']=='received'" 2>/dev/null && pass "Screen capture received" || fail "Screen capture" "unexpected response"
[ "$latency" -lt 2000 ] && pass "Screen capture latency <2s (${latency}ms)" || fail "Screen capture latency" "${latency}ms >= 2s"
score=$(echo "$body" | python3 -c "import sys,json; d=json.load(sys.stdin); print(d.get('score',0))" 2>/dev/null)
[ "$score" -eq 50 ] && pass "Screen capture score = 50" || fail "Screen capture score" "expected 50, got $score"

# =========================================
# 2.2 File Scan — 触发与敏感文件识别
# =========================================
echo ""
echo "=== 2.2 File Scan Exfil ==="
T1=$(python3 -c "import time; print(int(time.time()*1000))")
resp=$(curl -s -w "\n%{http_code}" -X POST "$MGR_API/api/countermeasure/exfil" \
  -H "Content-Type: application/json" \
  -d '{"type":"file_scan","target_ip":"10.111.29.4","data_type":"file_scan","data":{"tool_dirs":{"burpsuite":"C:\\Tools\\BurpSuite","nmap":"C:\\Tools\\Nmap","metasploit":"C:\\metasploit-framework","cobaltstrike":"/opt/cobaltstrike","hydra":"/usr/bin/hydra"},"sensitive_files":["passwords.txt","config.yaml","id_rsa","token.json","credentials.xml"],"clipboard":"admin:Password123!@#"}}')
T2=$(python3 -c "import time; print(int(time.time()*1000))")
http_code=$(echo "$resp" | tail -1)
body=$(echo "$resp" | head -1)
latency=$((T2 - T1))
echo "  Latency: ${latency}ms, HTTP: $http_code"
echo "  Response: $body"

score=$(echo "$body" | python3 -c "import sys,json; d=json.load(sys.stdin); print(d.get('score',0))" 2>/dev/null)
[ "$score" -eq 30 ] && pass "File scan score = 30" || fail "File scan score" "expected 30, got $score"

# =========================================
# 2.3 Net Probe — 拓扑数据
# =========================================
echo ""
echo "=== 2.3 Net Probe Exfil ==="
T1=$(python3 -c "import time; print(int(time.time()*1000))")
resp=$(curl -s -w "\n%{http_code}" -X POST "$MGR_API/api/countermeasure/exfil" \
  -H "Content-Type: application/json" \
  -d '{"type":"net_probe","target_ip":"10.111.29.4","data_type":"net_probe","data":{"internal_ips":["10.111.29.5","10.111.29.6","192.168.1.100","172.16.0.50"],"peer_assets":[{"ip":"10.111.29.5","open_ports":[22,3389,445,5985],"services":["ssh","rdp","smb","winrm"],"role":"attacker_workstation","confidence":0.88},{"ip":"10.111.29.6","open_ports":[80,443,22,8080],"services":["http","https","ssh","http-proxy"],"role":"command_node","confidence":0.75}]}}')
T2=$(python3 -c "import time; print(int(time.time()*1000))")
http_code=$(echo "$resp" | tail -1)
body=$(echo "$resp" | head -1)
latency=$((T2 - T1))
echo "  Latency: ${latency}ms, HTTP: $http_code"
echo "  Response: $body"

score=$(echo "$body" | python3 -c "import sys,json; d=json.load(sys.stdin); print(d.get('score',0))" 2>/dev/null)
[ "$score" -eq 40 ] && pass "Net probe score = 40" || fail "Net probe score" "expected 40, got $score"

# =========================================
# 2.4 冷却机制 — 边界测试
# =========================================
echo ""
echo "=== 2.4 冷却机制边界测试 ==="

# 2.4.1 同IP同类型立即重复 = 应被冷却
echo "  --- 2.4.1 重复 screen_capture (同IP) ---"
r1=$(curl -s -X POST "$MGR_API/api/countermeasure/exfil" \
  -H "Content-Type: application/json" \
  -d '{"type":"screen_capture","target_ip":"10.100.100.100","data_type":"screen_capture","data":{"width":1920,"height":1080}}')
s1=$(echo "$r1" | python3 -c "import sys,json; d=json.load(sys.stdin); print(d['score'])")
echo "  1st: score=$s1"
[ "$s1" -eq 50 ] && pass "Cooldown-1: 1st screen_capture = 50" || fail "Cooldown-1" "score=$s1"

r2=$(curl -s -X POST "$MGR_API/api/countermeasure/exfil" \
  -H "Content-Type: application/json" \
  -d '{"type":"screen_capture","target_ip":"10.100.100.100","data_type":"screen_capture","data":{"width":1920,"height":1080}}')
s2=$(echo "$r2" | python3 -c "import sys,json; d=json.load(sys.stdin); print(d['score'])")
echo "  2nd (duplicate): score=$s2"
[ "$s2" -eq 0 ] && pass "Cooldown-2: duplicate blocked (score=0)" || fail "Cooldown-2" "score=$s2 (expected 0)"

# 2.4.2 同IP不同类型 = 不应被冷却
echo "  --- 2.4.2 不同类型 (同IP) ---"
r3=$(curl -s -X POST "$MGR_API/api/countermeasure/exfil" \
  -H "Content-Type: application/json" \
  -d '{"type":"file_scan","target_ip":"10.100.100.100","data_type":"file_scan","data":{"tool_dirs":{"nmap":"/usr/bin/nmap"}}}')
s3=$(echo "$r3" | python3 -c "import sys,json; d=json.load(sys.stdin); print(d['score'])")
echo "  file_scan (same IP): score=$s3"
[ "$s3" -eq 30 ] && pass "Cooldown-3: different type not blocked ($s3)" || fail "Cooldown-3" "score=$s3 (expected 30)"

# 2.4.3 不同IP同类型 = 不应被冷却
echo "  --- 2.4.3 不同IP (同类型) ---"
r4=$(curl -s -X POST "$MGR_API/api/countermeasure/exfil" \
  -H "Content-Type: application/json" \
  -d '{"type":"screen_capture","target_ip":"10.200.200.200","data_type":"screen_capture","data":{"width":1920,"height":1080}}')
s4=$(echo "$r4" | python3 -c "import sys,json; d=json.load(sys.stdin); print(d['score'])")
echo "  screen_capture (diff IP): score=$s4"
[ "$s4" -eq 50 ] && pass "Cooldown-4: different IP not blocked ($s4)" || fail "Cooldown-4" "score=$s4 (expected 50)"

# =========================================
# 2.5 异常输入处理
# =========================================
echo ""
echo "=== 2.5 异常输入处理 ==="

# 2.5.1 空类型
echo "  --- 2.5.1 Empty type ---"
r=$(curl -s -w "\n%{http_code}" -X POST "$MGR_API/api/countermeasure/exfil" \
  -H "Content-Type: application/json" \
  -d '{"type":"","target_ip":"10.1.1.1","data_type":"","data":{}}')
code=$(echo "$r" | tail -1)
echo "  HTTP $code"
[ "$code" != "500" ] && pass "Empty type: no 500 crash (HTTP $code)" || fail "Empty type" "HTTP 500 crash"

# 2.5.2 超大 payload
echo "  --- 2.5.2 Large payload (100KB) ---"
bigdata=$(python3 -c "print('x'*102400)")
r=$(curl -s -w "\n%{http_code}" -X POST "$MGR_API/api/countermeasure/exfil" \
  -H "Content-Type: application/json" \
  -d "{\"type\":\"file_scan\",\"target_ip\":\"10.1.1.2\",\"data_type\":\"file_scan\",\"data\":{\"big\":\"$bigdata\"}}" 2>/dev/null)
code=$(echo "$r" | tail -1)
echo "  HTTP $code"
[ "$code" != "500" ] && pass "Large payload: no 500 crash (HTTP $code)" || fail "Large payload" "HTTP 500 crash"

# 2.5.3 非法 JSON
echo "  --- 2.5.3 Invalid JSON ---"
r=$(curl -s -w "\n%{http_code}" -X POST "$MGR_API/api/countermeasure/exfil" \
  -H "Content-Type: application/json" \
  -d 'not-json{{{')
code=$(echo "$r" | tail -1)
echo "  HTTP $code"
[ "$code" = "400" ] && pass "Invalid JSON: HTTP 400 (correct)" || fail "Invalid JSON" "HTTP $code (expected 400)"

# 2.5.4 未知 type
echo "  --- 2.5.4 Unknown type ---"
r=$(curl -s -X POST "$MGR_API/api/countermeasure/exfil" \
  -H "Content-Type: application/json" \
  -d '{"type":"unknown_type_xyz","target_ip":"10.3.3.3","data_type":"unknown_type_xyz","data":{"test":1}}')
score=$(echo "$r" | python3 -c "import sys,json; d=json.load(sys.stdin); print(d.get('score',-1))" 2>/dev/null)
echo "  score=$score"
[ "$score" -ge 0 ] && pass "Unknown type: graceful handling (score=$score)" || fail "Unknown type" "crash or error"

# 2.5.5 GET 模式空数据
echo "  --- 2.5.5 GET empty data ---"
r=$(curl -s -w "\n%{http_code}" "$MGR_API/api/countermeasure/exfil?d=&tt=screen_cap" 2>/dev/null)
code=$(echo "$r" | tail -1)
echo "  HTTP $code"
[ "$code" = "400" ] && pass "GET empty data: HTTP 400" || fail "GET empty data" "HTTP $code (expected 400)"

# 2.5.6 缺少 target_ip
echo "  --- 2.5.6 Missing target_ip ---"
r=$(curl -s -w "\n%{http_code}" -X POST "$MGR_API/api/countermeasure/exfil" \
  -H "Content-Type: application/json" \
  -d '{"type":"screen_capture","data_type":"screen_capture","data":{}}')
code=$(echo "$r" | tail -1)
body=$(echo "$r" | head -1)
echo "  HTTP $code, body: $body"
[ "$code" != "500" ] && pass "Missing target_ip: no crash (HTTP $code)" || fail "Missing target_ip" "HTTP 500 crash"

# =========================================
# 2.6 得分总计验证
# =========================================
echo ""
echo "=== 2.6 得分总计验证 ==="
sb=$(curl -s -H "X-API-Key: $KEY" "$MGR_API/api/countermeasure/scoreboard" 2>/dev/null)
total=$(echo "$sb" | python3 -c "import sys,json; d=json.load(sys.stdin); print(d['total_score'])" 2>/dev/null)
events=$(echo "$sb" | python3 -c "import sys,json; d=json.load(sys.stdin); print(len(d['events']))" 2>/dev/null)
echo "  Total score: $total, Events: $events"
[ "$total" -gt 0 ] 2>/dev/null && pass "Scoreboard has data ($total pts, $events events)" || fail "Scoreboard" "empty"

# =========================================
# 2.7 审计完整性
# =========================================
echo ""
echo "=== 2.7 审计完整性 ==="
audit=$(curl -s -H "X-API-Key: $KEY" "$MGR_API/api/countermeasure/audit" 2>/dev/null)
audit_total=$(echo "$audit" | python3 -c "import sys,json; d=json.load(sys.stdin); print(d['total'])" 2>/dev/null)
sig_ok=$(echo "$audit" | python3 -c "
import sys,json
d = json.load(sys.stdin)
ok = sum(1 for e in d['entries'] if len(e.get('signature','')) == 64)
print(ok)
" 2>/dev/null)
echo "  Audit entries: $audit_total, SHA256 verified: $sig_ok"
[ "$sig_ok" -eq "$audit_total" ] 2>/dev/null && pass "All audit entries SHA256 signed" || fail "Audit SHA256" "$sig_ok/$audit_total"

# =========================================
# 2.8 拓扑图生成
# =========================================
echo ""
echo "=== 2.8 拓扑图验证 ==="
topo=$(curl -s -H "X-API-Key: $KEY" "$MGR_API/api/countermeasure/topology" 2>/dev/null)
team_size=$(echo "$topo" | python3 -c "import sys,json; d=json.load(sys.stdin); print(d.get('team_size',0))" 2>/dev/null)
echo "  Team size: $team_size"
[ "$team_size" -gt 0 ] 2>/dev/null && pass "Topology generated ($team_size nodes)" || fail "Topology" "0 nodes"

# =========================================
echo ""
echo "=============================================="
echo "  T2 反制效果测试完成"
echo "  PASS: $PASS  FAIL: $FAIL"
echo "=============================================="
[ "$FAIL" -gt 0 ] && cat "$LOG"
exit $FAIL
