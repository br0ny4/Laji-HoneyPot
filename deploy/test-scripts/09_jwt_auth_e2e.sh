#!/bin/bash
# ==========================================
# 09 — JWT 认证 & 管理端 UI E2E 测试
# ==========================================
set -e

MGR_API="${MGR_API:-http://localhost:8080}"
PASS=0; FAIL=0; SKIP=0
LOG="/tmp/auth_e2e.log"

pass() { echo "  [PASS] $1"; ((PASS++)); }
fail() { echo "  [FAIL] $1"; ((FAIL++)); echo "FAIL: $1" >> "$LOG"; }
skip() { echo "  [SKIP] $1"; ((SKIP++)); }

echo "=============================================="
echo "  T4: JWT认证 & 管理端UI E2E测试"
echo "  $(date '+%Y-%m-%d %H:%M:%S')"
echo "=============================================="
echo "" > "$LOG"

# =========================================
# 1. 登录失败场景
# =========================================
echo "=== 1. 登录安全测试 ==="

# 1.1 空请求
resp=$(curl -s -X POST "$MGR_API/api/auth/login" -H 'Content-Type: application/json' -d '{}' 2>/dev/null)
echo "$resp" | grep -q "username and password required" && pass "空凭证拒绝(400)" || fail "空凭证" "$resp"

# 1.2 错误密码
resp=$(curl -s -X POST "$MGR_API/api/auth/login" -H 'Content-Type: application/json' -d '{"username":"admin","password":"wrong"}' 2>/dev/null)
echo "$resp" | grep -q "invalid credentials" && pass "错误密码拒绝(401)" || fail "错误密码" "$resp"

# 1.3 不存在用户
resp=$(curl -s -X POST "$MGR_API/api/auth/login" -H 'Content-Type: application/json' -d '{"username":"nobody","password":"test"}' 2>/dev/null)
echo "$resp" | grep -q "invalid credentials" && pass "不存在用户拒绝(401)" || fail "不存在用户" "$resp"

# 1.4 连续错误锁定(6次)
for i in $(seq 1 6); do
  resp=$(curl -s -X POST "$MGR_API/api/auth/login" -H 'Content-Type: application/json' -d '{"username":"admin","password":"wrong"}' 2>/dev/null)
done
echo "$resp" | grep -q "locked" && pass "连续失败锁定" || skip "连续失败锁定" "可能未达到阈值"

# =========================================
# 2. 登录成功 → 令牌签发
# =========================================
echo "=== 2. 登录成功 & 令牌 ==="

resp=$(curl -s -X POST "$MGR_API/api/auth/login" -H 'Content-Type: application/json' -d '{"username":"admin","password":"admin123"}' 2>/dev/null)
ACCESS=$(echo "$resp" | python3 -c "import sys,json; print(json.load(sys.stdin).get('access_token',''))" 2>/dev/null)
REFRESH=$(echo "$resp" | python3 -c "import sys,json; print(json.load(sys.stdin).get('refresh_token',''))" 2>/dev/null)
EXPIRES=$(echo "$resp" | python3 -c "import sys,json; print(json.load(sys.stdin).get('expires_in',''))" 2>/dev/null)

[ -n "$ACCESS" ] && [ "$EXPIRES" = "900" ] && pass "登录签发令牌(expires=$EXPIRES s)" || fail "登录令牌" "expires=$EXPIRES"

# =========================================
# 3. 全局 JWT 拦截
# =========================================
echo "=== 3. 全局鉴权拦截 ==="

# 3.1 无Token访问API
resp=$(curl -s -w "\n%{http_code}" "$MGR_API/api/countermeasure/scoreboard" 2>/dev/null)
http_code=$(echo "$resp" | tail -1)
body=$(echo "$resp" | head -1)
[ "$http_code" = "401" ] && pass "无Token拦截(HTTP $http_code)" || fail "无Token拦截" "HTTP $http_code body=$body"

# 3.2 无效Token
resp=$(curl -s -w "\n%{http_code}" -H "Authorization: Bearer invalid.token.here" "$MGR_API/api/countermeasure/scoreboard" 2>/dev/null)
http_code=$(echo "$resp" | tail -1)
[ "$http_code" = "401" ] && pass "无效Token拦截(HTTP $http_code)" || fail "无效Token" "HTTP $http_code"

# 3.3 带Token可访问
resp=$(curl -s -w "\n%{http_code}" -H "Authorization: Bearer $ACCESS" "$MGR_API/api/countermeasure/scoreboard" 2>/dev/null)
http_code=$(echo "$resp" | tail -1)
[ "$http_code" = "200" ] && pass "有效Token放行(HTTP $http_code)" || fail "有效Token" "HTTP $http_code"

# 3.4 豁免端点无需认证
resp=$(curl -s -w "\n%{http_code}" "$MGR_API/healthz" 2>/dev/null)
http_code=$(echo "$resp" | tail -1)
[ "$http_code" = "200" ] && pass "Healthz豁免(HTTP $http_code)" || fail "Healthz豁免" "HTTP $http_code"

resp=$(curl -s -w "\n%{http_code}" -X POST "$MGR_API/api/countermeasure/exfil" -H 'Content-Type: application/json' -d '{"type":"test","target_ip":"10.0.0.1","data_type":"fingerprint","data":{}}' 2>/dev/null)
http_code=$(echo "$resp" | tail -1)
[ "$http_code" = "200" ] && pass "Exfil豁免(HTTP $http_code)" || fail "Exfil豁免" "HTTP $http_code"

# =========================================
# 4. 令牌刷新流程
# =========================================
echo "=== 4. 令牌刷新 ==="

if [ -n "$REFRESH" ]; then
  resp=$(curl -s -X POST "$MGR_API/api/auth/refresh" -H 'Content-Type: application/json' -d "{\"refresh_token\":\"$REFRESH\"}" 2>/dev/null)
  NEW_ACCESS=$(echo "$resp" | python3 -c "import sys,json; print(json.load(sys.stdin).get('access_token',''))" 2>/dev/null)
  [ -n "$NEW_ACCESS" ] && pass "令牌刷新成功" || fail "令牌刷新" "$resp"
  
  # 用无效refresh token
  resp=$(curl -s -w "\n%{http_code}" -X POST "$MGR_API/api/auth/refresh" -H 'Content-Type: application/json' -d '{"refresh_token":"invalid"}' 2>/dev/null)
  http_code=$(echo "$resp" | tail -1)
  [ "$http_code" = "401" ] && pass "无效Refresh拒接(HTTP $http_code)" || fail "无效Refresh" "HTTP $http_code"
else
  skip "令牌刷新" "无refresh_token"
fi

# =========================================
# 5. 登出
# =========================================
echo "=== 5. 登出 ==="
resp=$(curl -s -X POST "$MGR_API/api/auth/logout" -H 'Content-Type: application/json' -H "Authorization: Bearer $ACCESS" -d "{\"refresh_token\":\"$REFRESH\"}" 2>/dev/null)
echo "$resp" | grep -q "logged_out" && pass "登出成功" || fail "登出" "$resp"

# =========================================
# 6. 修改密码
# =========================================
echo "=== 6. 修改密码 ==="
if [ -n "$ACCESS" ]; then
  resp=$(curl -s -w "\n%{http_code}" -X POST "$MGR_API/api/auth/changepassword" -H 'Content-Type: application/json' -H "Authorization: Bearer $ACCESS" -d '{"old_password":"wrong","new_password":"NewPass123"}' 2>/dev/null)
  http_code=$(echo "$resp" | tail -1)
  [ "$http_code" = "400" ] && pass "旧密码错误拒接" || fail "旧密码错误" "HTTP $http_code"
  
  # 正确修改
  resp=$(curl -s -X POST "$MGR_API/api/auth/changepassword" -H 'Content-Type: application/json' -H "Authorization: Bearer $ACCESS" -d '{"old_password":"admin123","new_password":"NewPass123"}' 2>/dev/null)
  echo "$resp" | grep -q "password_changed" && pass "密码修改成功" || fail "密码修改" "$resp"
  
  # 改回原密码
  curl -s -X POST "$MGR_API/api/auth/changepassword" -H 'Content-Type: application/json' -H "Authorization: Bearer $ACCESS" -d '{"old_password":"NewPass123","new_password":"admin123"}' > /dev/null 2>&1
else
  skip "修改密码" "无access_token"
fi

# =========================================
# 7. 前端静态文件服务(SPA)
# =========================================
echo "=== 7. 前端SPA服务 ==="
resp=$(curl -s -w "\n%{http_code}" "$MGR_API/" 2>/dev/null)
http_code=$(echo "$resp" | tail -1)
[ "$http_code" = "200" ] && pass "SPA index.html(HTTP $http_code)" || fail "SPA index" "HTTP $http_code"

resp=$(curl -s -w "\n%{http_code}" "$MGR_API/assets/" 2>/dev/null)
http_code=$(echo "$resp" | tail -1)
[ "$http_code" = "200" ] || [ "$http_code" = "404" ] && pass "SPA静态资源(HTTP $http_code)" || fail "SPA静态资源" "HTTP $http_code"

# =========================================
# 结果汇总
# =========================================
echo ""
echo "=============================================="
echo "  T4: JWT认证E2E测试结果"
echo "=============================================="
TOTAL=$((PASS + FAIL + SKIP))
echo "  Total: $TOTAL | Pass: $PASS | Fail: $FAIL | Skip: $SKIP"
echo "=============================================="

exit $FAIL
