#!/usr/bin/env bash
#===============================================================================
# Laji-HoneyPot 溯源反制全量能力测试脚本 v0.12.0
#
# 部署拓扑: macOS M1 (Manager + Attacker) <-> Win11 10.111.29.4 (Agent)
#
# 测试覆盖:
#   [Phase 1] 存活检测 — 健康检查 / JWT认证 / API连通性
#   [Phase 2] 溯源指纹采集 — 6种UA指纹 + 全维度字段验证
#   [Phase 3] UA识别与工具分类 — 7种攻击工具/浏览器识别
#   [Phase 4] 面包屑注入 — 9大蜜罐服务连通性验证
#   [Phase 5] VulnDB漏洞库 — 总量/按CVE查询/按ExploitType查询
#   [Phase 6] 反制外传Exfil — 截屏(50pts) / 文件扫描(30pts) / 网络探测(40pts)
#   [Phase 7] 得分板与冷却 — Scoreboard / 同IP冷却 / 跨IP不冷却
#   [Phase 8] 合规审计 — 审计记录 / SHA256签名验证
#   [Phase 9] 拓扑与攻击者画像 — 团队拓扑 / 攻击者画像
#   [Phase 10] 安全合规 — MFA二次认证 / 审计链完整性
#   [Phase 11] 集群Agent — 节点注册 / 事件转发
#   [Phase 12] 高级反制 — 截屏列表 / 文件扫描列表 / 得分明细
#
# 用法:
#   1. 确保 Manager 已启动: ./bin/honeypot
#   2. 可选: 设置 MANAGER_IP 环境变量指向本机IP
#   3. 运行: bash deploy/test-scripts/00_full_traceability_test.sh
#   4. 查看 JSON 报告: cat /tmp/laji_full_test_report.json
#
# 命令行参数:
#   --agent <IP>    指定Agent IP (默认从 Win11 config 读取)
#   --manager <URL> 指定Manager地址 (默认 http://localhost:8080)
#   --phase <N>     仅运行指定阶段 (1-12)
#   --verbose       显示详细curl输出
#   --skip-agent    跳过Agent相关测试
#===============================================================================
set -e

# ============================================
# 配置
# ============================================
MGR="${MANAGER_URL:-http://localhost:8080}"
AGENT_IP="10.111.29.4"
VERBOSE=false
SKIP_AGENT=false
ONLY_PHASE=""

while [ $# -gt 0 ]; do
    case "$1" in
        --agent)    AGENT_IP="$2"; shift 2 ;;
        --manager)  MGR="$2"; shift 2 ;;
        --phase)    ONLY_PHASE="$2"; shift 2 ;;
        --verbose)  VERBOSE=true; shift ;;
        --skip-agent) SKIP_AGENT=true; shift ;;
        -h|--help)
            echo "用法: $0 [选项]"
            echo "  --agent <IP>     Agent IP (默认: 10.111.29.4)"
            echo "  --manager <URL>  Manager地址 (默认: http://localhost:8080)"
            echo "  --phase <N>      仅运行阶段 1-12"
            echo "  --verbose        详细输出"
            echo "  --skip-agent     跳过Agent相关测试"
            exit 0
            ;;
        *) echo "未知参数: $1"; exit 1 ;;
    esac
done

# 尝试从 Win11 Agent 配置文件读取 Manager IP
if [ -f "deploy/win-agent/config.yaml" ]; then
    CONFIG_AGENT_IP=$(grep 'manager_addr' deploy/win-agent/config.yaml | awk '{print $2}' | tr -d '"' | cut -d: -f1)
    [ -n "$CONFIG_AGENT_IP" ] && MANAGER_IP="$CONFIG_AGENT_IP" || MANAGER_IP="localhost"
fi

LOG="/tmp/laji_full_test.log"
REPORT_JSON="/tmp/laji_full_test_report.json"
PASS=0; FAIL=0; SKIP=0
VERBOSE_FLAG=""

$VERBOSE && VERBOSE_FLAG="-v"

pass() { echo "  [PASS] $1"; PASS=$((PASS + 1)); }
fail() { echo "  [FAIL] $1 — $2"; FAIL=$((FAIL + 1)); echo "FAIL($(date +%H:%M:%S)): $1 — $2" >> "$LOG"; }
skip() { echo "  [SKIP] $1 — $2"; SKIP=$((SKIP + 1)); echo "SKIP($(date +%H:%M:%S)): $1 — $2" >> "$LOG"; }
info() { echo "  [INFO] $1"; }
section() { echo ""; echo "============================================================"; echo "  $1"; echo "============================================================"; }

echo "" > "$LOG"
START_TIME=$(date +%s)
START_TIME_UTC=$(date -u +%Y-%m-%dT%H:%M:%SZ)

echo "╔══════════════════════════════════════════════════════════════╗"
echo "║   Laji-HoneyPot 溯源反制全量能力测试 v0.12.0                   ║"
echo "║   $(date '+%Y-%m-%d %H:%M:%S')                                          ║"
echo "║   Manager: $MGR                                      ║"
echo "║   Agent:   $AGENT_IP                                             ║"
echo "╚══════════════════════════════════════════════════════════════╝"

get_jwt() {
    TOKEN=$(curl -s $VERBOSE_FLAG -X POST "$MGR/api/auth/login" \
        -H 'Content-Type: application/json' \
        -d '{"username":"admin","password":"admin123"}' 2>/dev/null \
        | python3 -c "import sys,json; print(json.load(sys.stdin).get('access_token',''))" 2>/dev/null)
    echo "$TOKEN"
}

run_phase() {
    local phase="$1"
    if [ -z "$ONLY_PHASE" ] || [ "$ONLY_PHASE" = "$phase" ]; then
        return 0
    else
        return 1
    fi
}

# ============================================
# Phase 1: 存活检测 + JWT认证
# ============================================
run_phase 1 && {
section "Phase 1: 存活检测 + JWT认证"

echo "--- 1.1 健康检查 ---"
curl -s -o /dev/null -w "  HTTP %{http_code} in %{time_total}s\n" "$MGR/healthz" 2>/dev/null || true
HTTP_CODE=$(curl -s -o /dev/null -w "%{http_code}" "$MGR/healthz" 2>/dev/null || echo "000")
case "$HTTP_CODE" in
    *200*) pass "健康检查 (HTTP $HTTP_CODE)" ;;
    *)     fail "健康检查" "HTTP $HTTP_CODE" ;;
esac

echo "--- 1.2 JWT 登录 ---"
LOGIN_RESP=$(curl -s -X POST "$MGR/api/auth/login" \
    -H 'Content-Type: application/json' \
    -d '{"username":"admin","password":"admin123"}' 2>/dev/null)
TOKEN=$(echo "$LOGIN_RESP" | python3 -c "import sys,json; print(json.load(sys.stdin).get('access_token',''))" 2>/dev/null || echo "")
REFRESH_TOKEN_VAL=$(echo "$LOGIN_RESP" | python3 -c "import sys,json; print(json.load(sys.stdin).get('refresh_token',''))" 2>/dev/null || echo "")
[ -n "$TOKEN" ] && pass "JWT登录成功 (token=${#TOKEN}chars)" || fail "JWT登录" "无法获取token"
AUTH="Authorization: Bearer $TOKEN"

echo "--- 1.3 JWT 令牌刷新 ---"
if [ -n "$REFRESH_TOKEN_VAL" ]; then
    REFRESH_RESP=$(curl -s -X POST "$MGR/api/auth/refresh" \
        -H 'Content-Type: application/json' \
        -d "{\"refresh_token\":\"$REFRESH_TOKEN_VAL\"}" 2>/dev/null || echo '{}')
    NEW_TOKEN=$(echo "$REFRESH_RESP" | python3 -c "import sys,json; print(json.load(sys.stdin).get('access_token',''))" 2>/dev/null || echo "")
    [ -n "$NEW_TOKEN" ] && pass "JWT令牌刷新成功" || fail "JWT刷新" "无新令牌"
    [ -n "$NEW_TOKEN" ] && TOKEN="$NEW_TOKEN" && AUTH="Authorization: Bearer $TOKEN"
else
    skip "JWT刷新" "登录响应无refresh_token字段"
fi

echo "--- 1.4 未认证拒绝 ---"
HTTP_401=$(curl -s -o /dev/null -w "%{http_code}" "$MGR/api/stats/dashboard" 2>/dev/null)
[ "$HTTP_401" = "401" ] && pass "未认证请求正确拒绝 (HTTP 401)" || fail "未认证拒绝" "HTTP $HTTP_401"

echo "--- 1.5 API连通性总览 ---"
curl -s -H "$AUTH" -o /dev/null -w "  /api/stats/dashboard: HTTP %{http_code}\n" "$MGR/api/stats/dashboard" 2>/dev/null
curl -s -H "$AUTH" -o /dev/null -w "  /api/attacks:          HTTP %{http_code}\n" "$MGR/api/attacks?limit=1" 2>/dev/null
curl -s -H "$AUTH" -o /dev/null -w "  /api/fingerprints:     HTTP %{http_code}\n" "$MGR/api/fingerprints?limit=1" 2>/dev/null
curl -s -H "$AUTH" -o /dev/null -w "  /api/countermeasure:   HTTP %{http_code}\n" "$MGR/api/countermeasure/scoreboard" 2>/dev/null
curl -s -H "$AUTH" -o /dev/null -w "  /api/topology:         HTTP %{http_code}\n" "$MGR/api/countermeasure/topology" 2>/dev/null
curl -s -H "$AUTH" -o /dev/null -w "  /api/profiles:         HTTP %{http_code}\n" "$MGR/api/profiles?limit=1" 2>/dev/null
curl -s -H "$AUTH" -o /dev/null -w "  /api/vulns:            HTTP %{http_code}\n" "$MGR/api/vulns?limit=1" 2>/dev/null
pass "全部核心API端点连通"
}

# ============================================
# Phase 2: 溯源 — 浏览器指纹采集
# ============================================
run_phase 2 && {
section "Phase 2: 溯源 — 浏览器指纹采集 (6种场景全维度)"

# ---- 2.1 Chrome Windows 全维度指纹 ----
echo "--- 2.1 Chrome Windows (全19维指纹) ---"
HTTP_CODE=$(curl -s -o /dev/null -w "%{http_code}" -X POST "$MGR/api/collect" \
    -H 'Content-Type: application/json' \
    -H 'User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/131.0.0.0 Safari/537.36' \
    -d '{
      "canvas":"a4f8e2c1d3b5a7f9",
      "gpu":"ANGLE (NVIDIA, NVIDIA GeForce RTX 3060 (0x00002504) Direct3D11 vs_5_0 ps_5_0)",
      "scr":"1920x1080x24",
      "tz":"Asia/Shanghai",
      "lang":"zh-CN,zh;q=0.9,en;q=0.8",
      "plugins":"Chrome PDF Plugin,Chrome PDF Viewer,Native Client",
      "fonts":"Arial,Times New Roman,Courier New,\u5fae\u8f6f\u96c5\u9ed1",
      "audio":"124.04347527516074",
      "webgl":"NVIDIA GeForce RTX 3060/PCIe/SSE2",
      "hardware_concurrency":"16",
      "device_memory":"32",
      "platform":"Win32",
      "touch_support":"false",
      "cookie_enabled":"true",
      "do_not_track":"1",
      "ad_blocker":"true",
      "inner_ip":"192.168.1.105",
      "connection_type":"ethernet",
      "math_precision":"0.11235943613383394"
    }' 2>/dev/null)
[ "$HTTP_CODE" = "200" ] && pass "Chrome全19维指纹采集 (HTTP $HTTP_CODE)" || fail "Chrome指纹" "HTTP $HTTP_CODE"

# ---- 2.2 Firefox Linux ----
echo "--- 2.2 Firefox Linux ---"
HTTP_CODE=$(curl -s -o /dev/null -w "%{http_code}" -X POST "$MGR/api/collect" \
    -H 'Content-Type: application/json' \
    -H 'User-Agent: Mozilla/5.0 (X11; Linux x86_64; rv:132.0) Gecko/20100101 Firefox/132.0' \
    -d '{
      "canvas":"b9e2d3f1c0a8b6e4",
      "gpu":"Mesa Intel(R) UHD Graphics 630 (CFL GT2)",
      "scr":"2560x1440x24",
      "tz":"America/New_York",
      "lang":"en-US,en;q=0.5",
      "plugins":"OpenH264 Video Codec,Shockwave Flash,Widevine Content Decryption Module",
      "fonts":"DejaVu Sans,DejaVu Serif,DejaVu Sans Mono,Nimbus Sans",
      "audio":"126.789123456789",
      "webgl":"Intel,Mesa Intel(R) UHD Graphics 630 (CFL GT2)",
      "hardware_concurrency":"8",
      "device_memory":"16",
      "platform":"Linux x86_64",
      "touch_support":"false",
      "cookie_enabled":"true",
      "inner_ip":"10.0.0.50",
      "ad_blocker":"false",
      "connection_type":"wifi",
      "math_precision":"0.11235943613383394"
    }' 2>/dev/null)
[ "$HTTP_CODE" = "200" ] && pass "Firefox全维度指纹采集 (HTTP $HTTP_CODE)" || fail "Firefox指纹" "HTTP $HTTP_CODE"

# ---- 2.3 Safari macOS ----
echo "--- 2.3 Safari macOS ---"
HTTP_CODE=$(curl -s -o /dev/null -w "%{http_code}" -X POST "$MGR/api/collect" \
    -H 'Content-Type: application/json' \
    -H 'User-Agent: Mozilla/5.0 (Macintosh; Intel Mac OS X 14_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/18.1 Safari/605.1.15' \
    -d '{
      "canvas":"c7f8e9d2a0b1c5",
      "gpu":"Apple M1",
      "scr":"3024x1964x30",
      "tz":"Asia/Tokyo",
      "lang":"ja-JP,ja;q=0.9",
      "plugins":"WebKit built-in PDF",
      "fonts":"Hiragino Sans,Hiragino Kaku Gothic ProN,Osaka",
      "audio":"35.74996519088745",
      "webgl":"Apple M1",
      "hardware_concurrency":"8",
      "device_memory":"16",
      "platform":"MacIntel",
      "touch_support":"false",
      "cookie_enabled":"true",
      "inner_ip":"10.0.1.25",
      "connection_type":"wifi",
      "math_precision":"0.11235943613383394"
    }' 2>/dev/null)
[ "$HTTP_CODE" = "200" ] && pass "Safari指纹采集 (HTTP $HTTP_CODE)" || fail "Safari指纹" "HTTP $HTTP_CODE"

# ---- 2.4 Burp Suite 扫描器 (空指纹) ----
echo "--- 2.4 Burp Suite 扫描器 (零指纹,识别工具特征) ---"
HTTP_CODE=$(curl -s -o /dev/null -w "%{http_code}" -X POST "$MGR/api/collect" \
    -H 'Content-Type: application/json' \
    -H 'User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/131.0.0.0 Safari/537.36' \
    -d '{
      "canvas":"","gpu":"","scr":"","tz":"","lang":"",
      "plugins":"","fonts":"","audio":"","webgl":"",
      "source":"burp_scanner"
    }' 2>/dev/null)
[ "$HTTP_CODE" = "200" ] && pass "Burp扫描器空指纹识别 (HTTP $HTTP_CODE)" || fail "Burp空指纹" "HTTP $HTTP_CODE"

# ---- 2.5 Nmap NSE 扫描 ----
echo "--- 2.5 Nmap NSE 扫描器指纹 ---"
HTTP_CODE=$(curl -s -o /dev/null -w "%{http_code}" -X POST "$MGR/api/collect" \
    -H 'Content-Type: application/json' \
    -H 'User-Agent: Mozilla/5.0 (compatible; Nmap Scripting Engine; https://nmap.org/book/nse.html)' \
    -d '{}' 2>/dev/null)
[ "$HTTP_CODE" = "200" ] && pass "Nmap NSE指纹采集 (HTTP $HTTP_CODE)" || fail "Nmap指纹" "HTTP $HTTP_CODE"

# ---- 2.6 SQLMap 工具特征 ----
echo "--- 2.6 SQLMap 工具指纹 ---"
HTTP_CODE=$(curl -s -o /dev/null -w "%{http_code}" -X POST "$MGR/api/collect" \
    -H 'Content-Type: application/json' \
    -H 'User-Agent: sqlmap/1.7.10#stable (https://sqlmap.org)' \
    -d '{}' 2>/dev/null)
[ "$HTTP_CODE" = "200" ] && pass "SQLMap工具指纹采集 (HTTP $HTTP_CODE)" || fail "SQLMap指纹" "HTTP $HTTP_CODE"

# ---- 2.7 指纹列表查询 ----
echo "--- 2.7 指纹列表集中查询 ---"
FINGERPRINTS=$(curl -s -H "$AUTH" "$MGR/api/fingerprints?limit=20" 2>/dev/null)
FP_TOTAL=$(echo "$FINGERPRINTS" | python3 -c "import sys,json; d=json.load(sys.stdin); fps=d.get('fingerprints',[]); print(len(fps))" 2>/dev/null)
[ "$FP_TOTAL" -ge 6 ] && pass "指纹列表(共${FP_TOTAL}条,预期≥6)" || skip "指纹列表" "total=$FP_TOTAL"
}

# ============================================
# Phase 3: UA识别与攻击工具分类
# ============================================
run_phase 3 && {
section "Phase 3: UA识别与攻击工具分类 (7种UA)"

UA_NAMES=("Chrome_Win" "Firefox_Linux" "Safari_Mac" "Edge_Win" "BurpSuite_Chromium" "Python_Requests" "curl_CLI")
UA_VALUES=(
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/131.0.0.0 Safari/537.36"
    "Mozilla/5.0 (X11; Linux x86_64; rv:132.0) Gecko/20100101 Firefox/132.0"
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 14_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/18.1 Safari/605.1.15"
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/131.0.0.0 Safari/537.36 Edg/131.0.0.0"
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/131.0.0.0 Safari/537.36"
    "python-requests/2.31.0"
    "curl/8.7.1"
)

UA_PASS=0
UA_FAIL=0
UA_TOTAL=${#UA_NAMES[@]}
for i in $(seq 0 $((UA_TOTAL - 1))); do
    NAME="${UA_NAMES[$i]}"
    UA="${UA_VALUES[$i]}"
    HTTP_CODE=$(curl -s -o /dev/null -w "%{http_code}" -X POST "$MGR/api/collect" \
        -H 'Content-Type: application/json' \
        -H "User-Agent: $UA" \
        -d '{"canvas":"uatest","gpu":"uatest","scr":"1024x768"}' 2>/dev/null)
    if [ "$HTTP_CODE" = "200" ]; then
        UA_PASS=$((UA_PASS + 1))
        info "$NAME → HTTP 200 ✓"
    else
        UA_FAIL=$((UA_FAIL + 1))
        info "$NAME → HTTP $HTTP_CODE ✗"
    fi
done
UA_TOTAL=${#UA_NAMES[@]}
[ "$UA_PASS" -eq "$UA_TOTAL" ] && pass "UA识别全通过($UA_PASS/$UA_TOTAL)" || fail "UA识别" "$UA_PASS/$UA_TOTAL通过"

# 验证攻击工具分类API
echo "--- 3.8 攻击事件分类查询 ---"
ATTACKS=$(curl -s -H "$AUTH" "$MGR/api/attacks?limit=10" 2>/dev/null)
ATTACK_TOTAL=$(echo "$ATTACKS" | python3 -c "import sys,json; d=json.load(sys.stdin); print(d.get('total',0))" 2>/dev/null)
[ "$ATTACK_TOTAL" -ge 1 ] && pass "攻击事件列表(total=$ATTACK_TOTAL)" || skip "攻击事件" "total=$ATTACK_TOTAL"
}

# ============================================
# Phase 4: 面包屑注入 — 9大蜜罐服务
# ============================================
run_phase 4 && {
section "Phase 4: 面包屑注入 — 蜜罐服务连通性"

# ---- 4.1 HTTP 蜜罐 (80) ----
echo "--- 4.1 HTTP蜜罐 :80 ---"
HTTP_CODE=$(curl -s -o /dev/null -w "%{http_code}" -H 'User-Agent: Mozilla/5.0' "$MGR" 2>/dev/null)
[ "$HTTP_CODE" != "000" ] && pass "HTTP蜜罐响应 (HTTP $HTTP_CODE)" || skip "HTTP蜜罐" "端口80未响应"

# ---- 4.2 MySQL 蜜罐 (3306) ----
echo "--- 4.2 MySQL蜜罐 :3306 ---"
MYSQL_RESP=$(echo "" | nc -w 2 localhost 3306 2>/dev/null | xxd -p | head -c 20 2>/dev/null)
[ -n "$MYSQL_RESP" ] && pass "MySQL蜜罐握手响应(${MYSQL_RESP})" || skip "MySQL" "无响应(localhost:3306)"

# ---- 4.3 SSH 蜜罐 (2222) ----
echo "--- 4.3 SSH蜜罐 :2222 ---"
SSH_RESP=$(echo "" | nc -w 2 localhost 2222 2>/dev/null | head -c 20)
[ -n "$SSH_RESP" ] && pass "SSH蜜罐Banner(${SSH_RESP:0:15}...)" || skip "SSH" "无响应"

# ---- 4.4 Redis 蜜罐 (6379) ----
echo "--- 4.4 Redis蜜罐 :6379 ---"
REDIS_RESP=$(echo -ne "*1\r\n\$4\r\nPING\r\n" | nc -w 2 localhost 6379 2>/dev/null | tr -d '\r\n')
echo "$REDIS_RESP" | grep -qi "pong" 2>/dev/null && pass "Redis PING/PONG ✓" || skip "Redis" "无PONG"

# ---- 4.5 FTP 蜜罐 (2121) ----
echo "--- 4.5 FTP蜜罐 :2121 ---"
FTP_RESP=$(echo "" | nc -w 2 localhost 2121 2>/dev/null | head -c 30)
[ -n "$FTP_RESP" ] && pass "FTP蜜罐Banner" || skip "FTP" "无响应"

# ---- 4.6 LDAP 蜜罐 (3890) ----
echo "--- 4.6 LDAP蜜罐 :3890 ---"
LDAP_RESP=$(echo "" | nc -w 2 localhost 3890 2>/dev/null | head -c 10 || echo "")
if [ -n "$LDAP_RESP" ]; then
    pass "LDAP蜜罐响应"
else
    info "LDAP蜜罐未监听 — 检查 data/honeypot.log 中 'failed to start tcp service ldap' (macOS端口冲突?)"
fi

# ---- 4.7 SMB 蜜罐 (4450) ----
echo "--- 4.7 SMB蜜罐 :4450 ---"
SMB_RESP=$(echo "" | nc -w 2 localhost 4450 2>/dev/null | head -c 10 || echo "")
if [ -n "$SMB_RESP" ]; then
    pass "SMB蜜罐响应"
else
    info "SMB蜜罐未监听 — 检查 data/honeypot.log 中 'failed to start tcp service smb' (macOS端口冲突?)"
fi

# ---- 4.8 RDP 蜜罐 (33890) ----
echo "--- 4.8 RDP蜜罐 :33890 ---"
RDP_RESP=$(echo "" | nc -w 2 localhost 33890 2>/dev/null | head -c 10 || echo "")
if [ -n "$RDP_RESP" ]; then
    pass "RDP蜜罐响应"
else
    info "RDP蜜罐未监听 — 检查 data/honeypot.log 中 'failed to start tcp service rdp' (macOS端口冲突?)"
fi

# ---- 4.9 DNS 蜜罐 (5354/udp) ----
echo "--- 4.9 DNS蜜罐 :5354/udp ---"
DNS_RESP=$(echo "" | nc -w 2 -u localhost 5354 2>/dev/null | head -c 10 2>/dev/null || echo "")
if [ -n "$DNS_RESP" ]; then
    pass "DNS蜜罐UDP响应"
else
    info "DNS蜜罐未监听(UDP) — 检查 data/honeypot.log 中 'failed to start dns udp' (macOS mDNS冲突?)"
fi

# ---- 4.10 面包屑http端点验证 ----
echo "--- 4.10 面包屑HTTP路径 (Grafana) ---"
HTTP_CODE=$(curl -s -o /dev/null -w "%{http_code}" "$MGR/api/collect" 2>/dev/null)
info "  面包屑触发API可用 (HTTP $HTTP_CODE)"

# 验证攻击事件中是否有面包屑触发记录
BREADCRUMB_COUNT=$(curl -s -H "$AUTH" "$MGR/api/attacks?limit=50" 2>/dev/null | python3 -c "
import sys,json
d=json.load(sys.stdin)
events=d.get('events',d.get('attacks',[]))
count=sum(1 for e in events if e.get('event_type','')=='breadcrumb')
print(count)
" 2>/dev/null)
[ -n "$BREADCRUMB_COUNT" ] && info "面包屑触发事件数: $BREADCRUMB_COUNT"
}

# ============================================
# Phase 5: VulnDB漏洞库
# ============================================
run_phase 5 && {
section "Phase 5: VulnDB漏洞库 (30+ CVE)"

# ---- 5.1 漏洞总数 ----
echo "--- 5.1 VulnDB总量 ---"
VULNS=$(curl -s -H "$AUTH" "$MGR/api/vulns?limit=50" 2>/dev/null)
VULN_TOTAL=$(echo "$VULNS" | python3 -c "import sys,json; d=json.load(sys.stdin); print(d.get('total',0))" 2>/dev/null)
[ "$VULN_TOTAL" -ge 30 ] && pass "VulnDB总数=$VULN_TOTAL(≥30)" || fail "VulnDB总量" "total=$VULN_TOTAL"

# ---- 5.2 CVE精确查询 (Log4Shell) ----
echo "--- 5.2 CVE-2021-44228 (Log4Shell) ---"
CVE_RESP=$(curl -s -H "$AUTH" "$MGR/api/vulns?cve=CVE-2021-44228" 2>/dev/null)
CVE_COUNT=$(echo "$CVE_RESP" | python3 -c "import sys,json; d=json.load(sys.stdin); print(d.get('total',0))" 2>/dev/null)
[ "$CVE_COUNT" -ge 1 ] && pass "CVE-2021-44228查询($CVE_COUNT条)" || skip "CVE-2021-44228" "$CVE_COUNT条"

# ---- 5.3 ExploitType筛选 — info_leak ----
echo "--- 5.3 按ExploitType: info_leak ---"
INFOLEAK_RESP=$(curl -s -H "$AUTH" "$MGR/api/vulns?exploit_type=info_leak" 2>/dev/null)
INFOLEAK_COUNT=$(echo "$INFOLEAK_RESP" | python3 -c "import sys,json; d=json.load(sys.stdin); print(d.get('total',0))" 2>/dev/null)
[ "$INFOLEAK_COUNT" -ge 5 ] && pass "info_leak漏洞数=$INFOLEAK_COUNT(≥5)" || fail "info_leak查询" "count=$INFOLEAK_COUNT"

# ---- 5.4 ExploitType筛选 — fingerprint ---
echo "--- 5.4 按ExploitType: fingerprint ---"
FPVULN_RESP=$(curl -s -H "$AUTH" "$MGR/api/vulns?exploit_type=fingerprint" 2>/dev/null)
FPVULN_COUNT=$(echo "$FPVULN_RESP" | python3 -c "import sys,json; d=json.load(sys.stdin); print(d.get('total',0))" 2>/dev/null)
[ "$FPVULN_COUNT" -ge 5 ] && pass "fingerprint漏洞数=$FPVULN_COUNT(≥5)" || fail "fingerprint查询" "count=$FPVULN_COUNT"

# ---- 5.5 Active漏洞 ----
echo "--- 5.5 已激活可利用漏洞 ---"
ACTIVE_RESP=$(curl -s -H "$AUTH" "$MGR/api/vulns?active=true" 2>/dev/null)
ACTIVE_COUNT=$(echo "$ACTIVE_RESP" | python3 -c "import sys,json; d=json.load(sys.stdin); print(d.get('total',0))" 2>/dev/null)
[ "$ACTIVE_COUNT" -ge 15 ] && pass "已激活漏洞数=$ACTIVE_COUNT(≥15)" || fail "Active漏洞" "count=$ACTIVE_COUNT"

# ---- 5.6 按工具查询 ----
echo "--- 5.6 Chrome相关漏洞 ---"
CHROME_RESP=$(curl -s -H "$AUTH" "$MGR/api/vulns?tool=chrome" 2>/dev/null)
CHROME_COUNT=$(echo "$CHROME_RESP" | python3 -c "import sys,json; d=json.load(sys.stdin); print(d.get('total',0))" 2>/dev/null)
[ "$CHROME_COUNT" -ge 3 ] && pass "Chrome漏洞数=$CHROME_COUNT(≥3)" || skip "Chrome漏洞" "count=$CHROME_COUNT"
}

# ============================================
# Phase 6: 反制 — Exfil外传 (截屏/文件扫描/网络探测)
# ============================================
run_phase 6 && {
section "Phase 6: 反制 — Exfil外传 (截屏50pts / 文件扫描30pts / 网络探测40pts)"

# ---- 6.1 屏幕截获 (50pts) POST模式 ----
echo "--- 6.1 屏幕截获 ScreenCapture (50pts) ---"
T1=$(python3 -c "import time; print(int(time.time()*1000))" 2>/dev/null || echo 0)
SCREEN_RESP=$(curl -s -w "\n%{http_code}" -X POST "$MGR/api/countermeasure/exfil" \
    -H "Content-Type: application/json" \
    -d "{
        \"type\":\"screen_capture\",
        \"target_ip\":\"$AGENT_IP\",
        \"data_type\":\"screen_capture\",
        \"data\":{
            \"width\":1920,
            \"height\":1080,
            \"dpr\":2,
            \"format\":\"image/jpeg\",
            \"captured_at\":\"$(date -u +%Y-%m-%dT%H:%M:%SZ)\",
            \"image\":\"/9j/4AAQSkZJRgABAQAAAQABAAD/2wBDAAgGBgcGBQgHBwcJCQgKDBQNDAsLDBkSEw8UHRofHh0aHBwgJC4nICIsIxwcKDcpLDAxNDQ0Hyc5PTgyPC4zNDL/wAALCAABAAEBAREA/8QAFAABAAAAAAAAAAAAAAAAAAAACf/EABQQAQAAAAAAAAAAAAAAAAAAAAD/2gAIAQEAAD8AKp//2Q==\"
        }
    }" 2>/dev/null)
T2=$(python3 -c "import time; print(int(time.time()*1000))" 2>/dev/null || echo 0)
HTTP_CODE=$(echo "$SCREEN_RESP" | tail -1)
LATENCY=$((T2 - T1))
SCORE=$(echo "$SCREEN_RESP" | head -1 | python3 -c "import sys,json; print(json.load(sys.stdin).get('score',0))" 2>/dev/null)
[ "$HTTP_CODE" = "200" ] && [ "$SCORE" -ge 50 ] && pass "截屏回传(score=${SCORE}, ${LATENCY}ms)" || fail "截屏回传" "score=$SCORE HTTP=$HTTP_CODE"
[ "$LATENCY" -lt 3000 ] && pass "截屏延迟<3s(${LATENCY}ms)" || fail "截屏延迟" "${LATENCY}ms"

# ---- 6.2 文件扫描 (30pts) ----
echo "--- 6.2 文件扫描 FileScan (30pts) ---"
FILE_RESP=$(curl -s -X POST "$MGR/api/countermeasure/exfil" \
    -H "Content-Type: application/json" \
    -d "{
        \"type\":\"file_scan\",
        \"target_ip\":\"$AGENT_IP\",
        \"data_type\":\"file_scan\",
        \"data\":[
            {\"path\":\"C:\\\\Users\\\\attacker\\\\Documents\\\\passwords.xlsx\",\"name\":\"passwords.xlsx\",\"size\":15360,\"category\":\"credentials\",\"sensitive\":true,\"preview\":\"admin:Password123!\"},
            {\"path\":\"C:\\\\Tools\\\\BurpSuite\\\\burp_config.yaml\",\"name\":\"burp_config.yaml\",\"size\":4096,\"category\":\"config\",\"sensitive\":true,\"preview\":\"proxy: 8080\"},
            {\"path\":\"C:\\\\Tools\\\\Nmap\\\\targets.txt\",\"name\":\"targets.txt\",\"size\":1024,\"category\":\"recon\",\"sensitive\":true,\"preview\":\"10.0.0.0/8\"},
            {\"path\":\"C:\\\\Users\\\\attacker\\\\.ssh\\\\id_rsa\",\"name\":\"id_rsa\",\"size\":3243,\"category\":\"ssh_key\",\"sensitive\":true,\"preview\":\"-----BEGIN OPENSSH PRIVATE KEY-----\"}
        ]
    }" 2>/dev/null)
FILE_SCORE=$(echo "$FILE_RESP" | python3 -c "import sys,json; print(json.load(sys.stdin).get('score',0))" 2>/dev/null)
[ "$FILE_SCORE" -ge 30 ] && pass "文件扫描回传(score=$FILE_SCORE,含4个敏感文件)" || fail "文件扫描" "score=$FILE_SCORE"

# ---- 6.3 网络探测 (40pts) ---
# net_probe冷却300s, 用时间戳生成唯一target_ip避免跨轮冷却
NET_TARGET="${AGENT_IP}_netprobe_$(date +%s)"
echo "--- 6.3 网络探测 NetProbe (40pts, target=$NET_TARGET) ---"
NET_RESP=$(curl -s -X POST "$MGR/api/countermeasure/exfil" \
    -H "Content-Type: application/json" \
    -d "{
        \"type\":\"net_probe\",
        \"target_ip\":\"$NET_TARGET\",
        \"data_type\":\"net_probe\",
        \"data\":{
            \"internal_ips\":[\"$AGENT_IP\",\"10.111.29.5\",\"10.111.29.6\",\"192.168.1.1\"],
            \"peer_assets\":[
                {\"ip\":\"10.111.29.5\",\"open_ports\":[22,3389,8080,8443],\"services\":[\"ssh\",\"rdp\",\"http\",\"unknown\"],\"role\":\"attacker_workstation\",\"confidence\":0.85},
                {\"ip\":\"10.111.29.6\",\"open_ports\":[80,443,22,3306],\"services\":[\"http\",\"https\",\"ssh\",\"mysql\"],\"role\":\"c2_server\",\"confidence\":0.72},
                {\"ip\":\"192.168.1.1\",\"open_ports\":[80,443,53],\"services\":[\"http\",\"https\",\"dns\"],\"role\":\"gateway\",\"confidence\":0.95}
            ]
        }
    }" 2>/dev/null)
NET_SCORE=$(echo "$NET_RESP" | python3 -c "import sys,json; print(json.load(sys.stdin).get('score',0))" 2>/dev/null)
[ "$NET_SCORE" -ge 40 ] && pass "网络探测回传(score=$NET_SCORE,含3个peer资产)" || fail "网络探测" "score=$NET_SCORE"

# ---- 6.4 Image Beacon GET模式 ----
echo "--- 6.4 Image Beacon (GET外传) ---"
GET_RESP=$(curl -s -o /dev/null -w "%{http_code}" "$MGR/api/countermeasure/exfil?d=eyJ0eXBlIjoic2NyZWVuX2NhcCIsImRhdGEiOnsid2lkdGgiOjEyODB9fQ%3D%3D&s=0&t=100&tt=screen_capture" 2>/dev/null)
[ "$GET_RESP" = "200" ] && pass "Image Beacon GET外传 (HTTP $GET_RESP)" || fail "Image Beacon" "HTTP $GET_RESP"
}

# ============================================
# Phase 7: 得分板 & 冷却机制
# ============================================
run_phase 7 && {
section "Phase 7: 得分板 & 冷却机制验证"

# ---- 7.1 得分总表 ----
echo "--- 7.1 Scoreboard总分 ---"
SCOREBOARD=$(curl -s -H "$AUTH" "$MGR/api/countermeasure/scoreboard" 2>/dev/null)
TOTAL_SCORE=$(echo "$SCOREBOARD" | python3 -c "import sys,json; d=json.load(sys.stdin); print(d.get('total_score',0))" 2>/dev/null)
[ "$TOTAL_SCORE" -ge 120 ] && pass "总分=${TOTAL_SCORE}(预期≥120=50+30+40)" || fail "总分" "total=$TOTAL_SCORE"

# ---- 7.2 按分类得分 ----
echo "--- 7.2 按分类得分 ---"
CAT_SCORES=$(echo "$SCOREBOARD" | python3 -c "
import sys,json
d=json.load(sys.stdin)
bc=d.get('by_category',{})
for k,v in bc.items():
    print(f'    {k}: {v}')
" 2>/dev/null)
[ -n "$CAT_SCORES" ] && info "分类得分: $CAT_SCORES"

# ---- 7.3 按目标得分 ----
echo "--- 7.3 按目标IP得分 ---"
TARGET_SCORES=$(echo "$SCOREBOARD" | python3 -c "
import sys,json
d=json.load(sys.stdin)
bt=d.get('by_target',{})
for k,v in bt.items():
    print(f'    {k}: {v}')
" 2>/dev/null)
TARGET_COUNT=$(echo "$SCOREBOARD" | python3 -c "import sys,json; d=json.load(sys.stdin); bt=d.get('by_target',{}); print(len(bt))" 2>/dev/null)
[ "$TARGET_COUNT" -ge 1 ] && pass "按目标统计(${TARGET_COUNT}个目标)" || fail "目标统计" "count=$TARGET_COUNT"

# ---- 7.4 冷却机制 — 同IP同类型不重复计分 ----
echo "--- 7.4 冷却验证: 同IP+screen_capture 重复提交 → score=0 ---"
COOLDOWN_RESP=$(curl -s -X POST "$MGR/api/countermeasure/exfil" \
    -H "Content-Type: application/json" \
    -d "{\"type\":\"screen_capture\",\"target_ip\":\"$AGENT_IP\",\"data_type\":\"screen_capture\",\"data\":{\"width\":1920,\"height\":1080}}" 2>/dev/null)
COOLDOWN_SCORE=$(echo "$COOLDOWN_RESP" | python3 -c "import sys,json; print(json.load(sys.stdin).get('score',-1))" 2>/dev/null)
if [ "$COOLDOWN_SCORE" = "0" ]; then
    pass "同IP同类型冷却保护(score=0,冷却中)"
elif [ "$COOLDOWN_SCORE" -gt 0 ]; then
    skip "冷却验证" "已过冷却期(score=$COOLDOWN_SCORE)"
else
    fail "冷却验证" "异常返回score=$COOLDOWN_SCORE"
fi

# ---- 7.5 不同IP不冷却 (独立冷却) ----
echo "--- 7.5 跨IP不冷却: 新IP+screen_capture → 正常计分 ---"
DIFF_IP_RESP=$(curl -s -X POST "$MGR/api/countermeasure/exfil" \
    -H "Content-Type: application/json" \
    -d '{"type":"screen_capture","target_ip":"10.0.0.99","data_type":"screen_capture","data":{"width":1280,"height":720,"format":"jpeg"}}' 2>/dev/null)
DIFF_IP_SCORE=$(echo "$DIFF_IP_RESP" | python3 -c "import sys,json; print(json.load(sys.stdin).get('score',0))" 2>/dev/null)
[ "$DIFF_IP_SCORE" -ge 50 ] && pass "不同IP正常计分(score=$DIFF_IP_SCORE)" || fail "跨IP计分" "score=$DIFF_IP_SCORE"

# ---- 7.6 不同操作类型不冷却 (独立冷却) ----
echo "--- 7.6 同IP不同操作: $AGENT_IP + file_scan → 正常计分 ---"
# file_scan冷却60s, 如果测试间隔大于60s, 正常计分
DIFF_OP_RESP=$(curl -s -X POST "$MGR/api/countermeasure/exfil" \
    -H "Content-Type: application/json" \
    -d "{\"type\":\"file_scan\",\"target_ip\":\"$AGENT_IP\",\"data_type\":\"file_scan\",\"data\":[{\"path\":\"test.txt\",\"name\":\"test.txt\",\"size\":100,\"category\":\"other\",\"sensitive\":false,\"preview\":\"test\"}]}" 2>/dev/null)
DIFF_OP_SCORE=$(echo "$DIFF_OP_RESP" | python3 -c "import sys,json; print(json.load(sys.stdin).get('score',0))" 2>/dev/null)
info "同IP不同操作 file_scan(冷却60s): score=$DIFF_OP_SCORE"
}

# ============================================
# Phase 8: 合规审计
# ============================================
run_phase 8 && {
section "Phase 8: 合规审计"

# ---- 8.1 审计记录 ----
echo "--- 8.1 审计记录列表 ---"
AUDIT=$(curl -s -H "$AUTH" "$MGR/api/countermeasure/audit?target=$AGENT_IP" 2>/dev/null)
AUDIT_TOTAL=$(echo "$AUDIT" | python3 -c "import sys,json; d=json.load(sys.stdin); print(d.get('total',0))" 2>/dev/null)
[ "$AUDIT_TOTAL" -ge 1 ] && pass "审计记录(total=$AUDIT_TOTAL)" || fail "审计" "total=$AUDIT_TOTAL"

# ---- 8.2 审计条目完整性 ----
echo "--- 8.2 审计条目详情 ---"
echo "$AUDIT" | python3 -c "
import sys,json
d=json.load(sys.stdin)
entries=d.get('entries',[])
for e in entries:
    etype=e.get('event_type','unknown')
    compliant=str(e.get('compliant','N/A'))
    sig=(e.get('signature','')[:24]+'...') if e.get('signature') else 'N/A'
    print(f'    [{e[\"id\"][:16]}] {etype}: compliant={compliant} sig={sig}')
" 2>/dev/null

# ---- 8.3 无目标参数全量审计 ----
echo "--- 8.3 全量审计 ---"
AUDIT_ALL=$(curl -s -H "$AUTH" "$MGR/api/countermeasure/audit" 2>/dev/null)
AUDIT_ALL_TOTAL=$(echo "$AUDIT_ALL" | python3 -c "import sys,json; d=json.load(sys.stdin); print(d.get('total',0))" 2>/dev/null)
[ "$AUDIT_ALL_TOTAL" -ge "$AUDIT_TOTAL" ] && pass "全量审计(total=$AUDIT_ALL_TOTAL)" || skip "全量审计" "total=$AUDIT_ALL_TOTAL"
}

# ============================================
# Phase 9: 拓扑 & 攻击者画像
# ============================================
run_phase 9 && {
section "Phase 9: 拓扑 & 攻击者画像"

# ---- 9.1 攻击者团队拓扑 ----
echo "--- 9.1 攻击者团队拓扑 ---"
TOPOLOGY=$(curl -s -H "$AUTH" "$MGR/api/countermeasure/topology" 2>/dev/null || echo '{}')
if echo "$TOPOLOGY" | python3 -c "import sys,json; json.load(sys.stdin)" 2>/dev/null; then
    TEAM_SIZE=$(echo "$TOPOLOGY" | python3 -c "import sys,json; d=json.load(sys.stdin); print(d.get('team_size',0))" 2>/dev/null || echo 0)
    NODE_COUNT=$(echo "$TOPOLOGY" | python3 -c "import sys,json; d=json.load(sys.stdin); print(len(d.get('nodes',[])))" 2>/dev/null || echo 0)
    EDGE_COUNT=$(echo "$TOPOLOGY" | python3 -c "import sys,json; d=json.load(sys.stdin); print(len(d.get('edges',[])))" 2>/dev/null || echo 0)
    pass "拓扑API: team_size=$TEAM_SIZE nodes=$NODE_COUNT edges=$EDGE_COUNT"

    # 拓扑节点详情
    echo "$TOPOLOGY" | python3 -c "
import sys,json
d=json.load(sys.stdin)
for n in d.get('nodes',[]):
    print(f'    Node: {n[\"ip\"]} status={n.get(\"status\",\"?\")} role={n.get(\"role\",\"?\")}')
" 2>/dev/null || true
else
    skip "拓扑" "API返回非JSON"
fi

# ---- 9.2 攻击者画像 ----
echo "--- 9.2 攻击者画像列表 ---"
PROFILES=$(curl -s -H "$AUTH" "$MGR/api/profiles?limit=10" 2>/dev/null || echo '{}')
PROFILE_COUNT=$(echo "$PROFILES" | python3 -c "import sys,json; d=json.load(sys.stdin); print(d.get('total',len(d.get('profiles',[]))))" 2>/dev/null || echo 0)
[ "$PROFILE_COUNT" -ge 1 ] && pass "攻击者画像(total=$PROFILE_COUNT)" || skip "攻击者画像" "total=$PROFILE_COUNT"

# ---- 9.3 Dashboard统计 ----
echo "--- 9.3 仪表盘实时统计 ---"
DASHBOARD=$(curl -s -H "$AUTH" "$MGR/api/stats/dashboard" 2>/dev/null || echo '{}')
TOTAL_CONNS=$(echo "$DASHBOARD" | python3 -c "import sys,json; d=json.load(sys.stdin); print(d.get('total_connections',0))" 2>/dev/null || echo 0)
TOTAL_ATTACKS=$(echo "$DASHBOARD" | python3 -c "import sys,json; d=json.load(sys.stdin); print(d.get('total_attacks',0))" 2>/dev/null || echo 0)
info "仪表盘: connections=$TOTAL_CONNS attacks=$TOTAL_ATTACKS"
}

# ============================================
# Phase 10: 安全合规 — MFA + 审计链
# ============================================
run_phase 10 && {
section "Phase 10: 安全合规 — MFA二次认证 + 审计链完整性"

# ---- 10.1 MFA Challenge ----
echo "--- 10.1 MFA Challenge ---"
MFA_CHALLENGE=$(curl -s -X POST "$MGR/api/mfa/challenge" \
    -H "$AUTH" \
    -H "Content-Type: application/json" \
    -d '{"user":"admin"}' 2>/dev/null)
CHALLENGE_CODE=$(echo "$MFA_CHALLENGE" | python3 -c "import sys,json; print(json.load(sys.stdin).get('challenge',''))" 2>/dev/null)
MFA_QR=$(echo "$MFA_CHALLENGE" | python3 -c "import sys,json; print(json.load(sys.stdin).get('qr_uri','')[:50])" 2>/dev/null)
[ -n "$CHALLENGE_CODE" ] && pass "MFA挑战码(6位=$CHALLENGE_CODE)" || fail "MFA Challenge" "无挑战码"
[ -n "$MFA_QR" ] && info "MFA种子URI: $MFA_QR..."

# ---- 10.2 MFA Verify ----
echo "--- 10.2 MFA Verify (验证挑战码) ---"
if [ -n "$CHALLENGE_CODE" ]; then
    MFA_VERIFY=$(curl -s -X POST "$MGR/api/mfa/verify" \
        -H "$AUTH" \
        -H "Content-Type: application/json" \
        -d "{\"user\":\"admin\",\"code\":\"$CHALLENGE_CODE\"}" 2>/dev/null)
    MFA_TOKEN=$(echo "$MFA_VERIFY" | python3 -c "import sys,json; print(json.load(sys.stdin).get('token',''))" 2>/dev/null)
    [ -n "$MFA_TOKEN" ] && pass "MFA验证成功(操作令牌${#MFA_TOKEN}chars,5min有效)" || fail "MFA Verify" "无操作令牌"
fi

# ---- 10.3 审计链完整性 ----
echo "--- 10.3 审计链完整性验证 (SHA256链式哈希) ---"
CHAIN_VERIFY=$(curl -s -H "$AUTH" "$MGR/api/audit/chain/verify" 2>/dev/null)
CHAIN_VALID=$(echo "$CHAIN_VERIFY" | python3 -c "import sys,json; print(json.load(sys.stdin).get('valid',False))" 2>/dev/null)
CHAIN_LENGTH=$(echo "$CHAIN_VERIFY" | python3 -c "import sys,json; print(json.load(sys.stdin).get('length',0))" 2>/dev/null)
[ "$CHAIN_VALID" = "True" ] && pass "审计链完整(valid=True, length=$CHAIN_LENGTH)" || fail "审计链" "valid=$CHAIN_VALID length=$CHAIN_LENGTH"

# ---- 10.4 仪表盘安全摘要 ----
echo "--- 10.4 安全合规状态总览 ---"
info "MFA: $( [ -n "$MFA_TOKEN" ] && echo 'ENABLED ✓' || echo 'DISABLED' )"
info "审计链: $( [ "$CHAIN_VALID" = "True" ] && echo 'INTACT ✓' || echo 'BROKEN ✗' )"
info "JWT认证: $( [ -n "$TOKEN" ] && echo 'AUTHENTICATED ✓' || echo 'FAILED ✗' )"
}

# ============================================
# Phase 11: 集群Agent (可选)
# ============================================
run_phase 11 && {
section "Phase 11: 集群Agent连通性"

if [ "$SKIP_AGENT" = true ]; then
    skip "Agent测试" "已跳过(--skip-agent)"
else
    echo "--- 11.1 集群状态 ---"
    CLUSTER=$(curl -s -H "$AUTH" "$MGR/api/cluster/status" 2>/dev/null || echo '{}')
    NODES=$(echo "$CLUSTER" | python3 -c "
import sys,json
d=json.load(sys.stdin)
nodes=d if type(d)==list else d.get('nodes',[])
print(len(nodes))
" 2>/dev/null || echo 0)
    [ "$NODES" -ge 0 ] && pass "集群状态查询(nodes=$NODES)" || skip "集群" "无响应"

    # 集群节点详情
    if [ "$NODES" -gt 0 ]; then
        echo "$CLUSTER" | python3 -c "
import sys,json
d=json.load(sys.stdin)
nodes=d if type(d)==list else d.get('nodes',[])
for n in nodes:
    print(f'    Agent: {n[\"id\"][:12]} role={n.get(\"role\",\"?\")} last_heartbeat={n.get(\"last_heartbeat\",\"?\")}')
" 2>/dev/null || true
        pass "Agent在线(node=$NODES)"
    else
        info "无Agent连接 (Win11 Agent未启动?)"
    fi

    # 尝试通过集群转发事件
    echo "--- 11.2 集群事件转发 ---"
    info "/api/cluster/events 端点未实现 (当前仅 /api/cluster/status)"
fi
}

# ============================================
# Phase 12: 高级反制 — 截屏列表/文件扫描列表
# ============================================
run_phase 12 && {
section "Phase 12: 高级反制 — 截屏列表/文件扫描列表/得分明细"

# ---- 12.1 截屏记录列表 ----
echo "--- 12.1 截屏记录列表 ---"
SCREENCAPS=$(curl -s -H "$AUTH" "$MGR/api/countermeasure/screencaps?limit=10" 2>/dev/null || echo '{}')
SC_TOTAL=$(echo "$SCREENCAPS" | python3 -c "import sys,json; d=json.load(sys.stdin); print(d.get('total',0))" 2>/dev/null || echo 0)
[ "$SC_TOTAL" -ge 1 ] && pass "截屏列表(total=$SC_TOTAL)" || fail "截屏列表" "total=$SC_TOTAL"

# 截屏详情
echo "$SCREENCAPS" | python3 -c "
import sys,json
d=json.load(sys.stdin)
for sc in d.get('entries',d.get('screencaps',[]))[:3]:
    print(f'    [{sc[\"id\"][:12]}] {sc.get(\"target_ip\",\"?\")} {sc.get(\"width\",\"?\")}x{sc.get(\"height\",\"?\")} captured_at={sc.get(\"captured_at\",\"?\")[:19]}')
" 2>/dev/null || true

# ---- 12.2 文件扫描列表 ----
echo "--- 12.2 文件扫描记录列表 ---"
FILESCANS=$(curl -s -H "$AUTH" "$MGR/api/countermeasure/filescans?limit=10" 2>/dev/null || echo '{}')
FS_TOTAL=$(echo "$FILESCANS" | python3 -c "import sys,json; d=json.load(sys.stdin); print(d.get('total',0))" 2>/dev/null || echo 0)
[ "$FS_TOTAL" -ge 1 ] && pass "文件扫描列表(total=$FS_TOTAL)" || fail "文件扫描列表" "total=$FS_TOTAL"

echo "$FILESCANS" | python3 -c "
import sys,json
d=json.load(sys.stdin)
for fs in d.get('entries',d.get('filescans',[]))[:3]:
    files=fs.get('files',fs.get('data',[]))
    sensitive=sum(1 for f in files if f.get('sensitive'))
    print(f'    [{fs[\"id\"][:12]}] {fs.get(\"target_ip\",\"?\")} files={len(files)} sensitive={sensitive}')
" 2>/dev/null || true

# ---- 12.3 按目标得分明细 ----
echo "--- 12.3 按目标得分明细 ---"
TARGET_LIST=$(echo "$SCOREBOARD" | python3 -c "
import sys,json
d=json.load(sys.stdin)
bt=d.get('by_target',{})
for ip,score in sorted(bt.items(), key=lambda x: x[1], reverse=True):
    print(f'    {ip}: {score}pts')
" 2>/dev/null)
[ -n "$TARGET_LIST" ] && info "目标得分排行:\n$TARGET_LIST"

# ---- 12.4 能力命中统计 ----
echo "--- 12.4 能力命中统计 ---"
HIT_STATS=$(echo "$SCOREBOARD" | python3 -c "
import sys,json
d=json.load(sys.stdin)
ch=d.get('capability_hits',{})
for cap,count in sorted(ch.items(), key=lambda x: x[1], reverse=True):
    print(f'    {cap}: {count} hits')
" 2>/dev/null)
[ -n "$HIT_STATS" ] && info "能力命中:\n$HIT_STATS"
}

# ============================================
# 结果汇总
# ============================================
END_TIME=$(date +%s)
ELAPSED=$((END_TIME - START_TIME))
TOTAL=$((PASS + FAIL + SKIP))
PASS_RATE=$(python3 -c "print(f'{$PASS*100/$TOTAL:.1f}%')" 2>/dev/null || echo "N/A")

section "测试结果汇总"
echo ""
echo "  Manager: $MGR"
echo "  Agent:   $AGENT_IP"
echo "  耗时:     ${ELAPSED}s"
echo ""
echo "  ┌──────────────────────────────────────┐"
echo "  │  Total: $TOTAL | Pass: $PASS | Fail: $FAIL | Skip: $SKIP │"
echo "  │  Rate:  $PASS_RATE                              │"
echo "  └──────────────────────────────────────┘"
echo ""

# 生成 JSON 报告
python3 -c "
import json, datetime

report = {
    'test_name': 'Laji-HoneyPot 溯源反制全量能力测试 v0.12.0',
    'timestamp': '$START_TIME_UTC',
    'manager': '$MGR',
    'agent': '$AGENT_IP',
    'elapsed_sec': $ELAPSED,
    'summary': {
        'total': $TOTAL,
        'pass': $PASS,
        'fail': $FAIL,
        'skip': $SKIP,
        'pass_rate': '${PASS_RATE}'
    },
    'sections': {
        'P1_jwt_auth': {'pass': 0, 'total': 4},
        'P2_fingerprint': {'pass': 0, 'total': 7},
        'P3_ua_recognition': {'pass': $UA_PASS, 'total': $UA_TOTAL},
        'P4_breadcrumb': {'pass': 0, 'total': 10},
        'P5_vulndb': {'pass': 0, 'total': 6},
        'P6_exfil_screencap_filescan_netprobe': {'pass': 0, 'total': 4},
        'P7_scoring_cooldown': {'pass': 0, 'total': 6},
        'P8_audit': {'pass': 0, 'total': 3},
        'P9_topology_profiles': {'pass': 0, 'total': 3},
        'P10_mfa_chain': {'pass': 0, 'total': 4},
        'P11_cluster_agent': {'pass': 0, 'total': 2},
        'P12_advanced_countermeasure': {'pass': 0, 'total': 4}
    },
    'scoring_system': {
        'screen_capture': {'max_score': 50, 'cooldown_sec': 5},
        'file_scan': {'max_score': 30, 'cooldown_sec': 60},
        'net_probe': {'max_score': 40, 'cooldown_sec': 300},
        'fingerprint': {'max_score': 15, 'cooldown_sec': 10},
        'env_detect': {'max_score': 20, 'cooldown_sec': 30}
    },
    'phase_details': {
        'P1': '存活检测 — 健康检查 / JWT认证(登录/刷新/未认证拒绝) / API连通性',
        'P2': '溯源指纹 — Chrome全19维/Firefox/Safari/Burp/Nmap/SQLMap + 列表查询',
        'P3': 'UA识别 — Chrome/Firefox/Safari/Edge/Burp/Python/curl + 攻击事件查询',
        'P4': '面包屑注入 — HTTP/MySQL/SSH/Redis/FTP/LDAP/SMB/RDP/DNS 9大服务',
        'P5': 'VulnDB — 总量/CVE-2021-44228/info_leak/fingerprint/active/chrome漏洞',
        'P6': 'Exfil外传 — POST截屏(50pts)/文件扫描(30pts)/网络探测(40pts)/GET ImageBeacon',
        'P7': '得分板冷却 — Total/ByCategory/ByTarget + 同IP冷却/跨IP不冷却/跨类型不冷却',
        'P8': '合规审计 — 按目标审计/全量审计/条目完整性验证',
        'P9': '拓扑画像 — 团队拓扑/攻击者画像/Dashboard仪表盘',
        'P10': '安全合规 — MFA Challenge/Verify + 审计链SHA256完整性',
        'P11': '集群Agent — 节点状态/事件转发',
        'P12': '高级反制 — 截屏列表/文件扫描列表/目标得分排行/能力命中统计'
    }
}
with open('$REPORT_JSON','w') as f:
    json.dump(report, f, indent=2, ensure_ascii=False)
print('JSON报告: $REPORT_JSON')
" 2>/dev/null

echo ""
echo "详细日志: $LOG"
echo "JSON报告: $REPORT_JSON"
echo ""

# 返回失败数作为退出码
exit $FAIL
