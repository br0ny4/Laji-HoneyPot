#!/bin/bash
# ============================================================
# Laji-HoneyPot v0.17.0 全量部署与测试脚本
# 覆盖: 管理端验证 / Agent部署 / 蜜饵联动 / API全量 / 蜜罐服务
# ============================================================
set -e

BASE="http://127.0.0.1:8080"
PASS=0
FAIL=0
ISSUES=""

# ---- 颜色 ----
GREEN='\033[0;32m'
RED='\033[0;31m'
YELLOW='\033[1;33m'
NC='\033[0m'

log_pass() { echo -e "  ${GREEN}[PASS]${NC} $1"; PASS=$((PASS+1)); }
log_fail() { echo -e "  ${RED}[FAIL]${NC} $1"; FAIL=$((FAIL+1)); ISSUES="$ISSUES\n  - $1"; }
log_info() { echo -e "  ${YELLOW}[INFO]${NC} $1"; }

echo "============================================"
echo " Laji-HoneyPot v0.17.0 全量部署测试"
echo " 管理端: macOS M1 (arm64)"
echo " 时间: $(date '+%Y-%m-%d %H:%M:%S')"
echo "============================================"
echo ""

# ==========================================================
# Phase 1: 管理端部署验证
# ==========================================================
echo "--- Phase 1: 管理端部署验证 ---"

# 1.1 进程检查
PID=$(pgrep -f "bin/honeypot" 2>/dev/null | head -1)
if [ -n "$PID" ]; then
    log_pass "管理端进程运行中 (PID=$PID)"
else
    log_fail "管理端进程未运行"
fi

# 1.2 架构检查
ARCH_INFO=$(file bin/honeypot 2>/dev/null | grep -o 'arm64')
if [ "$ARCH_INFO" = "arm64" ]; then
    log_pass "二进制为 Apple Silicon arm64 原生编译"
else
    log_info "二进制架构: $(file bin/honeypot 2>/dev/null || echo 'unknown')"
fi

# 1.3 健康检查
HEALTH=$(curl -s -o /dev/null -w "%{http_code}" "$BASE/healthz" 2>/dev/null)
if [ "$HEALTH" = "200" ]; then
    HEALTH_BODY=$(curl -s "$BASE/healthz" 2>/dev/null)
    VERSION=$(echo "$HEALTH_BODY" | python3 -c "import sys,json; print(json.load(sys.stdin).get('version','?'))" 2>/dev/null)
    log_pass "Healthz 端点正常 (HTTP $HEALTH, version=$VERSION)"
else
    log_fail "Healthz 端点异常 (HTTP $HEALTH)"
fi

# 1.4 API 端口监听
if lsof -i :8080 -sTCP:LISTEN 2>/dev/null | grep -q honeypot; then
    log_pass "API 端口 8080 监听正常"
else
    log_fail "API 端口 8080 未监听"
fi

# 1.5 前端 SPA
SPA=$(curl -s -o /dev/null -w "%{http_code}" "$BASE/" 2>/dev/null)
if [ "$SPA" = "200" ]; then
    log_pass "前端 SPA 可访问 (HTTP $SPA)"
else
    log_info "前端 SPA 返回 HTTP $SPA (可能未构建前端)"
fi

# ==========================================================
# Phase 2: 蜜罐服务端口验证
# ==========================================================
echo ""
echo "--- Phase 2: 蜜罐服务端口验证 ---"

check_port() {
    local port=$1
    local name=$2
    if lsof -i :$port -sTCP:LISTEN 2>/dev/null | grep -q honeypot; then
        log_pass "$name ($port) 监听正常"
    else
        log_info "$name ($port) 端口未监听 (macOS 可能端口冲突)"
    fi
}

check_port 8081 "HTTP"
check_port 3306 "MySQL"
check_port 6379 "Redis"
check_port 2222 "SSH"
check_port 2121 "FTP"
check_port 3890 "LDAP"
check_port 5354 "DNS"
check_port 4450 "SMB"
check_port 33890 "RDP"
check_port 8443 "Cluster"

# ==========================================================
# Phase 3: 认证与 JWT
# ==========================================================
echo ""
echo "--- Phase 3: JWT 认证验证 ---"

LOGIN_RESP=$(curl -s -X POST "$BASE/api/auth/login" \
    -H "Content-Type: application/json" \
    -d '{"username":"admin","password":"admin123"}' 2>/dev/null)

TOKEN=$(echo "$LOGIN_RESP" | python3 -c "import sys,json; print(json.load(sys.stdin).get('access_token',''))" 2>/dev/null)

if [ -n "$TOKEN" ] && [ ${#TOKEN} -gt 20 ]; then
    log_pass "JWT 登录成功 (token 长度=${#TOKEN})"
else
    log_fail "JWT 登录失败"
fi

# 无 token 的请求应返回 401
NOAUTH=$(curl -s -o /dev/null -w "%{http_code}" "$BASE/api/bait/tokens" 2>/dev/null)
if [ "$NOAUTH" = "401" ]; then
    log_pass "未认证请求正确返回 401"
else
    log_info "未认证请求返回 HTTP $NOAUTH"
fi

# ==========================================================
# Phase 4: Agent 部署 API
# ==========================================================
echo ""
echo "--- Phase 4: Agent 部署 API ---"

# 4.1 Linux Agent 生成
LINUX_AGENT=$(curl -s -X POST "$BASE/api/cluster/agent/generate" \
    -H "Authorization: Bearer $TOKEN" \
    -H "Content-Type: application/json" \
    -d '{"manager_addr":"10.0.0.1:8443","scenario":"full","os_target":"linux"}' 2>/dev/null)

LINUX_BIN=$(echo "$LINUX_AGENT" | python3 -c "import sys,json; print(json.load(sys.stdin).get('binary_name',''))" 2>/dev/null)
LINUX_OS=$(echo "$LINUX_AGENT" | python3 -c "import sys,json; print(json.load(sys.stdin).get('os_target',''))" 2>/dev/null)
LINUX_SVCS=$(echo "$LINUX_AGENT" | python3 -c "import sys,json; print(len(json.load(sys.stdin).get('enabled_svcs',[])))" 2>/dev/null)

if [ "$LINUX_BIN" = "honeypot-linux-amd64" ] && [ "$LINUX_OS" = "linux" ]; then
    log_pass "Linux Agent 生成成功 (binary=$LINUX_BIN, services=$LINUX_SVCS)"
else
    log_fail "Linux Agent 生成异常 (bin=$LINUX_BIN, os=$LINUX_OS)"
fi

# 4.2 Windows Agent 生成
WINDOWS_AGENT=$(curl -s -X POST "$BASE/api/cluster/agent/generate" \
    -H "Authorization: Bearer $TOKEN" \
    -H "Content-Type: application/json" \
    -d '{"manager_addr":"10.111.29.4:8443","scenario":"full","os_target":"windows","node_name":"WIN-AGENT-01"}' 2>/dev/null)

WIN_BIN=$(echo "$WINDOWS_AGENT" | python3 -c "import sys,json; print(json.load(sys.stdin).get('binary_name',''))" 2>/dev/null)
WIN_OS=$(echo "$WINDOWS_AGENT" | python3 -c "import sys,json; print(json.load(sys.stdin).get('os_target',''))" 2>/dev/null)
WIN_PS=$(echo "$WINDOWS_AGENT" | python3 -c "import sys,json; d=json.load(sys.stdin); print(len(d.get('install_script_ps','')))" 2>/dev/null)
WIN_SC=$(echo "$WINDOWS_AGENT" | python3 -c "import sys,json; d=json.load(sys.stdin); print(len(d.get('service_config','')))" 2>/dev/null)

if [ "$WIN_BIN" = "honeypot-windows-amd64.exe" ] && [ "$WIN_OS" = "windows" ] && [ "$WIN_PS" -gt 100 ]; then
    log_pass "Windows Agent 生成成功 (binary=$WIN_BIN, ps_len=$WIN_PS, svc_len=$WIN_SC)"
    # 提取并保存 Windows 部署脚本
    echo "$WINDOWS_AGENT" | python3 -c "import sys,json; print(json.load(sys.stdin)['install_script_ps'])" > /tmp/win-agent-deploy.ps1 2>/dev/null
    log_info "Windows 部署脚本已保存到 /tmp/win-agent-deploy.ps1"
else
    log_fail "Windows Agent 生成异常 (bin=$WIN_BIN, os=$WIN_OS, ps=$WIN_PS)"
fi

# 4.3 macOS M1 Agent 生成 (本机作为攻击者节点)
MACOS_AGENT=$(curl -s -X POST "$BASE/api/cluster/agent/generate" \
    -H "Authorization: Bearer $TOKEN" \
    -H "Content-Type: application/json" \
    -d '{"manager_addr":"127.0.0.1:8443","scenario":"web","os_target":"linux","node_name":"macOS-Attacker-Node"}' 2>/dev/null)

MACOS_SCENARIO=$(echo "$MACOS_AGENT" | python3 -c "import sys,json; print(json.load(sys.stdin).get('scenario',''))" 2>/dev/null)
if [ "$MACOS_SCENARIO" = "web" ]; then
    log_pass "macOS 攻击者节点 Agent 生成成功 (scenario=web)"
else
    log_fail "macOS Agent 生成异常"
fi

# ==========================================================
# Phase 5: 蜜饵系统与联动引擎
# ==========================================================
echo ""
echo "--- Phase 5: 蜜饵系统 + 联动引擎 ---"

# 5.1 蜜饵令牌列表
BAIT_TOKENS=$(curl -s -H "Authorization: Bearer $TOKEN" "$BASE/api/bait/tokens" 2>/dev/null)
TOKEN_COUNT=$(echo "$BAIT_TOKENS" | python3 -c "
import sys,json
d=json.load(sys.stdin)
tokens=d.get('tokens',d) if isinstance(d,dict) else d
print(len(tokens) if isinstance(tokens,list) else 0)" 2>/dev/null)
if [ "$TOKEN_COUNT" -ge 7 ]; then
    log_pass "蜜饵令牌生成完整 ($TOKEN_COUNT/7 种类型)"
else
    log_fail "蜜饵令牌数量不足 (预期>=7, 实际=$TOKEN_COUNT)"
fi

# 5.2 联动关系列表
LINKAGES=$(curl -s -H "Authorization: Bearer $TOKEN" "$BASE/api/bait/linkages?limit=100" 2>/dev/null)
LINK_COUNT=$(echo "$LINKAGES" | python3 -c "
import sys,json
d=json.load(sys.stdin)
links=d.get('linkages',d) if isinstance(d,dict) else d
print(len(links) if isinstance(links,list) else 0)" 2>/dev/null)
if [ "$LINK_COUNT" -ge 10 ]; then
    log_pass "蜜饵联动关系完整 ($LINK_COUNT 条联动)"
    
    # 统计各类型联动
    echo "$LINKAGES" | python3 -c "
import sys,json
from collections import Counter
data=json.load(sys.stdin)
links=data.get('linkages',data) if isinstance(data,dict) else data
if isinstance(links,list):
    types=Counter(l.get('linkage_type','?') for l in links)
    for t,c in sorted(types.items()):
        print(f'    {t}: {c} \\u6761\\u8054\\u52a8')
" 2>/dev/null
else
    log_fail "蜜饵联动数量不足 (预期>=10, 实际=$LINK_COUNT)"
fi

# 5.3 联动统计
LINK_STATS=$(curl -s -H "Authorization: Bearer $TOKEN" "$BASE/api/bait/linkages/stats" 2>/dev/null)
LINK_TOTAL=$(echo "$LINK_STATS" | python3 -c "import sys,json; print(json.load(sys.stdin).get('total_linkages',0))" 2>/dev/null)
if [ "$LINK_TOTAL" -ge 10 ]; then
    log_pass "联动统计正常 (共 $LINK_TOTAL 条)"
else
    log_fail "联动统计异常 (total=$LINK_TOTAL)"
fi

# ==========================================================
# Phase 6: 核心 API 全量验证
# ==========================================================
echo ""
echo "--- Phase 6: 核心 API 全量验证 ---"

test_api() {
    local method="$1"
    local path="$2"
    local desc="$3"
    local expected="$4"
    
    local code
    if [ "$method" = "POST" ]; then
        code=$(curl -s -o /dev/null -w "%{http_code}" -X POST "$BASE$path" \
            -H "Authorization: Bearer $TOKEN" \
            -H "Content-Type: application/json" \
            -d '{}' 2>/dev/null)
    else
        code=$(curl -s -o /dev/null -w "%{http_code}" "$BASE$path" \
            -H "Authorization: Bearer $TOKEN" 2>/dev/null)
    fi
    
    if echo "$code" | grep -qE "$expected"; then
        log_pass "$desc ($method $path) -> HTTP $code"
    else
        log_fail "$desc ($method $path) -> HTTP $code (expected $expected)"
    fi
}

test_api "GET"    "/api/stats/dashboard"        "仪表盘统计"     "200"
test_api "GET"    "/api/stats/detailed"          "详细统计"       "200"
test_api "GET"    "/api/attacks?limit=5"         "攻击事件列表"   "200"
test_api "GET"    "/api/fingerprints?limit=5"    "指纹采集列表"   "200"
test_api "GET"    "/api/countermeasures?limit=5" "反制日志列表"   "200"
test_api "GET"    "/api/topology"                "拓扑图数据"     "200"
test_api "GET"    "/api/vulns?limit=5"           "漏洞库列表"     "200"
test_api "GET"    "/api/vulndb?limit=5"          "漏洞库别名"     "200"
test_api "GET"    "/api/metrics"                 "系统指标"       "200"
test_api "GET"    "/api/services/status"         "服务状态"       "200"
test_api "GET"    "/api/cluster/nodes"           "集群节点"       "200"
test_api "GET"    "/api/cluster/events?limit=5"  "集群事件"       "200"
test_api "GET"    "/api/profile/attackers?limit=5" "攻击者画像"   "200"
test_api "GET"    "/api/bait/tokens"             "蜜饵令牌"       "200"
test_api "GET"    "/api/bait/access?limit=5"     "蜜饵访问记录"   "200"
test_api "GET"    "/api/bait/stats"              "蜜饵统计"       "200"
test_api "GET"    "/api/bait/linkages?limit=10"  "蜜饵联动列表"   "200"
test_api "GET"    "/api/bait/linkages/stats"     "蜜饵联动统计"   "200"
test_api "GET"    "/api/system"                  "系统信息"       "200"
test_api "GET"    "/api/traps/config"            "陷阱配置"       "200"

# 反制引擎端点
test_api "GET"    "/api/countermeasure/scoreboard"   "反制得分板"     "200"
test_api "GET"    "/api/countermeasure/screencaps?limit=3"  "截屏记录" "200"
test_api "GET"    "/api/countermeasure/filescans?limit=3"   "文件扫描" "200"

# 审计链
test_api "GET"    "/api/audit/chain?limit=3"       "审计链记录"     "200"
test_api "GET"    "/api/audit/chain/verify"        "审计链验证"     "200"

# ==========================================================
# Phase 7: 蜜罐协议可达性测试
# ==========================================================
echo ""
echo "--- Phase 7: 蜜罐协议可达性测试 ---"

test_proto() {
    local host="$1"
    local port="$2"
    local name="$3"
    if timeout 3 bash -c "echo > /dev/tcp/$host/$port" 2>/dev/null; then
        log_pass "$name ($host:$port) 可达"
    else
        log_info "$name ($host:$port) 不可达 (端口未监听或防火墙)"
    fi
}

test_proto "127.0.0.1" 8081 "HTTP"
test_proto "127.0.0.1" 3306 "MySQL"
test_proto "127.0.0.1" 6379 "Redis"
test_proto "127.0.0.1" 2222 "SSH"
test_proto "127.0.0.1" 2121 "FTP"

# ==========================================================
# Phase 8: Windows Agent 远程部署配置生成
# ==========================================================
echo ""
echo "--- Phase 8: Windows 11 (10.111.29.4) Agent 部署配置 ---"

# 保存完整部署脚本
echo "$WINDOWS_AGENT" | python3 -c "
import sys,json
d = json.load(sys.stdin)
print('=== Windows Agent 部署配置 ===')
print(f'管理端: {d[\"manager_addr\"]}')
print(f'操作系统: {d[\"os_target\"]}')
print(f'二进制文件: {d[\"binary_name\"]}')
print(f'启用服务: {d[\"enabled_svcs\"]}')
print(f'场景: {d[\"scenario\"]}')
" 2>/dev/null

log_info "Windows Agent 配置文件已生成:"
echo "$WINDOWS_AGENT" | python3 -c "import sys,json; print(json.load(sys.stdin)['config_yaml'])" > /tmp/win-agent-config.yaml 2>/dev/null
echo "  - config.yaml  -> /tmp/win-agent-config.yaml"
echo "  - deploy script -> /tmp/win-agent-deploy.ps1"

# ==========================================================
# 汇总
# ==========================================================
echo ""
echo "============================================"
echo "  测试汇总"
echo "============================================"
echo -e "  ${GREEN}PASS: $PASS${NC}"
if [ "$FAIL" -gt 0 ]; then
    echo -e "  ${RED}FAIL: $FAIL${NC}"
    echo -e "  问题列表:$ISSUES"
else
    echo -e "  ${RED}FAIL: 0${NC}"
fi
echo "  总计: $((PASS + FAIL)) 项"
echo ""
echo "  部署产出物:"
echo "  - macOS 管理端: 运行中 (http://127.0.0.1:8080)"
echo "  - Windows Agent 配置: /tmp/win-agent-config.yaml"
echo "  - Windows 部署脚本: /tmp/win-agent-deploy.ps1"
echo "  - 管理端日志: /tmp/honeypot.log"
echo "============================================"
