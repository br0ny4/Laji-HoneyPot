#!/usr/bin/env bash
#===============================================================================
# Laji-HoneyPot 一键本地部署 + 全量测试
# 
# 在 macOS M1 终端执行:
#   chmod +x deploy/one-click.sh && ./deploy/one-click.sh
#
# 流程:
#   1. 编译后端 (darwin/arm64)
#   2. 构建前端 (React)
#   3. 启动 Manager (后台)
#   4. 运行全量溯源反制测试
#   5. 生成测试报告
#   6. 交叉编译 Win11 Agent
#===============================================================================
set -euo pipefail

RED='\033[0;31m'; GREEN='\033[0;32m'; YELLOW='\033[1;33m'
BLUE='\033[0;34m'; CYAN='\033[0;36m'; NC='\033[0m'
info()  { echo -e "${GREEN}[INFO]${NC}  $*"; }
warn()  { echo -e "${YELLOW}[WARN]${NC}  $*"; }
err()   { echo -e "${RED}[ERROR]${NC} $*"; exit 1; }
step()  { echo -e "\n${BLUE}==>${NC} ${CYAN}Step $*${NC}"; }

SCRIPT_DIR="$(cd "$(dirname "$0")/.." && pwd)"
cd "$SCRIPT_DIR"

echo -e "${CYAN}"
echo "  ╔══════════════════════════════════════════════════╗"
echo "  ║   Laji-HoneyPot 一键部署 + 全量测试 v0.12.0       ║"
echo "  ║   macOS M1 → 管理端/攻击者                       ║"
echo "  ║   Win11 10.111.29.4 → Agent                     ║"
echo "  ╚══════════════════════════════════════════════════╝"
echo -e "${NC}"

MANAGER_IP=$(ipconfig getifaddr en0 2>/dev/null || echo "localhost")
info "本机IP: ${CYAN}$MANAGER_IP${NC}"
info "项目目录: $SCRIPT_DIR"

#========================================================================
# Step 1: 编译后端
#========================================================================
step "1: 编译后端 (darwin/arm64)"

GO_BIN=""
for go_path in go /usr/local/go/bin/go /opt/homebrew/bin/go; do
    if command -v "$go_path" &>/dev/null; then
        GO_BIN="$go_path"
        break
    fi
done

if [ -z "$GO_BIN" ]; then
    err "未找到 Go ≥1.22，请安装: brew install go"
fi

info "Go: $($GO_BIN version)"
mkdir -p bin
CGO_ENABLED=0 GOOS=darwin GOARCH=arm64 $GO_BIN build -ldflags="-s -w" -o bin/honeypot ./cmd/honeypot/
info "后端编译完成: bin/honeypot"

#========================================================================
# Step 2: 构建前端
#========================================================================
step "2: 构建前端"

if command -v npm &>/dev/null; then
    cd web
    [ ! -d node_modules ] && npm install
    npm run build
    cd "$SCRIPT_DIR"
    info "前端构建完成: web/dist/"
    FRONTEND_READY=true
else
    warn "未找到 Node.js/npm，跳过前端构建 (API仍可用)"
    warn "安装Node: brew install node"
    FRONTEND_READY=false
fi

#========================================================================
# Step 3: 启动服务
#========================================================================
step "3: 启动 Laji-HoneyPot Manager"

# 检查是否已运行
if lsof -iTCP:8080 -sTCP:LISTEN &>/dev/null; then
    warn "端口8080已占用，尝试停止旧进程..."
    pkill -f "bin/honeypot" 2>/dev/null || true
    sleep 2
fi

# 后台启动
nohup ./bin/honeypot > data/honeypot.log 2>&1 &
MANAGER_PID=$!
info "Manager PID: $MANAGER_PID"

# 等待启动
echo -n "  等待服务启动"
for i in $(seq 1 20); do
    if curl -s -o /dev/null http://localhost:8080/healthz 2>/dev/null; then
        echo ""
        info "服务启动成功 (http://localhost:8080)"
        break
    fi
    echo -n "."
    sleep 1
done

if ! curl -s -o /dev/null http://localhost:8080/healthz 2>/dev/null; then
    err "服务启动超时，查看日志: tail -50 data/honeypot.log"
fi

#========================================================================
# Step 4: 运行全量测试
#========================================================================
step "4: 运行溯源反制全量测试"

# JWT登录获取token
TOKEN=$(curl -s -X POST http://localhost:8080/api/auth/login \
    -H 'Content-Type: application/json' \
    -d '{"username":"admin","password":"admin123"}' 2>/dev/null \
    | python3 -c "import sys,json; print(json.load(sys.stdin).get('access_token',''))" 2>/dev/null)
AUTH="Authorization: Bearer $TOKEN"

echo ""
echo "  ╔══════════════════════════════════════════════════╗"
echo "  ║           快速验证 (5项核心能力)                 ║"
echo "  ╚══════════════════════════════════════════════════╝"
echo ""

PASS=0
FAIL=0

# Q1: 指纹采集
echo -n "  [Q1] 指纹采集 (Chrome全维度)... "
HTTP=$(curl -s -o /dev/null -w "%{http_code}" -X POST http://localhost:8080/api/collect \
    -H 'Content-Type: application/json' \
    -H 'User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 Chrome/131.0.0.0 Safari/537.36' \
    -d '{"canvas":"test123","gpu":"NVIDIA RTX 3060","scr":"1920x1080x24","tz":"Asia/Shanghai","lang":"zh-CN","audio":"124.0435","hardware_concurrency":"16","device_memory":"32","platform":"Win32","inner_ip":"192.168.1.105"}' 2>/dev/null)
[ "$HTTP" = "200" ] && echo -e "${GREEN}PASS${NC}" && ((PASS++)) || echo -e "${RED}FAIL (HTTP $HTTP)${NC}" && ((FAIL++))

# Q2: 截屏外传
echo -n "  [Q2] 截屏外传 (50pts)... "
SCORE=$(curl -s -X POST http://localhost:8080/api/countermeasure/exfil \
    -H "Content-Type: application/json" \
    -d '{"type":"screen_capture","target_ip":"10.111.29.4","data_type":"screen_capture","data":{"width":1920,"height":1080,"dpr":2,"format":"jpeg","captured_at":"2026-07-02T10:00:00Z","image":"base64_fake"}}' 2>/dev/null \
    | python3 -c "import sys,json; print(json.load(sys.stdin).get('score',0))" 2>/dev/null)
[ "$SCORE" -ge 50 ] && echo -e "${GREEN}PASS (score=$SCORE)${NC}" && ((PASS++)) || echo -e "${RED}FAIL (score=$SCORE)${NC}" && ((FAIL++))

# Q3: 文件扫描外传
echo -n "  [Q3] 文件扫描外传 (30pts)... "
SCORE=$(curl -s -X POST http://localhost:8080/api/countermeasure/exfil \
    -H "Content-Type: application/json" \
    -d '{"type":"file_scan","target_ip":"10.111.29.4","data_type":"file_scan","data":[{"path":"C:\\passwords.txt","name":"passwords.txt","size":1024,"category":"credentials","sensitive":true,"preview":"admin:p@ssw0rd"}]}' 2>/dev/null \
    | python3 -c "import sys,json; print(json.load(sys.stdin).get('score',0))" 2>/dev/null)
[ "$SCORE" -ge 30 ] && echo -e "${GREEN}PASS (score=$SCORE)${NC}" && ((PASS++)) || echo -e "${RED}FAIL (score=$SCORE)${NC}" && ((FAIL++))

# Q4: 网络探测外传
echo -n "  [Q4] 网络探测外传 (40pts)... "
SCORE=$(curl -s -X POST http://localhost:8080/api/countermeasure/exfil \
    -H "Content-Type: application/json" \
    -d '{"type":"net_probe","target_ip":"10.111.29.4","data_type":"net_probe","data":{"internal_ips":["10.111.29.4","10.111.29.5"],"peer_assets":[{"ip":"10.111.29.5","open_ports":[22,3389],"services":["ssh","rdp"],"role":"attacker_workstation","confidence":0.85}]}}' 2>/dev/null \
    | python3 -c "import sys,json; print(json.load(sys.stdin).get('score',0))" 2>/dev/null)
[ "$SCORE" -ge 40 ] && echo -e "${GREEN}PASS (score=$SCORE)${NC}" && ((PASS++)) || echo -e "${RED}FAIL (score=$SCORE)${NC}" && ((FAIL++))

# Q5: 得分板总分
echo -n "  [Q5] 得分板总分 (预期≥120)... "
TOTAL=$(curl -s -H "$AUTH" http://localhost:8080/api/countermeasure/scoreboard 2>/dev/null \
    | python3 -c "import sys,json; print(json.load(sys.stdin).get('total_score',0))" 2>/dev/null)
[ "$TOTAL" -ge 120 ] && echo -e "${GREEN}PASS (total=$TOTAL)${NC}" && ((PASS++)) || echo -e "${RED}FAIL (total=$TOTAL)${NC}" && ((FAIL++))

echo ""
echo "  ┌──────────────────────────────────────┐"
echo "  │  快速验证: $PASS/5 PASS  $FAIL/5 FAIL          │"
echo "  └──────────────────────────────────────┘"
echo ""

#========================================================================
# Step 5: 运行全量 E2E 测试
#========================================================================
step "5: 运行全量 E2E 测试 (12阶段)"

TEST_SCRIPT="$SCRIPT_DIR/deploy/test-scripts/00_full_traceability_test.sh"
if [ -f "$TEST_SCRIPT" ]; then
    chmod +x "$TEST_SCRIPT"
    info "执行全量测试 (预计3-5分钟)..."
    echo ""
    bash "$TEST_SCRIPT" --manager http://localhost:8080 --skip-agent
    TEST_EXIT=$?
else
    warn "测试脚本不存在: $TEST_SCRIPT"
    TEST_EXIT=1
fi

#========================================================================
# Step 6: 交叉编译 Win11 Agent
#========================================================================
step "6: 交叉编译 Win11 Agent (windows/amd64)"

BUILD_SCRIPT="$SCRIPT_DIR/deploy/build-win-agent.sh"
if [ -f "$BUILD_SCRIPT" ]; then
    chmod +x "$BUILD_SCRIPT"
    bash "$BUILD_SCRIPT"
else
    warn "编译脚本不存在，手动编译:"
    echo "  CGO_ENABLED=0 GOOS=windows GOARCH=amd64 go build -o deploy/win-agent/honeypot-agent.exe ./cmd/honeypot/"
fi

#========================================================================
# 完成
#========================================================================
echo ""
echo -e "${GREEN}╔══════════════════════════════════════════════════╗${NC}"
echo -e "${GREEN}║              部署完成!                           ${NC}"
echo -e "${GREEN}╚══════════════════════════════════════════════════╝${NC}"
echo ""
echo "  Manager 运行中: http://localhost:8080 (PID: $MANAGER_PID)"
echo "  管理面板:       http://localhost:8080"
echo "  默认账号:       admin / admin123"
echo ""
echo "  停止服务:       kill $MANAGER_PID"
echo "  查看日志:       tail -f data/honeypot.log"
echo ""
echo "  Win11 Agent 部署包: deploy/win-agent/"
echo "  ─────────────────────────────────────────"
echo "  1. 修改 deploy/win-agent/config.yaml 中的 manager_addr"
echo "     将IP改为: ${CYAN}$MANAGER_IP${NC}:8443"
echo "  2. 将整个 deploy/win-agent/ 文件夹复制到 Win11"
echo "  3. 在 Win11 上以管理员运行 PowerShell:"
echo "     cd C:\\path\\to\\win-agent"
echo "     .\\deploy.ps1"
echo ""
echo "  完整测试 (推荐):"
echo "     ${CYAN}bash deploy/test-scripts/00_full_traceability_test.sh${NC}"
echo ""
echo "  测试报告: /tmp/laji_full_test_report.json"
echo ""
