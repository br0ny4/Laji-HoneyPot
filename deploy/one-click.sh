#!/usr/bin/env bash
#===============================================================================
# Laji-HoneyPot v0.17.1 一键部署+全量测试脚本
#
# macOS M1 Manager 部署 + Win11 Agent 交叉编译
#
# 使用方式: bash deploy/one-click.sh [MANAGER_IP]
#   MANAGER_IP 默认使用 en0 接口 IP
#===============================================================================
set -e
PROJECT="$(cd "$(dirname "$0")/.." && pwd)"
VERSION="0.17.1"

if [ -n "$1" ]; then
    MGR_IP="$1"
else
    MGR_IP=$(ipconfig getifaddr en0 2>/dev/null || echo "127.0.0.1")
fi

GREEN='\033[0;32m'; CYAN='\033[0;36m'; YELLOW='\033[1;33m'; NC='\033[0m'
ok() { echo -e "  ${GREEN}[OK]${NC} $1"; }
info() { echo -e "  ${CYAN}[→]${NC} $1"; }
warn() { echo -e "  ${YELLOW}[!]${NC} $1"; }

echo "=============================================="
echo "  Laji-HoneyPot v$VERSION 一键部署"
echo "  Manager IP: $MGR_IP"
echo "=============================================="
echo ""

# ---- Step 1: 编译后端 ----
info "Step 1/6: 编译后端 (darwin/arm64)..."
cd "$PROJECT"
GOOS=darwin GOARCH=arm64 CGO_ENABLED=0 go build -ldflags="-s -w" -o bin/honeypot ./cmd/honeypot/
ok "后端编译完成"

# ---- Step 2: 构建前端 ----
info "Step 2/6: 构建前端..."
cd "$PROJECT/web"
npm ci --silent 2>/dev/null || true
npx vite build --outDir ../web-dist 2>&1 | tail -1
ok "前端构建完成"

# ---- Step 3: 启动 Manager ----
info "Step 3/6: 启动 Manager..."
cd "$PROJECT"
pkill -f "bin/honeypot" 2>/dev/null || true
sleep 1
[ -d "web-dist" ] && export HONEYPOT_WEB_DIR="$PWD/web-dist"
./bin/honeypot > /tmp/honeypot-oneclick.log 2>&1 &
MGR_PID=$!
sleep 3
if curl -s http://127.0.0.1:8080/healthz | grep -q ok; then
    ok "Manager 已启动 (PID=$MGR_PID)"
else
    warn "Manager 启动失败, 查看 /tmp/honeypot-oneclick.log"
    exit 1
fi

# ---- Step 4: 登录获取 Token ----
info "Step 4/6: JWT 登录 + Agent 部署包生成..."
TOKEN=$(curl -s -X POST http://127.0.0.1:8080/api/auth/login \
    -H "Content-Type: application/json" \
    -d '{"username":"admin","password":"admin123"}' \
    | python3 -c "import sys,json; print(json.load(sys.stdin).get('access_token',''))" 2>/dev/null)
if [ -n "$TOKEN" ]; then
    ok "Token 获取成功"

    # 下载部署包
    curl -s -o "$PROJECT/deploy/agent-package-linux.zip" "http://127.0.0.1:8080/api/cluster/agent/package?os=linux&scenario=full"
    curl -s -o "$PROJECT/deploy/agent-package-windows.zip" "http://127.0.0.1:8080/api/cluster/agent/package?os=windows&scenario=full"
    ok "部署包已导出: deploy/agent-package-linux.zip, deploy/agent-package-windows.zip"
else
    warn "登录失败, 跳过部署包下载"
fi

# ---- Step 5: 全量功能测试 ----
info "Step 5/6: 全量功能测试..."
cd "$PROJECT"
bash scripts/full-test.sh 2>&1 | grep -E "PASS|FAIL|总计|===|Phase" || true

# ---- Step 6: 交叉编译 Win Agent ----
info "Step 6/6: 交叉编译 Win11 Agent..."
bash "$PROJECT/deploy/build-win-agent.sh" "$MGR_IP" 2>&1 | tail -5

echo ""
echo "=============================================="
echo "  一键部署完成 (v$VERSION)"
echo "=============================================="
echo ""
echo "  管理端: http://$MGR_IP:8080"
echo "  日志:   /tmp/honeypot-oneclick.log"
echo "  PID:    $MGR_PID"
echo ""
echo "  部署包: deploy/agent-package-linux.zip"
echo "          deploy/agent-package-windows.zip"
echo ""
echo "  快速验证: bash deploy/quick-verify.sh http://$MGR_IP:8080"
echo "=============================================="
