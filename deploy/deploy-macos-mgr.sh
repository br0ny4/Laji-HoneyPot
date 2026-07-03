#!/usr/bin/env bash
#===============================================================================
# Laji-HoneyPot macOS M1 Manager v0.17.1 完整部署脚本
#
# 使用方式: bash deploy/deploy-macos-mgr.sh [MANAGER_IP]
#   MANAGER_IP 可选, 默认用 en0 接口 IP (局域网 IP)
#===============================================================================
set -e
PROJECT="$(cd "$(dirname "$0")/.." && pwd)"
VERSION="0.17.1"

# 默认端口
API_PORT=8080
CLUSTER_PORT=8443

# Manager 地址 (Agent 节点连接用)
if [ -n "$1" ]; then
    MANAGER_IP="$1"
else
    MANAGER_IP=$(ipconfig getifaddr en0 2>/dev/null || echo "127.0.0.1")
fi

GREEN='\033[0;32m'; CYAN='\033[0;36m'; NC='\033[0m'
ok() { echo -e "  ${GREEN}[OK]${NC} $1"; }
info() { echo -e "  ${CYAN}[→]${NC} $1"; }

echo "=============================================="
echo "  Laji-HoneyPot v$VERSION Manager 部署"
echo "  Manager IP: $MANAGER_IP"
echo "=============================================="
echo ""

# ---- Step 1: 编译后端 ----
info "Step 1/4: 编译后端 (darwin/arm64)..."
cd "$PROJECT"
GOOS=darwin GOARCH=arm64 go build -ldflags="-s -w" -o bin/honeypot ./cmd/honeypot/
ok "后端编译完成 (arm64 native, $(du -sh bin/honeypot | cut -f1))"

# ---- Step 2: 构建前端 ----
info "Step 2/4: 构建前端..."
cd "$PROJECT/web"
npm ci --silent 2>/dev/null || npm install --silent
npx vite build --outDir ../web-dist 2>&1 | tail -1
ok "前端构建完成"

# ---- Step 3: 启动 Manager ----
info "Step 3/4: 启动 Manager..."
cd "$PROJECT"

# 停止旧进程
pkill -f "bin/honeypot" 2>/dev/null || true
sleep 1

# 确保 web-dist 存在
if [ -d "web-dist" ]; then
    export HONEYPOT_WEB_DIR="$PWD/web-dist"
fi

./bin/honeypot > /tmp/honeypot-mgr.log 2>&1 &
PID=$!
sleep 3

# 验证启动
if curl -s http://localhost:$API_PORT/healthz | grep -q ok; then
    ok "Manager 已启动 (PID=$PID, 端口=$API_PORT)"
else
    echo "  [FAIL] Manager 启动失败, 查看 /tmp/honeypot-mgr.log"
    exit 1
fi

# ---- Step 4: 部署验证 ----
info "Step 4/4: 部署验证..."

echo ""
echo "=============================================="
echo "  部署完成 (v$VERSION)"
echo "=============================================="
echo ""
echo "  管理端:"
echo "    API:           http://$MANAGER_IP:$API_PORT"
echo "    前端:          http://$MANAGER_IP:$API_PORT"
echo "    集群监听:      $MANAGER_IP:$CLUSTER_PORT (Agent连接)"
echo "    健康检查:      http://$MANAGER_IP:$API_PORT/healthz"
echo ""
echo "  日志:  /tmp/honeypot-mgr.log"
echo ""
echo "  Agent 部署 (v0.17.1 双模式):"
echo "    方式1-一键拉取: Web UI → Agent部署 → 选择Windows/Linux → 一键拉取模式 → 复制命令"
echo "    方式2-手动部署: Web UI → Agent部署 → 手动部署模式 → 下载部署包 → 发送到目标主机"
echo "    方式3-API调用:  curl http://$MANAGER_IP:$API_PORT/api/cluster/agent/package?os=linux"
echo ""
echo "  快速验证:  bash deploy/quick-verify.sh http://$MANAGER_IP:$API_PORT"
echo "  全量测试:  bash scripts/full-test.sh"
echo "=============================================="
