#!/usr/bin/env bash
#===============================================================================
# Laji-HoneyPot macOS M1 Manager 完整部署脚本
# 编译后端(darwin/arm64) + 构建前端 + 启动管理端 + 蜜罐服务
#
# 用法:  chmod +x deploy-macos-mgr.sh && ./deploy-macos-mgr.sh
#
# 部署后:
#   管理面板: http://localhost:8080
#   蜜罐HTTP: http://localhost:80
#   集群监听: 0.0.0.0:8443 (Win11 Agent 连接用)
#===============================================================================
set -euo pipefail

RED='\033[0;31m'; GREEN='\033[0;32m'; YELLOW='\033[1;33m'
BLUE='\033[0;34m'; CYAN='\033[0;36m'; NC='\033[0m'
info()  { echo -e "${GREEN}[INFO]${NC}  $*"; }
warn()  { echo -e "${YELLOW}[WARN]${NC}  $*"; }
err()   { echo -e "${RED}[ERROR]${NC} $*"; exit 1; }
step()  { echo -e "\n${BLUE}==>${NC} ${CYAN}$*${NC}"; }

SCRIPT_DIR="$(cd "$(dirname "$0")/.." && pwd)"
cd "$SCRIPT_DIR"

echo -e "${CYAN}"
echo "  ╔══════════════════════════════════════════════╗"
echo "  ║   Laji-HoneyPot v0.12.0                      ║"
echo "  ║   macOS M1 Manager 完整部署                   ║"
echo "  ║   溯源反制蜜罐系统                              ║"
echo "  ╚══════════════════════════════════════════════╝"
echo -e "${NC}"

#========================================================================
# Step 1: 检测环境
#========================================================================
step "[1/8] 检测系统环境"

OS=$(uname -s)
ARCH=$(uname -m)
info "系统: $OS / $ARCH"

case "$ARCH" in
    arm64|aarch64) GOARCH="arm64" ;;
    x86_64|amd64)  GOARCH="amd64" ;;
    *) err "不支持的CPU架构: $ARCH" ;;
esac

# 获取本机局域网IP
MANAGER_IP=$(ipconfig getifaddr en0 2>/dev/null || echo "localhost")
info "本机管理端IP: $MANAGER_IP"

#========================================================================
# Step 2: 检查 Go
#========================================================================
step "[2/8] 检查 Go 环境"

GO_FOUND=false
for go_path in go /usr/local/go/bin/go /opt/homebrew/bin/go; do
    if command -v "$go_path" &>/dev/null; then
        GO_VER=$("$go_path" version 2>/dev/null | grep -oE 'go[0-9]+\.[0-9]+' | head -1 | sed 's/go//')
        if [ -n "$GO_VER" ]; then
            info "Go $GO_VER ($go_path)"
            GO_BIN="$go_path"
            GO_FOUND=true
            break
        fi
    fi
done

if [ "$GO_FOUND" = false ]; then
    warn "未找到 Go，请手动安装: https://go.dev/dl/"
    warn "或使用 Homebrew: brew install go"
    exit 1
fi

#========================================================================
# Step 3: 编译后端 (macOS ARM64)
#========================================================================
step "[3/8] 编译后端 (darwin/$GOARCH)"

mkdir -p bin
export CGO_ENABLED=0
export GOOS=darwin
export GOARCH="$GOARCH"

$GO_BIN build -ldflags="-s -w" -o bin/honeypot ./cmd/honeypot/
info "后端编译完成 → bin/honeypot ($(ls -lh bin/honeypot | awk '{print $5}'))"

#========================================================================
# Step 4: 构建前端
#========================================================================
step "[4/8] 检查并构建前端"

NODE_FOUND=false
for node_path in node /usr/local/bin/node /opt/homebrew/bin/node; do
    if command -v "$node_path" &>/dev/null; then
        NODE_FOUND=true
        break
    fi
done

if [ "$NODE_FOUND" = false ]; then
    warn "未找到 Node.js ≥18，跳过前端构建"
    warn "管理面板将不可用（API仍可正常使用）"
    warn "如需管理面板，请安装Node.js后运行: cd web && npm install && npm run build"
else
    cd "$SCRIPT_DIR/web"
    if [ ! -d "node_modules" ]; then
        info "安装前端依赖..."
        npm install
    fi
    info "构建前端..."
    npm run build
    cd "$SCRIPT_DIR"
    info "前端构建完成 → web/dist/"
fi

#========================================================================
# Step 5: 生成配置
#========================================================================
step "[5/8] 配置管理端"

# 备份现有配置
if [ -f config.yaml ]; then
    cp config.yaml config.yaml.bak 2>/dev/null || true
    info "已备份 config.yaml → config.yaml.bak"
fi

info "使用项目自带 config.yaml (api_addr=0.0.0.0:8080, cluster=manager)"
info "配置文件: $SCRIPT_DIR/config.yaml"

#========================================================================
# Step 6: 创建数据目录
#========================================================================
step "[6/8] 初始化数据目录"

mkdir -p data
info "数据目录: $SCRIPT_DIR/data/"

#========================================================================
# Step 7: 端口检查
#========================================================================
step "[7/8] 端口占用检查"

PORTS=(80 8080 8081 2222 2121 3306 3890 4450 5354 6379 8443 33890)
OCCUPIED=()
for port in "${PORTS[@]}"; do
    if lsof -iTCP:"$port" -sTCP:LISTEN &>/dev/null; then
        OCCUPIED+=("$port")
    fi
done

if [ ${#OCCUPIED[@]} -gt 0 ]; then
    warn "以下端口已被占用: ${OCCUPIED[*]}"
    warn "建议关闭占用程序后重试，或修改 config.yaml 中的端口配置"
    warn "查看占用: lsof -iTCP:80,8080 -sTCP:LISTEN"
fi

#========================================================================
# Step 8: 启动
#========================================================================
step "[8/8] 启动服务"

echo ""
echo -e "  ${GREEN}部署完成！${NC}"
echo ""
echo "  ┌─────────────────────────────────────────────────────┐"
echo "  │  启动命令:                                           │"
echo "  │    ${CYAN}cd $SCRIPT_DIR && ./bin/honeypot${NC}"
echo "  │                                                     │"
echo "  │  或后台运行:                                         │"
echo "  │    ${CYAN}nohup ./bin/honeypot > data/honeypot.log 2>&1 &${NC}"
echo "  │                                                     │"
echo "  │  管理面板:     http://localhost:8080                  │"
echo "  │  管理端IP:     ${CYAN}$MANAGER_IP${NC}"
echo "  │  集群监听:     ${CYAN}$MANAGER_IP:8443${NC} (Agent用)        │"
echo "  │  默认账号:     admin / admin123                      │"
echo "  │                                                     │"
echo "  │  蜜罐服务端口:                                        │"
echo "  │    HTTP:80  SSH:2222  FTP:2121  MySQL:3306           │"
echo "  │    Redis:6379  LDAP:3890  DNS:5354(udp)              │"
echo "  │    SMB:4450  RDP:33890                              │"
echo "  │                                                     │"
echo "  │  测试脚本:                                           │"
echo "  │    ${CYAN}bash deploy/test-scripts/05_traceability_e2e.sh${NC}"
echo "  │                                                     │"
echo "  │  Win11 Agent 部署包:                                 │"
echo "  │    deploy/win-agent/                                 │"
echo "  │  将 direwolf-agent-darwin-arm64 替换为 Win11 二进制   │"
echo "  └─────────────────────────────────────────────────────┘"
echo ""

# 询问是否立即启动
read -r -p "是否立即启动服务? [y/N]: " START_CONFIRM
if [[ "$START_CONFIRM" =~ ^[Yy]$ ]]; then
    info "正在启动 Laji-HoneyPot Manager..."
    ./bin/honeypot
fi
