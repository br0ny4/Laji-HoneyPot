#!/usr/bin/env bash
#===============================================================================
# Laji-HoneyPot 一键部署脚本
# 自动识别 OS/架构/环境 → 安装依赖 → 编译前端 → 编译后端 → 生成配置
# 支持: Linux (amd64/arm64), macOS (Intel/Apple Silicon), Windows (Git Bash/WSL)
#===============================================================================
set -euo pipefail

# ---- 颜色输出 ----
RED='\033[0;31m'; GREEN='\033[0;32m'; YELLOW='\033[1;33m'
BLUE='\033[0;34m'; CYAN='\033[0;36m'; NC='\033[0m'
info()  { echo -e "${GREEN}[INFO]${NC}  $*"; }
warn()  { echo -e "${YELLOW}[WARN]${NC}  $*"; }
err()   { echo -e "${RED}[ERROR]${NC} $*"; exit 1; }
step()  { echo -e "\n${BLUE}==>${NC} ${CYAN}$*${NC}"; }

# ---- 系统检测 ----
detect_os() {
    case "$(uname -s)" in
        Linux*)     OS="linux" ;;
        Darwin*)    OS="darwin" ;;
        MINGW*|MSYS*|CYGWIN*) OS="windows" ;;
        *)          err "不支持的操作系统: $(uname -s)" ;;
    esac
    ARCH=$(uname -m)
    case "$ARCH" in
        x86_64|amd64) ARCH="amd64" ;;
        aarch64|arm64) ARCH="arm64" ;;
        *) err "不支持的 CPU 架构: $ARCH" ;;
    esac
    info "检测到系统: ${OS}/${ARCH}"
}

# ---- 检测命令是否存在 ----
has() { command -v "$1" >/dev/null 2>&1; }

# ---- 安装 Go ----
install_go() {
    local GO_VER="1.22.10"
    # 尝试常见路径的 Go
    for trygo in go /usr/local/go/bin/go /opt/homebrew/bin/go; do
        if "$trygo" version >/dev/null 2>&1; then
            local current
            current=$("$trygo" version | sed -n 's/.*go\([0-9]\+\.[0-9]\+\).*/\1/p' | head -1)
            if [ -n "$current" ] && [ "$(printf '%s\n' "1.22" "$current" | sort -V | head -1)" = "1.22" ]; then
                info "Go $current 已满足要求 (≥1.22)"
                # 确保在 PATH 中
                export PATH="$(dirname "$trygo"):$PATH"
                return 0
            fi
        fi
    done
    warn "Go ≥1.22 未安装，正在自动安装..."
    local GO_URL="https://go.dev/dl/go${GO_VER}.${OS}-${ARCH}.tar.gz"
    case "$OS" in
        linux|darwin)
            curl -fsSL "$GO_URL" -o /tmp/go.tar.gz || warn "下载 Go 失败，请手动安装: https://go.dev/dl/"
            if [ -f /tmp/go.tar.gz ]; then
                if has sudo; then
                    sudo rm -rf /usr/local/go
                    sudo tar -C /usr/local -xzf /tmp/go.tar.gz
                else
                    rm -rf "$HOME/go"
                    tar -C "$HOME" -xzf /tmp/go.tar.gz
                    export PATH="$HOME/go/bin:$PATH"
                fi
                rm -f /tmp/go.tar.gz
            fi
            ;;
        windows)
            err "Windows 请手动安装 Go: https://go.dev/dl/go${GO_VER}.windows-amd64.msi"
            ;;
    esac
    if has go; then
        info "Go 安装完成: $(go version)"
    else
        warn "Go 未能自动安装完成，请手动安装后重试"
    fi
}

# ---- 安装 Node.js ----
install_node() {
    if has node; then
        local current
        current=$(node -v | sed 's/[^0-9]//g' | head -c 2)
        if [ "$current" -ge 18 ] 2>/dev/null; then
            info "Node.js $(node -v) 已满足要求 (≥18)"
            return 0
        fi
    fi
    warn "Node.js ≥18 未安装，正在通过 nvm 安装..."
    if [ ! -d "$HOME/.nvm" ]; then
        curl -o- https://raw.githubusercontent.com/nvm-sh/nvm/v0.40.1/install.sh | bash
        export NVM_DIR="$HOME/.nvm"
        [ -s "$NVM_DIR/nvm.sh" ] && \. "$NVM_DIR/nvm.sh"
    fi
    export NVM_DIR="$HOME/.nvm"
    [ -s "$NVM_DIR/nvm.sh" ] && \. "$NVM_DIR/nvm.sh"
    nvm install 18
    nvm use 18
    info "Node.js 安装完成: $(node -v)"
}

# ---- 安装 Git ----
install_git() {
    if has git; then
        info "Git 已安装: $(git --version | head -1)"
        return 0
    fi
    warn "Git 未安装，正在自动安装..."
    case "$OS" in
        linux)
            if has apt-get; then
                sudo apt-get update -qq && sudo apt-get install -y -qq git
            elif has yum; then
                sudo yum install -y git
            elif has dnf; then
                sudo dnf install -y git
            else
                err "无法自动安装 Git，请手动安装: https://git-scm.com"
            fi
            ;;
        darwin)
            if has brew; then
                brew install git
            else
                err "请先安装 Homebrew (https://brew.sh) 然后运行: brew install git"
            fi
            ;;
        windows) err "Windows 请安装 Git Bash: https://git-scm.com/download/win" ;;
    esac
    info "Git 安装完成"
}

# ---- PATH 恢复（针对 trae-sandbox 环境 PATH 退化） ----
ensure_path() {
    local missing=()
    local restored=()
    for cmd in go node npm git curl; do
        if ! command -v "$cmd" >/dev/null 2>&1; then
            missing+=("$cmd")
        fi
    done
    if [ ${#missing[@]} -eq 0 ]; then
        return 0
    fi
    # 预置常用 PATH 条目
    local extra_paths="/usr/local/bin:/opt/homebrew/bin:/usr/bin:/bin:$HOME/go/bin"
    # 附加 nvm node 路径
    for nvm_dir in "$HOME/.nvm/versions/node"/*; do
        if [ -d "$nvm_dir/bin" ]; then
            extra_paths="$extra_paths:$nvm_dir/bin"
        fi
    done 2>/dev/null
    export PATH="${extra_paths}:${PATH}"
    # 检查恢复了哪些
    for cmd in "${missing[@]}"; do
        if command -v "$cmd" >/dev/null 2>&1; then
            restored+=("$cmd")
        fi
    done
    local still_missing=()
    for cmd in "${missing[@]}"; do
        if ! command -v "$cmd" >/dev/null 2>&1; then
            still_missing+=("$cmd")
        fi
    done
    if [ ${#restored[@]} -gt 0 ]; then
        warn "PATH 恢复: ${restored[*]} 已恢复可用"
    fi
    if [ ${#still_missing[@]} -gt 0 ]; then
        warn "PATH 恢复不完全，以下命令仍不可用: ${still_missing[*]}"
    fi
}

# ---- 主流程 ----
main() {
    ensure_path

    echo -e "${CYAN}"
    echo "  ╔══════════════════════════════════════════╗"
    echo "  ║     Laji-HoneyPot 一键部署脚本           ║"
    echo "  ║     面向溯源反制的开源蜜罐系统           ║"
    echo "  ╚══════════════════════════════════════════╝"
    echo -e "${NC}"

    # 进入项目目录
    SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
    PROJECT_DIR="${SCRIPT_DIR}"
    cd "$PROJECT_DIR"

    # Step 1: 系统检测
    step "[1/7] 检测系统环境"
    detect_os

    # Step 2: 安装依赖
    step "[2/7] 检查并安装依赖"
    install_git
    install_go
    install_node

    # Step 3: 初始化 Go 模块（首次克隆后需要）
    step "[3/7] 初始化 Go 依赖"
    if [ ! -f "go.sum" ]; then
        go mod tidy
    fi
    info "Go 依赖就绪"

    # Step 4: 编译后端
    step "[4/7] 编译后端"
    go build -o bin/honeypot ./cmd/honeypot/
    info "后端编译完成 → bin/honeypot"

    # Step 5: 安装前端依赖 + 构建
    step "[5/7] 安装前端依赖并构建"
    cd "$PROJECT_DIR/web"
    if [ ! -d "node_modules" ]; then
        npm install --silent
    fi
    npm run build --silent
    cd "$PROJECT_DIR"
    info "前端构建完成 → web/dist/"

    # Step 6: 生成默认配置（如不存在）
    step "[6/7] 检查配置文件"
    if [ ! -f "config.yaml" ]; then
        cat > config.yaml << 'YAML'
# Laji-HoneyPot 配置文件（由 install.sh 自动生成）
log_level: info
api_addr: "127.0.0.1:8080"
data_dir: "./data"
api_key: "hp-admin-2024"

plugins:
  honeypot-engine:
    enabled: true
    http_port: 8081
    mysql_port: 3306
    redis_port: 6379
    ssh_port: 2222
    ftp_port: 2121
    ldap_port: 3890
    dns_port: 5354
    smb_port: 4450
    rdp_port: 33890
  traceability-engine:
    enabled: true
  ops-engine:
    enabled: true

alerts: {}
YAML
        info "已生成默认配置文件 config.yaml"
    else
        info "config.yaml 已存在，跳过"
    fi

    # Step 7: 验证 + 启动提示
    step "[7/7] 部署完成"

    echo ""
    echo -e "  ${GREEN}✓ 所有组件已就绪${NC}"
    echo ""
    echo "  ┌─────────────────────────────────────────────┐"
    echo "  │  启动蜜罐:                                   │"
    echo "  │    ${CYAN}./bin/honeypot${NC}                              │"
    echo "  │                                             │"
    echo "  │  访问管理后台:                               │"
    echo "  │    ${CYAN}http://127.0.0.1:8080${NC}                     │"
    echo "  │                                             │"
    echo "  │  测试指纹采集:                               │"
    echo "  │    curl 'http://127.0.0.1:8081/api/collect?d=test' │"
    echo "  │                                             │"
    echo "  │  查看日志:                                   │"
    echo "  │    tail -f data/honeypot.log                 │"
    echo "  └─────────────────────────────────────────────┘"
}

main "$@"
