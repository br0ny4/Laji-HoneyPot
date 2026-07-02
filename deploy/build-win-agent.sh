#!/usr/bin/env bash
#===============================================================================
# Laji-HoneyPot Win11 Agent 交叉编译脚本
# 在 macOS M1 上交叉编译 Windows amd64 二进制
#
# 用法: bash deploy/build-win-agent.sh
# 输出: deploy/win-agent/honeypot-agent.exe
#===============================================================================
set -euo pipefail

GREEN='\033[0;32m'; BLUE='\033[0;34m'; CYAN='\033[0;36m'; NC='\033[0m'
info() { echo -e "${GREEN}[INFO]${NC}  $*"; }
step() { echo -e "\n${BLUE}==>${NC} ${CYAN}$*${NC}"; }

SCRIPT_DIR="$(cd "$(dirname "$0")/.." && pwd)"
OUTPUT_DIR="$SCRIPT_DIR/deploy/win-agent"

step "交叉编译 Win11 Agent"

# 查找 Go
GO_BIN=""
for go_path in go /usr/local/go/bin/go /opt/homebrew/bin/go; do
    if command -v "$go_path" &>/dev/null; then
        GO_BIN="$go_path"
        break
    fi
done

if [ -z "$GO_BIN" ]; then
    echo "错误: 未找到 Go，请先安装 Go ≥1.22"
    exit 1
fi

info "Go: $($GO_BIN version)"

# 交叉编译
export CGO_ENABLED=0
export GOOS=windows
export GOARCH=amd64

cd "$SCRIPT_DIR"
mkdir -p "$OUTPUT_DIR"

$GO_BIN build -ldflags="-s -w" -o "$OUTPUT_DIR/honeypot-agent.exe" ./cmd/honeypot/

if [ -f "$OUTPUT_DIR/honeypot-agent.exe" ]; then
    SIZE=$(ls -lh "$OUTPUT_DIR/honeypot-agent.exe" | awk '{print $5}')
    info "编译完成 → $OUTPUT_DIR/honeypot-agent.exe ($SIZE)"
else
    echo "错误: 编译失败"
    exit 1
fi

# 显示部署步骤
echo ""
echo "=============================================="
echo "  Win11 Agent 编译完成!"
echo "=============================================="
echo ""
echo "  部署到 Win11 (10.111.29.4):"
echo ""
echo "  1. 传输文件到 Win11:"
echo "     scp deploy/win-agent/honeypot-agent.exe user@10.111.29.4:C:/Laji-HoneyPot/"
echo "     scp deploy/win-agent/config.yaml user@10.111.29.4:C:/Laji-HoneyPot/"
echo "     scp deploy/win-agent/deploy.ps1 user@10.111.29.4:C:/Laji-HoneyPot/"
echo ""
echo "     (或通过 U盘 / 共享文件夹 / 微信 等方式传输)"
echo ""
echo "  2. 重要: 修改 config.yaml 中的 manager_addr"
echo "     将 10.111.31.103 替换为 macOS M1 本机的局域网IP"
echo "     获取方法: ipconfig getifaddr en0"
echo ""
echo "  3. 在 Win11 上以管理员运行 PowerShell:"
echo "     cd C:\\Laji-HoneyPot"
echo "     Set-ExecutionPolicy -Scope Process -ExecutionPolicy Bypass"
echo "     .\\deploy.ps1"
echo ""
echo "  4. 验证Agent连接 (在 macOS 上):"
echo "     curl -H 'Authorization: Bearer <token>' http://localhost:8080/api/cluster/status"
echo ""
echo "=============================================="
