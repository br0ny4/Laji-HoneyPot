#!/usr/bin/env bash
#===============================================================================
# Laji-HoneyPot v0.17.1 Win11 Agent 交叉编译脚本 (macOS → Windows)
#
# 使用方式:
#   bash deploy/build-win-agent.sh [MANAGER_IP]
#   编译完成后二进制输出到 deploy/win-agent/
#
# v0.17.1 新增 — 双模式部署:
#   方式1-一键拉取: 在 Win11 上执行管理端生成的 pull_command
#   方式2-手动部署: 将 deploy/win-agent/ 目录内容发送到 Win11
#===============================================================================
set -e
PROJECT="$(cd "$(dirname "$0")/.." && pwd)"
VERSION="0.17.1"
OUTDIR="$PROJECT/deploy/win-agent"
MANAGER_IP="${1:-}"

GREEN='\033[0;32m'; CYAN='\033[0;36m'; NC='\033[0m'
ok() { echo -e "  ${GREEN}[OK]${NC} $1"; }
info() { echo -e "  ${CYAN}[→]${NC} $1"; }

echo "=============================================="
echo "  Laji-HoneyPot v$VERSION Win11Agent 编译"
echo "  编译平台: $(uname -m) -> windows/amd64"
echo "=============================================="
echo ""

# ---- Step 1: 交叉编译 ----
info "Step 1/3: 交叉编译 Windows Agent..."
cd "$PROJECT"
GOOS=windows GOARCH=amd64 CGO_ENABLED=0 go build -ldflags="-s -w" -o "$OUTDIR/honeypot-agent.exe" ./cmd/honeypot/
ok "编译完成: $OUTDIR/honeypot-agent.exe ($(du -sh "$OUTDIR/honeypot-agent.exe" | cut -f1))"

# ---- Step 2: 从管理端拉取部署包 ----
info "Step 2/3: 拉取 Agent 部署包..."
if [ -n "$MANAGER_IP" ]; then
    MGMT_URL="http://$MANAGER_IP:8080"
    if curl -s -o "$OUTDIR/agent-package.zip" "$MGMT_URL/api/cluster/agent/package?os=windows" 2>/dev/null; then
        unzip -o "$OUTDIR/agent-package.zip" -d "$OUTDIR/" > /dev/null 2>&1
        ok "从管理端拉取部署包成功 ($MGMT_URL)"
    else
        info "管理端不可达, 使用本地模板"
    fi
else
    info "未指定管理端地址, 跳过远程拉取"
fi

# ---- Step 3: 部署指引 ----
info "Step 3/3: 部署指引..."

echo ""
echo "=============================================="
echo "  编译完成 (v$VERSION) — 部署指引"
echo "=============================================="
echo ""
echo "  产出物: deploy/win-agent/"
echo "    honeypot-agent.exe   Agent 二进制 (windows/amd64)"
echo "    config.yaml          配置文件"
echo "    deploy.ps1           PowerShell 一键启动脚本 (v0.17.1)"
echo "    deploy.bat           CMD 批处理启动"
echo ""
echo "  v0.17.1 双模式部署:"
echo ""
echo "  【方式1: 一键拉取 (推荐)】"
echo "    Web UI -> Agent部署 -> Windows + 一键拉取 -> 复制命令"
echo "    在 Win11 PowerShell (管理员) 中粘贴执行"
echo "    自动下载配置+二进制+启动, 无需手动传文件"
echo ""
echo "  【方式2: 手动部署】"
echo "    1. 将 deploy/win-agent/ 目录复制到 Win11"
echo "    2. 编辑 config.yaml, 将 MANAGER_IP_PLACEHOLDER 替换为管理端 IP"
echo "    3. 右键 PowerShell -> 以管理员身份运行"
echo "    4. Set-ExecutionPolicy -Scope Process -ExecutionPolicy Bypass"
echo "    5. .\\deploy.ps1"
echo "=============================================="
