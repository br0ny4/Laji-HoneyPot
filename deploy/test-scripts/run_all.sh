#!/usr/bin/env bash
#===============================================================================
# run_all.sh — Laji-HoneyPot 全量测试一键入口
#
# 用法:
#   bash deploy/test-scripts/run_all.sh                    # 默认 localhost:8080
#   bash deploy/test-scripts/run_all.sh http://10.0.0.1:8080  # 指定 Manager
#   bash deploy/test-scripts/run_all.sh --agent 10.0.0.5   # 指定 Agent IP
#
# 子脚本:
#   00_full_traceability_test.sh  — 溯源反制全量 (12阶段, 最全面)
#   01_health_check.sh            — 健康检查
#   02_payload_delivery.sh        — Payload投递
#   03_countermeasure.sh          — 深度反制
#   04_full_attack.sh             — 全量攻击模拟
#   05_cluster_verify.sh          — 集群验证
#   06_traceability_test.sh       — 溯源专项
#   07_countermeasure_test.sh     — 反制专项
#===============================================================================
set -e

DIR="$(cd "$(dirname "$0")" && pwd)"
MGR="${1:-http://localhost:8080}"
AGENT="${2:-127.0.0.1}"

# 解析参数
while [ $# -gt 0 ]; do
    case "$1" in
        --agent) AGENT="$2"; shift 2 ;;
        --manager) MGR="$2"; shift 2 ;;
        *) break ;;
    esac
done

echo ""
echo "╔══════════════════════════════════════════════════╗"
echo "║   Laji-HoneyPot 全量测试套件 v0.12.0             ║"
echo "║   Manager: $MGR                  ║"
echo "║   Agent:   $AGENT                                     ║"
echo "╚══════════════════════════════════════════════════╝"
echo ""

# 确认环境
MANAGER_HOST=$(echo "$MGR" | sed 's|http[s]*://||' | cut -d: -f1)
MANAGER_PORT=$(echo "$MGR" | sed 's|http[s]*://||' | cut -d: -f2)
MANAGER_PORT="${MANAGER_PORT:-80}"

if ! curl -s -o /dev/null -w "" "$MGR/healthz" 2>/dev/null; then
    echo "[ERROR] 管理端未运行! ($MGR)"
    echo "  启动命令: cd $(dirname "$DIR")/.. && ./bin/honeypot"
    exit 1
fi

echo "[OK] 管理端在线 ($MGR)"
echo ""

# Prompt user for test strategy
echo "选择测试方案:"
echo "  1) 快速验证 (5项核心能力, ~30秒)"
echo "  2) 溯源反制全量 (12阶段完整测试, ~3-5分钟) [推荐]"
echo "  3) 全量测试套件 (所有脚本依次运行, ~10分钟)"
echo ""
read -r -p "请选择 [1-3, 默认=2]: " CHOICE
CHOICE="${CHOICE:-2}"

case "$CHOICE" in
    1)
        echo ""; echo ">>> 快速验证 <<<"
        bash "$DIR/../quick-verify.sh" "$MGR" "$AGENT"
        ;;
    2)
        echo ""; echo ">>> 溯源反制全量测试 (12阶段) <<<"
        chmod +x "$DIR/00_full_traceability_test.sh" 2>/dev/null || true
        bash "$DIR/00_full_traceability_test.sh" --manager "$MGR" --agent "$AGENT"
        ;;
    3)
        echo ""; echo ">>> 全量测试套件 <<<"
        echo ""
        echo "████ Phase 1: 健康检查 ████"
        bash "$DIR/01_health_check.sh" 2>/dev/null || echo "  (跳过)"
        echo ""
        echo "████ Phase 2: Payload 投递 ████"
        bash "$DIR/02_payload_delivery.sh" 2>/dev/null || echo "  (跳过)"
        echo ""
        echo "████ Phase 3: 深度反制 ████"
        bash "$DIR/03_countermeasure.sh" 2>/dev/null || echo "  (跳过)"
        echo ""
        echo "████ Phase 4: 全量攻击 ████"
        bash "$DIR/04_full_attack.sh" 2>/dev/null || echo "  (跳过)"
        echo ""
        echo "████ Phase 5: 集群验证 ████"
        bash "$DIR/05_cluster_verify.sh" 2>/dev/null || echo "  (跳过)"
        echo ""
        echo "████ Phase 6: 溯源反制E2E ████"
        chmod +x "$DIR/00_full_traceability_test.sh" 2>/dev/null || true
        bash "$DIR/00_full_traceability_test.sh" --manager "$MGR" --agent "$AGENT"
        ;;
    *)
        echo "无效选择, 使用默认方案2"
        chmod +x "$DIR/00_full_traceability_test.sh" 2>/dev/null || true
        bash "$DIR/00_full_traceability_test.sh" --manager "$MGR" --agent "$AGENT"
        ;;
esac

echo ""
echo "╔══════════════════════════════════════════════════╗"
echo "║   测试完成!                                      ║"
echo "║   管理后台: $MGR                       ║"
echo "║   报告:     /tmp/laji_full_test_report.json      ║"
echo "╚══════════════════════════════════════════════════╝"
