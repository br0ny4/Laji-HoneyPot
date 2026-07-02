#!/bin/bash
# ==========================================
# run_all.sh — 一键运行全部测试
# 用法: chmod +x *.sh && ./run_all.sh
# ==========================================
DIR="$(cd "$(dirname "$0")" && pwd)"

echo ""
echo "╔══════════════════════════════════════════╗"
echo "║   Laji-HoneyPot 全量测试套件            ║"
echo "║   管理端: 10.111.31.103 (macOS)         ║"
echo "║   Agent:  10.111.29.4  (Windows)        ║"
echo "╚══════════════════════════════════════════╝"
echo ""

# 确认环境
if ! curl -s "http://10.111.31.103:8080/healthz" > /dev/null 2>&1; then
  echo "[ERROR] 管理端未运行！请先启动管理端。"
  exit 1
fi
echo "[OK] 管理端在线"

# Phase 1: Health
echo ""
echo "████████████████████████████████████████████"
echo "  PHASE 1: 健康检查 & 核心 API"
echo "████████████████████████████████████████████"
bash "$DIR/01_health_check.sh"

# Phase 2: Payload
echo ""
echo "████████████████████████████████████████████"
echo "  PHASE 2: Payload 投递 & 面包屑"
echo "████████████████████████████████████████████"
bash "$DIR/02_payload_delivery.sh"

# Phase 3: Countermeasure
echo ""
echo "████████████████████████████████████████████"
echo "  PHASE 3: 深度反制系统"
echo "████████████████████████████████████████████"
bash "$DIR/03_countermeasure.sh"

# Phase 4: Full Attack
echo ""
echo "████████████████████████████████████████████"
echo "  PHASE 4: 全量模拟攻击"
echo "████████████████████████████████████████████"
bash "$DIR/04_full_attack.sh"

# Phase 5: Cluster
echo ""
echo "████████████████████████████████████████████"
echo "  PHASE 5: 集群验证"
echo "████████████████████████████████████████████"
bash "$DIR/05_cluster_verify.sh"

echo ""
echo "╔══════════════════════════════════════════╗"
echo "║   全部测试完成！                        ║"
echo "║   管理后台: http://10.111.31.103:8080   ║"
echo "╚══════════════════════════════════════════╝"
