#!/bin/bash
# ==========================================
# 05 — Agent 心跳 & 集群验证
# Agent 注册后运行此脚本验证集群通信
# ==========================================
MANAGER_IP="${MANAGER_IP:-127.0.0.1}"
AGENT_IP="${AGENT_IP:-127.0.0.1}"
AGENT_API_KEY="${AGENT_API_KEY:-YOUR_AGENT_API_KEY}"
MGR="http://${MANAGER_IP}:8080"
KEY="hp-admin-2024"

echo "=========================================="
echo "  Agent 集群验证"
echo "=========================================="
echo ""

echo "=== 集群节点列表 ==="
curl -s -k -H "X-API-Key: $KEY" "$MGR/api/cluster/nodes" | python3 -m json.tool 2>/dev/null || echo "(no nodes or endpoint error)"

echo ""
echo "=== 管理端 Stats ==="
curl -s -H "X-API-Key: $KEY" "$MGR/api/stats" | python3 -m json.tool

echo ""
echo "=== Agent 端健康检查 (${AGENT_IP}:8080) ==="
agent_hc=$(curl -s -o /dev/null -w "%{http_code}" "http://${AGENT_IP}:8080/healthz" 2>/dev/null)
echo "  Agent healthz: HTTP $agent_hc"

agent_api=$(curl -s -o /dev/null -w "%{http_code}" -H "X-API-Key: $AGENT_API_KEY" "http://${AGENT_IP}:8080/api/stats" 2>/dev/null)
echo "  Agent stats: HTTP $agent_api"

echo ""
echo "=== Agent 陷阱端口扫描 ==="
for port in 8081 3306 6379 2222 2121 3890 5354 4450 33890; do
  timeout 2 bash -c "echo >/dev/tcp/${AGENT_IP}/$port" 2>/dev/null && echo "  $port: OPEN" || echo "  $port: -"
done
