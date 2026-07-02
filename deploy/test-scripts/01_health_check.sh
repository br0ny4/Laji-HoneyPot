#!/bin/bash
# ==========================================
# 01 — 健康检查 & 核心 API 验证
# ==========================================
MGR="http://10.111.31.103:8080"
KEY="hp-admin-2024"

echo "=== 1.1 Health Check ==="
curl -s "$MGR/healthz" | python3 -m json.tool 2>/dev/null || curl -s "$MGR/healthz"
echo ""

echo "=== 1.2 Stats ==="
curl -s -H "X-API-Key: $KEY" "$MGR/api/stats" | python3 -m json.tool
echo ""

echo "=== 1.3 VulnDB Count ==="
curl -s -H "X-API-Key: $KEY" "$MGR/api/vulns?limit=1" | python3 -c "import sys,json; d=json.load(sys.stdin); print(f'VulnDB: {d[\"total\"]} entries')"
echo ""

echo "=== 1.4 Scoreboard ==="
curl -s -H "X-API-Key: $KEY" "$MGR/api/countermeasure/scoreboard" | python3 -m json.tool
echo ""

echo "=== 1.5 Trap Config ==="
curl -s -H "X-API-Key: $KEY" "$MGR/api/traps/config" | python3 -m json.tool
echo ""

echo "=== 1.6 Cluster Nodes ==="
curl -s -k -H "X-API-Key: $KEY" "$MGR/api/cluster/nodes" | python3 -m json.tool
