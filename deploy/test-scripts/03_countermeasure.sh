#!/bin/bash
# ==========================================
# 03 — 深度反制系统测试
# 测试: 外传链路 / 得分引擎 / 冷却机制 / 合规审计 / 拓扑
# ==========================================
MANAGER_IP="${MANAGER_IP:-127.0.0.1}"
AGENT_IP="${AGENT_IP:-127.0.0.1}"
MGR="http://${MANAGER_IP}:8080"
KEY="hp-admin-2024"

echo "=========================================="
echo "  深度反制系统 — 全链路测试"
echo "=========================================="
echo ""

# ----- 3.1 Screen Capture Exfil -----
echo "=== 3.1 Screen Capture Exfil ==="
resp=$(curl -s -X POST "$MGR/api/countermeasure/exfil" \
  -H "Content-Type: application/json" \
  -d "{\"type\":\"screen_capture\",\"target_ip\":\"$AGENT_IP\",\"data_type\":\"screen_capture\",\"data\":{\"width\":1920,\"height\":1080,\"dpr\":2,\"captured_at\":\"2026-07-02T10:00:00Z\"}}"')
echo "  Response: $resp"

# ----- 3.2 File Scan Exfil -----
echo "=== 3.2 File Scan Exfil ==="
resp=$(curl -s -X POST "$MGR/api/countermeasure/exfil" \
  -H "Content-Type: application/json" \
  -d "{\"type\":\"file_scan\",\"target_ip\":\"$AGENT_IP\",\"data_type\":\"file_scan\",\"data\":{\"tool_dirs\":{\"burpsuite\":\"C:\\\\Tools\\\\BurpSuite\",\"nmap\":\"C:\\\\Tools\\\\Nmap\",\"sqlmap\":\"/opt/sqlmap\",\"hydra\":\"/usr/bin/hydra\",\"metasploit\":\"C:\\\\metasploit-framework\"},\"sensitive_files\":[\"passwords.txt\",\"config.yaml\",\"ssh_key\",\"token.txt\"],\"clipboard\":\"admin:Password123!\"}}"')
echo "  Response: $resp"

# ----- 3.3 Net Probe Exfil -----
echo "=== 3.3 Net Probe Exfil ==="
resp=$(curl -s -X POST "$MGR/api/countermeasure/exfil" \
  -H "Content-Type: application/json" \
  -d "{\"type\":\"net_probe\",\"target_ip\":\"$AGENT_IP\",\"data_type\":\"net_probe\",\"data\":{\"internal_ips\":[\"10.0.0.5\",\"10.0.0.6\",\"192.168.1.100\"],\"peer_assets\":[{\"ip\":\"10.0.0.5\",\"open_ports\":[22,3389,8080],\"services\":[\"ssh\",\"rdp\"],\"role\":\"attacker_workstation\",\"confidence\":0.85},{\"ip\":\"10.0.0.6\",\"open_ports\":[80,443,22],\"services\":[\"http\",\"https\",\"ssh\"],\"role\":\"command_node\",\"confidence\":0.72}]}}"')
echo "  Response: $resp"

# ----- 3.4 Duplicate (Cooldown Test) -----
echo "=== 3.4 Cooldown Test (duplicate screen_capture) ==="
resp=$(curl -s -X POST "$MGR/api/countermeasure/exfil" \
  -H "Content-Type: application/json" \
  -d "{\"type\":\"screen_capture\",\"target_ip\":\"$AGENT_IP\",\"data_type\":\"screen_capture\",\"data\":{\"width\":1920,\"height\":1080}}"')
echo "  Response: $resp  (score should be 0 = cooldown active)"

# ----- 3.5 Scoreboard -----
echo ""
echo "=== 3.5 Scoreboard ==="
curl -s -H "X-API-Key: $KEY" "$MGR/api/countermeasure/scoreboard" | python3 -m json.tool

# ----- 3.6 Audit Trail -----
echo ""
echo "=== 3.6 Audit Trail ==="
curl -s -H "X-API-Key: $KEY" "$MGR/api/countermeasure/audit" | python3 -c "
import sys, json
d = json.load(sys.stdin)
print(f'  Total entries: {d[\"total\"]}')
for e in d['entries']:
    print(f'  [{e[\"id\"][:12]}] {e[\"event_type\"]}: compliant={e[\"compliant\"]}, sig={e[\"signature\"][:16]}...')
"

# ----- 3.7 Topology -----
echo ""
echo "=== 3.7 Topology ==="
curl -s -H "X-API-Key: $KEY" "$MGR/api/countermeasure/topology" | python3 -c "
import sys, json
d = json.load(sys.stdin)
print(f'  Team size: {d[\"team_size\"]}')
for n in d['nodes']:
    print(f'  Node: {n[\"ip\"]} ({n[\"status\"]}) role={n[\"role\"]}')
"

# ----- 3.8 GET (Image Beacon) Mode -----
echo ""
echo "=== 3.8 Image Beacon (GET) Exfil ==="
resp=$(curl -s "$MGR/api/countermeasure/exfil?d=base64encodeddata&tt=file_scan")
echo "  Response: $resp"

echo ""
echo "=== All Countermeasure Tests Complete ==="
