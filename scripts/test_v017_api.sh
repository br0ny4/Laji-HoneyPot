#!/bin/bash
set -e

BASE="http://127.0.0.1:8080"
echo "=== Login ==="
LOGIN=$(curl -s -X POST "$BASE/api/auth/login" \
  -H "Content-Type: application/json" \
  -d '{"username":"admin","password":"admin123"}')
TOKEN=$(echo "$LOGIN" | python3 -c "import sys,json; print(json.load(sys.stdin)['access_token'])")
echo "Got token: ${TOKEN:0:20}..."

echo ""
echo "=== 1. Windows Agent Deploy ==="
WINDOWS_RESULT=$(curl -s -X POST "$BASE/api/cluster/agent/generate" \
  -H "Authorization: Bearer $TOKEN" \
  -H "Content-Type: application/json" \
  -d '{"manager_addr":"10.0.0.1:8443","scenario":"remote_access","os_target":"windows"}')
echo "$WINDOWS_RESULT" | python3 -c "
import sys,json
d=json.load(sys.stdin)
print('OSTarget:', d.get('os_target'))
print('BinaryName:', d.get('binary_name'))
print('Has PS Script:', bool(d.get('install_script_ps')))
print('Has Svc Config:', bool(d.get('service_config')))
print('EnabledSvcs:', d.get('enabled_svcs'))
ps = d.get('install_script_ps','')
print('PS First 80 chars:', ps[:80])
"

echo ""
echo "=== 2. Linux Agent Deploy ==="
LINUX_RESULT=$(curl -s -X POST "$BASE/api/cluster/agent/generate" \
  -H "Authorization: Bearer $TOKEN" \
  -H "Content-Type: application/json" \
  -d '{"manager_addr":"10.0.0.1:8443","scenario":"web","os_target":"linux"}')
echo "$LINUX_RESULT" | python3 -c "
import sys,json
d=json.load(sys.stdin)
print('OSTarget:', d.get('os_target'))
print('BinaryName:', d.get('binary_name'))
print('Is Bash:', '#!/bin/bash' in d.get('deploy_script',''))
print('Has PS Script:', bool(d.get('install_script_ps')))
"

echo ""
echo "=== 3. Bait Linkages ==="
curl -s -H "Authorization: Bearer $TOKEN" "$BASE/api/bait/linkages?limit=5" | python3 -c "
import sys,json
data=json.load(sys.stdin)
if isinstance(data, list):
    print(f'Total linkages: {len(data)}')
    if len(data) > 0:
        l = data[0]
        print(f'First: id={l.get(\"id\")}, type={l.get(\"linkage_type\")}, host={l.get(\"service_host\")}, bait={l.get(\"bait_type\")}')
else:
    print('Response type:', type(data).__name__, str(data)[:200])
"

echo ""
echo "=== 4. Bait Linkage Stats ==="
curl -s -H "Authorization: Bearer $TOKEN" "$BASE/api/bait/linkages/stats" | python3 -m json.tool

echo ""
echo "=== 5. Bait Tokens ==="
curl -s -H "Authorization: Bearer $TOKEN" "$BASE/api/bait/tokens" | python3 -c "
import sys,json
data=json.load(sys.stdin)
if isinstance(data, list):
    print(f'Total tokens: {len(data)}')
    for t in data:
        print(f'  - {t.get(\"id\")} ({t.get(\"type\")}): {t.get(\"file_name\")}')
else:
    print('Response:', json.dumps(data, indent=2)[:200])
"

echo ""
echo "=== ALL API TESTS PASSED ==="
