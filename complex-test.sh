#!/bin/bash
# ═══════════════════════════════════════════════════════════════
#  AEGIRA COMPLEX TEST — Real-World Scenario
#  For: 64-bit Linux (x86_64 / ARM64)
#  Usage: sudo ./complex-test.sh
# ═══════════════════════════════════════════════════════════════

set -e

GREEN='\033[0;32m'
YELLOW='\033[1;33m'
RED='\033[0;31m'
BLUE='\033[0;34m'
CYAN='\033[0;36m'
NC='\033[0m'

if [ "$EUID" -ne 0 ]; then
    echo -e "${RED}[ERROR] Please run as root: sudo ./complex-test.sh${NC}"
    exit 1
fi

# ─── Helpers ───
get_http_code() {
    local code
    code=$(curl -s -o /dev/null -w "%{http_code}" --max-time 3 "$1" 2>/dev/null | tr -d '\n\r[:space:]' | head -c 3)
    [ -z "$code" ] && echo "000" || echo "$code"
}

banner() {
    echo ""
    echo -e "${BLUE}════════════════════════════════════════════════════════${NC}"
    echo -e "${BLUE}  $1${NC}"
    echo -e "${BLUE}════════════════════════════════════════════════════════${NC}"
}

cleanup() {
    echo -e "\n${YELLOW}[CLEANUP] Removing test containers...${NC}"
    pkill -f "journalctl -u aegira" 2>/dev/null || true
    docker rm -f complex-api-1 complex-api-2 complex-service-1 complex-service-2 2>/dev/null || true
    rm -f /etc/aegira/rules/custom/complex-*.json 2>/dev/null || true
    systemctl restart aegira 2>/dev/null || true
    echo -e "${GREEN}[CLEANUP] Done.${NC}"
}

trap cleanup EXIT

# ═══════════════════════════════════════════════════════════
#  INTRO
# ═══════════════════════════════════════════════════════════
banner "AEGIRA COMPLEX TEST"

echo ""
echo -e "${CYAN}Real-world scenario:${NC}"
echo "  • 2 containers running with HTTP APIs"
echo "  • Container 1's API dies → Aegira fixes it inside the container"
echo "  • Container 2 crashes → Aegira restarts it"
echo "  • Both containers crash + both APIs dead → Aegira fixes everything"
echo ""
echo -e "${YELLOW}Duration: ~4 minutes${NC}"
echo ""
read -p "Press ENTER to start..."

# ═══════════════════════════════════════════════════════════
#  INITIAL SETUP
# ═══════════════════════════════════════════════════════════
banner "INITIAL SETUP"

echo -e "${YELLOW}[INIT] Cleaning up...${NC}"
docker rm -f complex-api-1 complex-api-2 complex-service-1 complex-service-2 2>/dev/null || true
rm -f /etc/aegira/rules/custom/complex-*.json 2>/dev/null || true
systemctl restart aegira
sleep 2
echo -e "${GREEN}[INIT] Clean.${NC}"

# ─── Start Container 1 (API) ───
echo -e "\n${YELLOW}[INIT] Starting complex-api-1 (HTTP API)...${NC}"
docker run -d --name complex-api-1 -p 18081:8080 python:3-alpine \
    sh -c 'while true; do python3 -m http.server 8080 --bind 0.0.0.0; sleep 30; done'

# ─── Start Container 2 (API) ───
echo -e "${YELLOW}[INIT] Starting complex-api-2 (HTTP API)...${NC}"
docker run -d --name complex-api-2 -p 18082:8080 python:3-alpine \
    sh -c 'while true; do python3 -m http.server 8080 --bind 0.0.0.0; sleep 30; done'

echo "  Waiting 12s for APIs to be ready..."
sleep 12

# ─── Verify both APIs ───
echo -e "\n${YELLOW}[INIT] Verifying APIs...${NC}"
for port in 18081 18082; do
    HTTP_CODE=$(get_http_code "http://127.0.0.1:$port/")
    echo "    Port $port: HTTP $HTTP_CODE"
    if [ "$HTTP_CODE" != "200" ]; then
        echo -e "  ${RED}❌ Container on port $port failed to start.${NC}"
        docker logs complex-api-1 2>&1 | tail -5
        docker logs complex-api-2 2>&1 | tail -5
        exit 1
    fi
done
echo -e "  ${GREEN}✅ Both APIs up.${NC}"

# ═══════════════════════════════════════════════════════════
#  CONFIGURE AEGIRA
# ═══════════════════════════════════════════════════════════
banner "CONFIGURING AEGIRA"

echo -e "${YELLOW}[CONFIG] Setting multi-container targets...${NC}"
sudo aegira configure multi complex-api-1 complex-api-2 > /dev/null
sleep 2

echo -e "${YELLOW}[CONFIG] Creating HTTP health rules...${NC}"

# Rule for Container 1
tee /etc/aegira/rules/custom/complex-api-1.json > /dev/null << 'EOF'
[{
  "id": "complex_api_1_recovery",
  "name": "Complex API 1 Recovery",
  "severity": "critical",
  "trigger": {
    "type": "http_health",
    "container": "complex-api-1",
    "url": "http://127.0.0.1:18081/",
    "expected_status": 200,
    "interval_secs": 5
  },
  "error_patterns": ["HTTP health check failed"],
  "context_patterns": ["complex-api-1"],
  "remediation": {
    "type": "container_exec",
    "container": "complex-api-1",
    "args": ["sh", "-c", "kill $(pgrep -f 'http.server') 2>/dev/null || true; sleep 1; setsid python3 -m http.server 8080 --bind 0.0.0.0 > /dev/null 2>&1 < /dev/null &"]
  },
  "verification": {
    "type": "container_http_status",
    "container": "complex-api-1",
    "url": "http://127.0.0.1:18081/",
    "expected_status": 200
  },
  "action": "auto_recover",
  "priority": 40
}]
EOF

# Rule for Container 2
tee /etc/aegira/rules/custom/complex-api-2.json > /dev/null << 'EOF'
[{
  "id": "complex_api_2_recovery",
  "name": "Complex API 2 Recovery",
  "severity": "critical",
  "trigger": {
    "type": "http_health",
    "container": "complex-api-2",
    "url": "http://127.0.0.1:18082/",
    "expected_status": 200,
    "interval_secs": 5
  },
  "error_patterns": ["HTTP health check failed"],
  "context_patterns": ["complex-api-2"],
  "remediation": {
    "type": "container_exec",
    "container": "complex-api-2",
    "args": ["sh", "-c", "kill $(pgrep -f 'http.server') 2>/dev/null || true; sleep 1; setsid python3 -m http.server 8080 --bind 0.0.0.0 > /dev/null 2>&1 < /dev/null &"]
  },
  "verification": {
    "type": "container_http_status",
    "container": "complex-api-2",
    "url": "http://127.0.0.1:18082/",
    "expected_status": 200
  },
  "action": "auto_recover",
  "priority": 40
}]
EOF

systemctl restart aegira
sleep 4

echo -e "${YELLOW}[CONFIG] Verifying rules loaded...${NC}"
if aegira rules list 2>/dev/null | grep -q complex_api_1_recovery && \
   aegira rules list 2>/dev/null | grep -q complex_api_2_recovery; then
    echo -e "  ${GREEN}✅ Both rules loaded.${NC}"
else
    echo -e "  ${RED}❌ Rules not loaded.${NC}"
    exit 1
fi

# ═══════════════════════════════════════════════════════════
#  SCENARIO 1: API 1 dies (container 1 keeps running)
# ═══════════════════════════════════════════════════════════
banner "SCENARIO 1: API-1 dies, container running"

journalctl -u aegira -f --since "now" > /tmp/complex-1.log 2>&1 &
JL_PID=$!
sleep 3

echo -e "${YELLOW}→ Killing API inside complex-api-1...${NC}"
docker exec complex-api-1 pkill -f 'http.server' 2>/dev/null || true
sleep 3

CODE_1=$(get_http_code "http://127.0.0.1:18081/")
echo "    API-1 status: HTTP $CODE_1 (expected: 000)"

echo -e "${YELLOW}→ Waiting 30s for Aegira...${NC}"
sleep 30

kill $JL_PID 2>/dev/null || true
wait $JL_PID 2>/dev/null || true

CODE_1=$(get_http_code "http://127.0.0.1:18081/")
echo "    API-1 after recovery: HTTP $CODE_1 (expected: 200)"

if grep -q "RESOLVED" /tmp/complex-1.log 2>/dev/null && [ "$CODE_1" = "200" ]; then
    echo -e "  ${GREEN}✅ SCENARIO 1 PASS${NC}"
else
    echo -e "  ${RED}❌ SCENARIO 1 FAIL${NC} — Logs: /tmp/complex-1.log"
fi

# ═══════════════════════════════════════════════════════════
#  SCENARIO 2: Container 2 crashes
# ═══════════════════════════════════════════════════════════
banner "SCENARIO 2: Container-2 crashes"

journalctl -u aegira -f --since "now" > /tmp/complex-2.log 2>&1 &
JL_PID=$!
sleep 3

echo -e "${YELLOW}→ Killing complex-api-2...${NC}"
docker kill --signal=SIGKILL complex-api-2 > /dev/null 2>&1
sleep 3

CODE_2=$(get_http_code "http://127.0.0.1:18082/")
echo "    API-2 status: HTTP $CODE_2 (expected: 000)"

echo -e "${YELLOW}→ Waiting 30s for Aegira...${NC}"
sleep 30

kill $JL_PID 2>/dev/null || true
wait $JL_PID 2>/dev/null || true

CODE_2=$(get_http_code "http://127.0.0.1:18082/")
echo "    API-2 after recovery: HTTP $CODE_2 (expected: 200)"

if grep -q "RESOLVED" /tmp/complex-2.log 2>/dev/null && [ "$CODE_2" = "200" ]; then
    echo -e "  ${GREEN}✅ SCENARIO 2 PASS${NC}"
else
    echo -e "  ${RED}❌ SCENARIO 2 FAIL${NC} — Logs: /tmp/complex-2.log"
fi

# ═══════════════════════════════════════════════════════════
#  SCENARIO 3: Both containers crash + both APIs die
# ═══════════════════════════════════════════════════════════
banner "SCENARIO 3: Both containers + APIs die"

journalctl -u aegira -f --since "now" > /tmp/complex-3.log 2>&1 &
JL_PID=$!
sleep 3

echo -e "${YELLOW}→ Killing both containers...${NC}"
docker kill --signal=SIGKILL complex-api-1 > /dev/null 2>&1
docker kill --signal=SIGKILL complex-api-2 > /dev/null 2>&1
sleep 3

CODE_1=$(get_http_code "http://127.0.0.1:18081/")
CODE_2=$(get_http_code "http://127.0.0.1:18082/")
echo "    API-1: HTTP $CODE_1 (expected: 000)"
echo "    API-2: HTTP $CODE_2 (expected: 000)"

echo -e "${YELLOW}→ Waiting 45s for Aegira...${NC}"
sleep 45

kill $JL_PID 2>/dev/null || true
wait $JL_PID 2>/dev/null || true

CODE_1=$(get_http_code "http://127.0.0.1:18081/")
CODE_2=$(get_http_code "http://127.0.0.1:18082/")
echo "    API-1 after recovery: HTTP $CODE_1 (expected: 200)"
echo "    API-2 after recovery: HTTP $CODE_2 (expected: 200)"

RESOLVED_COUNT=$(grep -c "RESOLVED" /tmp/complex-3.log 2>/dev/null || echo 0)
echo "    Recoveries logged: $RESOLVED_COUNT"

if [ "$CODE_1" = "200" ] && [ "$CODE_2" = "200" ] && [ "$RESOLVED_COUNT" -ge 2 ]; then
    echo -e "  ${GREEN}✅ SCENARIO 3 PASS${NC}"
else
    echo -e "  ${RED}❌ SCENARIO 3 FAIL${NC} — Logs: /tmp/complex-3.log"
fi

# ═══════════════════════════════════════════════════════════
#  SUMMARY
# ═══════════════════════════════════════════════════════════
banner "COMPLEX TEST COMPLETE"

echo ""
echo -e "${CYAN}Scenarios tested:${NC}"
echo "  1. API-1 dies → recovered inside container"
echo "  2. Container-2 crashes → restarted"
echo "  3. Both die simultaneously → both recovered"
echo ""
echo -e "${CYAN}Logs saved:${NC}"
echo "  /tmp/complex-1.log"
echo "  /tmp/complex-2.log"
echo "  /tmp/complex-3.log"
echo ""
echo -e "${CYAN}Full Aegira log:${NC}"
echo "  sudo journalctl -u aegira"
echo ""
echo -e "${GREEN}Thank you for testing Aegira!${NC}"
echo ""
echo -e "${YELLOW}Please share:${NC}"
echo "  • Results from each scenario (PASS/FAIL)"
echo "  • Any errors"
echo "  • uname -a and docker --version"
echo ""
