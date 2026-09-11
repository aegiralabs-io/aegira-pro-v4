#!/bin/bash
# ═══════════════════════════════════════════════════════════════
#  AEGIRA BETA TEST SUITE v2
#  For: 64-bit Linux (x86_64 / ARM64)
#  Usage: sudo ./beta-test.sh
# ═══════════════════════════════════════════════════════════════

set -e

GREEN='\033[0;32m'
YELLOW='\033[1;33m'
RED='\033[0;31m'
BLUE='\033[0;34m'
CYAN='\033[0;36m'
NC='\033[0m'

if [ "$EUID" -ne 0 ]; then
    echo -e "${RED}[ERROR] Please run as root: sudo ./beta-test.sh${NC}"
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
    docker rm -f aegira-beta-1 aegira-beta-2 aegira-beta-api 2>/dev/null || true
    rm -f /etc/aegira/rules/custom/beta-*.json 2>/dev/null || true
    systemctl restart aegira 2>/dev/null || true
    echo -e "${GREEN}[CLEANUP] Done.${NC}"
}

trap cleanup EXIT

# ═══════════════════════════════════════════════════════════
#  INTRO
# ═══════════════════════════════════════════════════════════
banner "AEGIRA BETA TEST SUITE"

echo ""
echo -e "${CYAN}This test will run 4 scenarios:${NC}"
echo "  1. Docker container crash recovery"
echo "  2. OOM (out-of-memory) recovery"
echo "  3. Multi-container monitoring"
echo "  4. HTTP API in-container recovery"
echo ""
echo -e "${YELLOW}Duration: ~4 minutes${NC}"
echo ""
read -p "Press ENTER to start..."

# ═══════════════════════════════════════════════════════════
#  INITIAL CLEANUP
# ═══════════════════════════════════════════════════════════
banner "INITIAL SETUP"

echo -e "${YELLOW}[INIT] Cleaning up leftover containers...${NC}"
docker rm -f aegira-beta-1 aegira-beta-2 aegira-beta-api 2>/dev/null || true
rm -f /etc/aegira/rules/custom/beta-*.json 2>/dev/null || true
systemctl restart aegira
sleep 3
echo -e "${GREEN}[INIT] Clean.${NC}"

# ═══════════════════════════════════════════════════════════
#  TEST 1: Basic Docker Crash Recovery
# ═══════════════════════════════════════════════════════════
banner "[TEST 1/4] Basic Docker Crash Recovery"
echo -e "${CYAN}Scenario:${NC} A container crashes (SIGKILL)."
echo -e "${CYAN}Expected:${NC} Aegira detects the crash and restarts the container."
echo ""

docker run -d --name aegira-beta-1 alpine tail -f /dev/null > /dev/null
sleep 2

sudo aegira configure auto aegira-beta-1 --container > /dev/null
sleep 3

# Start log capture with a 1-minute window to catch startup logs
journalctl -u aegira --since "1 minute ago" -f > /tmp/beta-test-1.log 2>&1 &
JL_PID=$!
sleep 2

echo "  → Killing container..."
docker kill --signal=SIGKILL aegira-beta-1 > /dev/null || true
sleep 12

kill $JL_PID 2>/dev/null || true
wait $JL_PID 2>/dev/null || true

if grep -q "RESOLVED" /tmp/beta-test-1.log 2>/dev/null; then
    echo -e "  ${GREEN}✅ PASS${NC} — Container recovered"
else
    echo -e "  ${RED}❌ FAIL${NC} — Logs: /tmp/beta-test-1.log"
fi

docker rm -f aegira-beta-1 > /dev/null 2>&1 || true

# ═══════════════════════════════════════════════════════════
#  TEST 2: OOM Recovery
# ═══════════════════════════════════════════════════════════
banner "[TEST 2/4] OOM Recovery"
echo -e "${CYAN}Scenario:${NC} A container exceeds memory limit and gets OOM-killed."
echo -e "${CYAN}Expected:${NC} Aegira detects OOM and restarts the container."
echo ""

docker run -d --name aegira-beta-2 --memory=30m python:3-alpine python3 -c "
import time
data = []
while True:
    data.append(' ' * 1024 * 1024)
    time.sleep(0.1)
" > /dev/null
sleep 2

sudo aegira configure auto aegira-beta-2 --container > /dev/null
sleep 3

journalctl -u aegira --since "1 minute ago" -f > /tmp/beta-test-2.log 2>&1 &
JL_PID=$!
sleep 2

echo "  → Waiting for OOM..."
sleep 22

kill $JL_PID 2>/dev/null || true
wait $JL_PID 2>/dev/null || true

if grep -q "RESOLVED" /tmp/beta-test-2.log 2>/dev/null; then
    echo -e "  ${GREEN}✅ PASS${NC} — OOM container recovered"
else
    echo -e "  ${RED}❌ FAIL${NC} — Logs: /tmp/beta-test-2.log"
fi

docker rm -f aegira-beta-2 > /dev/null 2>&1 || true

# ═══════════════════════════════════════════════════════════
#  TEST 3: Multi-Container Monitoring
# ═══════════════════════════════════════════════════════════
banner "[TEST 3/4] Multi-Container Monitoring"
echo -e "${CYAN}Scenario:${NC} Two containers crash simultaneously."
echo -e "${CYAN}Expected:${NC} Aegira recovers both containers independently."
echo ""

docker run -d --name aegira-beta-1 alpine tail -f /dev/null > /dev/null
docker run -d --name aegira-beta-2 alpine tail -f /dev/null > /dev/null
sleep 2

sudo aegira configure multi aegira-beta-1 aegira-beta-2 > /dev/null
sleep 4

journalctl -u aegira --since "1 minute ago" -f > /tmp/beta-test-3.log 2>&1 &
JL_PID=$!
sleep 2

echo "  → Killing both containers..."
docker kill --signal=SIGKILL aegira-beta-1 > /dev/null 2>&1 || true
sleep 1
docker kill --signal=SIGKILL aegira-beta-2 > /dev/null 2>&1 || true
sleep 20

kill $JL_PID 2>/dev/null || true
wait $JL_PID 2>/dev/null || true

RECOVERED=$(grep -c "RESOLVED" /tmp/beta-test-3.log 2>/dev/null || echo 0)
if [ "$RECOVERED" -ge 2 ]; then
    echo -e "  ${GREEN}✅ PASS${NC} — Both containers recovered ($RECOVERED)"
else
    echo -e "  ${RED}❌ FAIL${NC} — Only $RECOVERED recovered (expected 2)"
    echo -e "  ${YELLOW}Logs:${NC} /tmp/beta-test-3.log"
fi

docker rm -f aegira-beta-1 aegira-beta-2 > /dev/null 2>&1 || true

# ═══════════════════════════════════════════════════════════
#  TEST 4: HTTP API In-Container Recovery
# ═══════════════════════════════════════════════════════════
banner "[TEST 4/4] HTTP API In-Container Recovery"
echo -e "${CYAN}Scenario:${NC} Container is running, but the API inside it dies."
echo -e "${CYAN}Expected:${NC} Aegira detects the dead API and recovers it INSIDE the running container."
echo ""

docker run -d --name aegira-beta-api -p 18080:8080 python:3-alpine \
    sh -c 'while true; do python3 -m http.server 8080 --bind 0.0.0.0; sleep 30; done'
sleep 10

echo "  → Verifying API is up..."
HTTP_CODE="000"
for i in 1 2 3 4 5; do
    HTTP_CODE=$(get_http_code "http://127.0.0.1:18080/")
    echo "    Attempt $i: HTTP $HTTP_CODE"
    [ "$HTTP_CODE" = "200" ] && break
    sleep 3
done

if [ "$HTTP_CODE" != "200" ]; then
    echo -e "  ${RED}❌ Container failed to start.${NC}"
    docker logs aegira-beta-api 2>&1 | tail -10
else
    echo -e "  ${GREEN}✅ API is up${NC}"

    tee /etc/aegira/rules/custom/beta-api.json > /dev/null << 'EOF'
[{
  "id": "beta_api_recovery",
  "name": "Beta API Recovery",
  "severity": "critical",
  "trigger": {
    "type": "http_health",
    "container": "aegira-beta-api",
    "url": "http://127.0.0.1:18080/",
    "expected_status": 200,
    "interval_secs": 5
  },
  "error_patterns": ["HTTP health check failed"],
  "context_patterns": ["aegira-beta-api"],
  "remediation": {
    "type": "container_exec",
    "container": "aegira-beta-api",
    "args": ["sh", "-c", "kill $(pgrep -f 'http.server') 2>/dev/null || true; sleep 1; setsid python3 -m http.server 8080 --bind 0.0.0.0 > /dev/null 2>&1 < /dev/null & sleep 3"]
  },
  "verification": {
    "type": "container_http_status",
    "container": "aegira-beta-api",
    "url": "http://127.0.0.1:18080/",
    "expected_status": 200
  },
  "action": "auto_recover",
  "priority": 40
}]
EOF

    systemctl restart aegira
    sleep 4

    if ! aegira rules list 2>/dev/null | grep -q beta_api_recovery; then
        echo -e "  ${RED}❌ Rule not loaded.${NC}"
    else
        echo -e "  ${GREEN}✅ Rule loaded.${NC}"

        journalctl -u aegira --since "1 minute ago" -f > /tmp/beta-test-4.log 2>&1 &
        JL_PID=$!
        sleep 3

        echo "  → Killing API inside container..."
        docker exec aegira-beta-api pkill -f 'http.server' 2>/dev/null || true
        sleep 3

        HTTP_CODE=$(get_http_code "http://127.0.0.1:18080/")
        echo "    API after kill: HTTP $HTTP_CODE (expected: 000)"

        echo "  → Waiting 45s for recovery..."
        sleep 45

        kill $JL_PID 2>/dev/null || true
        wait $JL_PID 2>/dev/null || true

        HTTP_CODE=$(get_http_code "http://127.0.0.1:18080/")
        echo "    API after recovery: HTTP $HTTP_CODE (expected: 200)"

        if grep -q "RESOLVED" /tmp/beta-test-4.log 2>/dev/null; then
            echo -e "  ${GREEN}✅ PASS${NC} — API recovered inside container"
        else
            echo -e "  ${RED}❌ FAIL${NC} — Logs: /tmp/beta-test-4.log"
        fi
    fi
fi

# ═══════════════════════════════════════════════════════════
#  SUMMARY
# ═══════════════════════════════════════════════════════════
banner "BETA TEST COMPLETE"

echo ""
echo -e "${CYAN}Logs saved:${NC}"
echo "  /tmp/beta-test-1.log  (crash recovery)"
echo "  /tmp/beta-test-2.log  (OOM recovery)"
echo "  /tmp/beta-test-3.log  (multi-container)"
echo "  /tmp/beta-test-4.log  (HTTP API)"
echo ""
echo -e "${CYAN}Full Aegira log:${NC}"
echo "  sudo journalctl -u aegira"
echo ""
echo -e "${GREEN}Thank you for beta testing Aegira!${NC}"
echo ""
echo -e "${YELLOW}Please share:${NC}"
echo "  • Which tests passed/failed (from output above)"
echo "  • Any errors you saw"
echo "  • Your OS: uname -a"
echo "  • Docker version: docker --version"
echo ""
