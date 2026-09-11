#!/bin/bash
# ═══════════════════════════════════════════════════════════════
#  AEGIRA CLEANUP SCRIPT
#  Removes Aegira completely from the system.
#  Usage: sudo ./cleanup.sh
# ═══════════════════════════════════════════════════════════════

set -e

GREEN='\033[0;32m'
YELLOW='\033[1;33m'
RED='\033[0;31m'
BLUE='\033[0;34m'
CYAN='\033[0;36m'
NC='\033[0m'

if [ "$EUID" -ne 0 ]; then
    echo -e "${RED}[ERROR] Please run as root: sudo ./cleanup.sh${NC}"
    exit 1
fi

banner() {
    echo ""
    echo -e "${BLUE}════════════════════════════════════════════════════════${NC}"
    echo -e "${BLUE}  $1${NC}"
    echo -e "${BLUE}════════════════════════════════════════════════════════${NC}"
}

banner "AEGIRA CLEANUP"

echo ""
echo -e "${YELLOW}This will completely remove Aegira from your system:${NC}"
echo "  • Stop and disable aegira.service"
echo "  • Remove /usr/local/bin/aegira"
echo "  • Remove /etc/aegira/ (config + rules)"
echo "  • Remove /var/log/aegira/ (logs)"
echo "  • Remove aegira.service unit file"
echo "  • Remove test containers"
echo ""
read -p "Continue? (y/N): " CONFIRM
if [ "$CONFIRM" != "y" ] && [ "$CONFIRM" != "Y" ]; then
    echo "Aborted."
    exit 0
fi

# ─── 1. Stop journalctl monitors ───
echo -e "\n${YELLOW}[1/7] Stopping journalctl monitors...${NC}"
pkill -f "journalctl -u aegira" 2>/dev/null || true
echo -e "${GREEN}  ✅ Done.${NC}"

# ─── 2. Stop and disable service ───
echo -e "\n${YELLOW}[2/7] Stopping and disabling aegira.service...${NC}"
if systemctl list-unit-files | grep -q "aegira.service"; then
    systemctl stop aegira.service 2>/dev/null || true
    systemctl disable aegira.service 2>/dev/null || true
    echo -e "${GREEN}  ✅ Service stopped and disabled.${NC}"
else
    echo -e "${CYAN}  ⚠️  Service not found (already removed?).${NC}"
fi

# ─── 3. Remove systemd unit file ───
echo -e "\n${YELLOW}[3/7] Removing systemd unit file...${NC}"
rm -f /etc/systemd/system/aegira.service
systemctl daemon-reload 2>/dev/null || true
systemctl reset-failed 2>/dev/null || true
echo -e "${GREEN}  ✅ Unit file removed.${NC}"

# ─── 4. Remove binary ───
echo -e "\n${YELLOW}[4/7] Removing binary...${NC}"
rm -f /usr/local/bin/aegira
rm -f /usr/bin/aegira
echo -e "${GREEN}  ✅ Binary removed.${NC}"

# ─── 5. Remove config and rules ───
echo -e "\n${YELLOW}[5/7] Removing config and rules...${NC}"
rm -rf /etc/aegira
echo -e "${GREEN}  ✅ /etc/aegira removed.${NC}"

# ─── 6. Remove logs ───
echo -e "\n${YELLOW}[6/7] Removing logs...${NC}"
rm -rf /var/log/aegira
echo -e "${GREEN}  ✅ /var/log/aegira removed.${NC}"

# ─── 7. Remove test containers ───
echo -e "\n${YELLOW}[7/7] Removing test containers...${NC}"
docker rm -f aegira-beta-1 aegira-beta-2 aegira-beta-api 2>/dev/null || true
docker rm -f complex-api-1 complex-api-2 2>/dev/null || true
docker rm -f test-crash test-oom test-api test-app-1 test-app-2 test-cooldown test-alert test-rotate 2>/dev/null || true
echo -e "${GREEN}  ✅ Test containers removed.${NC}"

# ─── Summary ───
banner "CLEANUP COMPLETE"

echo ""
echo -e "${GREEN}✅ Aegira has been completely removed from your system.${NC}"
echo ""
echo -e "${CYAN}Verified:${NC}"
[ ! -f /usr/local/bin/aegira ] && echo "  ✅ Binary removed" || echo "  ⚠️  Binary still exists"
[ ! -d /etc/aegira ] && echo "  ✅ Config removed" || echo "  ⚠️  Config still exists"
[ ! -d /var/log/aegira ] && echo "  ✅ Logs removed" || echo "  ⚠️  Logs still exist"
[ ! -f /etc/systemd/system/aegira.service ] && echo "  ✅ Service removed" || echo "  ⚠️  Service still exists"
echo ""
echo -e "${CYAN}To reinstall:${NC}"
echo "  sudo ./install.sh"
echo ""
