#!/bin/bash
# Aegira rebuild script
# Usage: ./rebuild.sh

set -e

# Colors for output
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
RED='\033[0;31m'
NC='\033[0m' # No Color

echo -e "${YELLOW}[1/4] Building Aegira...${NC}"
cargo build --release

if [ ! -f "target/release/aegira" ]; then
    echo -e "${RED}[ERROR] Build failed — binary not found${NC}"
    exit 1
fi

echo -e "${YELLOW}[2/4] Installing to /usr/local/bin...${NC}"
sudo cp target/release/aegira /usr/local/bin/aegira

echo -e "${YELLOW}[3/4] Restarting aegira service...${NC}"
sudo systemctl restart aegira

echo -e "${YELLOW}[4/4] Verifying service status...${NC}"
sleep 1
if sudo systemctl is-active --quiet aegira; then
    echo -e "${GREEN}[SUCCESS] Aegira is running with the latest build.${NC}"
    echo ""
    echo "Binary: $(ls -la /usr/local/bin/aegira | awk '{print $5, $6, $7, $8}')"
    echo "Service: $(sudo systemctl is-active aegira)"
else
    echo -e "${RED}[ERROR] Service is not running. Check: sudo journalctl -u aegira -n 50${NC}"
    exit 1
fi
