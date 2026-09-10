#!/bin/bash
# Aegira installer
# Usage: ./install.sh
#
# For end users. Installs the pre-built Aegira binary and sets up the
# systemd service. Does NOT compile from source.

set -e

GREEN='\033[0;32m'
YELLOW='\033[1;33m'
RED='\033[0;31m'
NC='\033[0m'

# Must run as root
if [ "$EUID" -ne 0 ]; then
    echo -e "${RED}[ERROR] Please run as root: sudo ./install.sh${NC}"
    exit 1
fi

# Must run on Linux
if [ "$(uname -s)" != "Linux" ]; then
    echo -e "${RED}[ERROR] Aegira requires Linux.${NC}"
    exit 1
fi

# Check for pre-built binary
BINARY="./aegira"
if [ ! -f "$BINARY" ]; then
    echo -e "${RED}[ERROR] Binary './aegira' not found in current directory.${NC}"
    echo "Download the release from GitHub and place it next to this script."
    echo "Or build from source: cargo build --release && cp target/release/aegira ."
    exit 1
fi

chmod +x "$BINARY"

echo -e "${YELLOW}[1/4] Installing binary to /usr/local/bin/aegira...${NC}"
cp "$BINARY" /usr/local/bin/aegira
chmod 755 /usr/local/bin/aegira

echo -e "${YELLOW}[2/4] Creating directories...${NC}"
mkdir -p /etc/aegira/rules/builtin /etc/aegira/rules/custom
mkdir -p /var/log/aegira
touch /etc/aegira/composio.env
chmod 600 /etc/aegira/composio.env

echo -e "${YELLOW}[3/4] Installing built-in rules...${NC}"
if [ -f "./rules.json" ]; then
    cp ./rules.json /etc/aegira/rules/builtin/rules.json
else
    echo "[]" > /etc/aegira/rules/builtin/rules.json
    echo "  (no rules.json found — using hardcoded defaults)"
fi

echo -e "${YELLOW}[4/4] Creating systemd service...${NC}"
cat > /etc/systemd/system/aegira.service <<EOF
[Unit]
Description=Aegira Automated Recovery Engine
After=network.target

[Service]
Type=simple
User=root
EnvironmentFile=-/etc/aegira/composio.env
ExecStart=/usr/local/bin/aegira run
Restart=always
RestartSec=3

[Install]
WantedBy=multi-user.target
EOF

systemctl daemon-reload
systemctl enable aegira.service
systemctl restart aegira.service

sleep 2

if systemctl is-active --quiet aegira; then
    echo ""
    echo -e "${GREEN}[SUCCESS] Aegira installed and running.${NC}"
    echo ""
    echo "  Binary:  /usr/local/bin/aegira"
    echo "  Rules:   /etc/aegira/rules/"
    echo "  Logs:    /var/log/aegira/incident.log"
    echo "  Service: aegira.service"
    echo ""
    echo "Next steps:"
    echo "  1. Configure target: sudo aegira configure auto <container> --container"
    echo "  2. View rules:       sudo aegira rules list"
    echo "  3. View incidents:   sudo aegira history"
else
    echo -e "${RED}[ERROR] Service failed to start. Check: journalctl -u aegira -n 50${NC}"
    exit 1
fi
