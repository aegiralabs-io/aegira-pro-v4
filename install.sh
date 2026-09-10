#!/bin/bash
set -e

GREEN='\033[0;32m'
YELLOW='\033[1;33m'
RED='\033[0;31m'
NC='\033[0m'

if [ "$EUID" -ne 0 ]; then
    echo -e "${RED}[ERROR] Please run as root: sudo ./install.sh${NC}"
    exit 1
fi

if [ "$(uname -s)" != "Linux" ]; then
    echo -e "${RED}[ERROR] Aegira requires Linux.${NC}"
    exit 1
fi

BINARY="./aegira"
if [ ! -f "$BINARY" ]; then
    echo -e "${RED}[ERROR] Binary './aegira' not found.${NC}"
    exit 1
fi

chmod +x "$BINARY"

echo -e "${YELLOW}[1/4] Installing binary...${NC}"
cp "$BINARY" /usr/local/bin/aegira
chmod 755 /usr/local/bin/aegira

echo -e "${YELLOW}[2/4] Creating directories...${NC}"
mkdir -p /etc/aegira/rules/builtin /etc/aegira/rules/custom
mkdir -p /var/log/aegira
touch /etc/aegira/composio.env
chmod 600 /etc/aegira/composio.env

echo -e "${YELLOW}[3/4] Installing rules...${NC}"
if [ -f "./rules.json" ]; then
    cp ./rules.json /etc/aegira/rules/builtin/rules.json
else
    echo "[]" > /etc/aegira/rules/builtin/rules.json
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
    echo "  Configure: sudo aegira configure auto <container> --container"
    echo "  Rules:     sudo aegira rules list"
    echo "  History:   sudo aegira history"
else
    echo -e "${RED}[ERROR] Service failed. Check: journalctl -u aegira -n 50${NC}"
    exit 1
fi
