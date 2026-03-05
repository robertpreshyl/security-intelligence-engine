#!/bin/bash
#
# Install AI-SOC systemd services
# Enables auto-start on reboot and service management via systemctl
#
# Usage: sudo bash install-services.sh
#

set -e

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_DIR="$(dirname "$SCRIPT_DIR")"

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m'

# Must run as root
if [ "$(id -u)" -ne 0 ]; then
    echo -e "${RED}This script must be run as root (sudo).${NC}"
    echo "Usage: sudo bash $0"
    exit 1
fi

echo "════════════════════════════════════════════════"
echo "  AllysecLabs Systemd Service Installer"
echo "════════════════════════════════════════════════"
echo ""

# Create logs directory
mkdir -p "$PROJECT_DIR/logs"
chown soc-admin:soc-admin "$PROJECT_DIR/logs"

# Copy service files
echo -e "  Installing service files..."
cp "$SCRIPT_DIR/ai-soc-api.service" /etc/systemd/system/
cp "$SCRIPT_DIR/ai-soc-dashboard.service" /etc/systemd/system/
echo -e "  ${GREEN}[ok]${NC} Service files copied to /etc/systemd/system/"

# Reload systemd
systemctl daemon-reload
echo -e "  ${GREEN}[ok]${NC} Systemd reloaded"

# Enable services (auto-start on boot)
systemctl enable ai-soc-api.service
systemctl enable ai-soc-dashboard.service
echo -e "  ${GREEN}[ok]${NC} Services enabled (auto-start on boot)"

# Start services
echo ""
echo -e "  Starting services..."
systemctl start ai-soc-api.service
sleep 3

# Check API is up before starting dashboard
if systemctl is-active --quiet ai-soc-api.service; then
    echo -e "  ${GREEN}[ok]${NC} API server started"
    systemctl start ai-soc-dashboard.service
    sleep 2
    if systemctl is-active --quiet ai-soc-dashboard.service; then
        echo -e "  ${GREEN}[ok]${NC} Dashboard started"
    else
        echo -e "  ${RED}[fail]${NC} Dashboard failed to start"
        echo "  Check: journalctl -u ai-soc-dashboard.service -n 20"
    fi
else
    echo -e "  ${RED}[fail]${NC} API server failed to start"
    echo "  Check: journalctl -u ai-soc-api.service -n 20"
    exit 1
fi

echo ""
echo "════════════════════════════════════════════════"
echo -e "  ${GREEN}Installation complete!${NC}"
echo "════════════════════════════════════════════════"
echo ""
echo "  Dashboard:   http://localhost:8501"
echo "  API Server:  http://localhost:8000"
echo ""
echo "  Management commands:"
echo "    sudo systemctl status ai-soc-api"
echo "    sudo systemctl status ai-soc-dashboard"
echo "    sudo systemctl restart ai-soc-api"
echo "    sudo systemctl stop ai-soc-api ai-soc-dashboard"
echo "    journalctl -u ai-soc-api -f          # Live API logs"
echo "    journalctl -u ai-soc-dashboard -f    # Live dashboard logs"
echo ""
