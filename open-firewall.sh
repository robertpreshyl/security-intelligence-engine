#!/bin/bash
#
# Open firewall ports for AI-SOC Dashboard
# Run with: sudo bash open-firewall.sh
#

if [ "$(id -u)" -ne 0 ]; then
    echo "This script must be run as root (sudo)"
    exit 1
fi

echo "Opening firewall ports for AI-SOC..."

# Check if ufw is active
if ! systemctl is-active --quiet ufw; then
    echo "ufw is not active - no firewall changes needed"
    exit 0
fi

# Allow ports
ufw allow 8000/tcp comment "AI-SOC API Server"
ufw allow 8501/tcp comment "AI-SOC Dashboard"

echo ""
echo "✅ Firewall ports opened:"
echo "   - 8000/tcp (API Server)"
echo "   - 8501/tcp (Dashboard)"
echo ""
ufw status | grep -E "(8000|8501)"
