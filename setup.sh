#!/bin/bash
# ========================================
#  DIY Hardware Wallet - Quick Setup
#  Run this script to set everything up!
# ========================================

echo ""
echo "========================================"
echo "  DIY Hardware Wallet - Setup Script"
echo "========================================"
echo ""

# Check Python
if ! command -v python3 &> /dev/null; then
    echo "[ERROR] Python 3 not found! Please install Python 3.8+"
    exit 1
fi

echo "[OK] Python found: $(python3 --version)"
echo ""

# Navigate to pc_app directory
cd "$(dirname "$0")/pc_app"

# Install Python dependencies
echo "[*] Installing Python dependencies..."
pip3 install -r requirements.txt

echo ""
echo "[OK] Python dependencies installed!"
echo ""

# Create config file if not exists
if [ ! -f "config.json" ]; then
    echo "[*] Creating default config..."
    echo '{"esp32_ip": "192.168.1.100", "port": 8443, "use_tls": false}' > config.json
fi

echo ""
echo "========================================"
echo "  SETUP COMPLETE!"
echo "========================================"
echo ""
echo "Next steps:"
echo "  1. Flash wallet_main.ino to your ESP32"
echo "  2. Update config.json with your ESP32's IP"
echo "  3. Run: python3 wallet_cli.py"
echo ""
