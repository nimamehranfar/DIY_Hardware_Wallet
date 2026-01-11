#!/bin/bash
# ========================================
#  DIY Hardware Wallet - SETUP & RUN
#  Just run: ./START_WALLET.sh
# ========================================

echo ""
echo "========================================"
echo "  DIY Hardware Wallet"
echo "========================================"
echo ""

cd "$(dirname "$0")"

# Check if first run
if [ ! -f ".installed" ]; then
    echo "[*] First run - Installing dependencies..."
    echo ""
    
    if ! command -v python3 &> /dev/null; then
        echo "[ERROR] Python 3 not found!"
        exit 1
    fi
    
    echo "[OK] Python found: $(python3 --version)"
    pip3 install -r requirements.txt
    
    if [ $? -eq 0 ]; then
        touch .installed
        echo "[OK] Setup complete!"
    fi
    echo ""
fi

# Check config
if [ ! -f "config.json" ]; then
    echo "[!] Creating default config.json..."
    echo '{"esp32_ip": "192.168.1.100", "port": 8443, "use_tls": true, "rpc_url": "https://api.devnet.solana.com"}' > config.json
    echo ""
    echo "[IMPORTANT] Edit config.json with your ESP32 IP address!"
    echo ""
fi

echo "[*] Starting wallet..."
echo ""
python3 wallet_cli.py
