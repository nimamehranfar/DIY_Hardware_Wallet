@echo off
REM ========================================
REM  DIY Hardware Wallet - Quick Setup
REM  Run this script to set everything up!
REM ========================================

echo.
echo ========================================
echo   DIY Hardware Wallet - Setup Script
echo ========================================
echo.

REM Check Python
python --version >nul 2>&1
if %errorlevel% neq 0 (
    echo [ERROR] Python not found! Please install Python 3.8+
    echo Download from: https://www.python.org/downloads/
    pause
    exit /b 1
)

echo [OK] Python found
echo.

REM Navigate to pc_app directory
cd /d "%~dp0pc_app"

REM Install Python dependencies
echo [*] Installing Python dependencies...
pip install -r requirements.txt
if %errorlevel% neq 0 (
    echo [WARNING] Some packages may have failed. Trying individually...
    pip install pyserial
    pip install solana
    pip install solders
    pip install base58
    pip install pycryptodome
    pip install cryptography
)

echo.
echo [OK] Python dependencies installed!
echo.

REM Create config file if not exists
if not exist "config.json" (
    echo [*] Creating default config...
    echo {"esp32_ip": "192.168.1.100", "port": 8443, "use_tls": false} > config.json
)

echo.
echo ========================================
echo   SETUP COMPLETE!
echo ========================================
echo.
echo Next steps:
echo   1. Flash wallet_main.ino to your ESP32
echo   2. Update config.json with your ESP32's IP
echo   3. Run: python wallet_cli.py
echo.
echo Press any key to exit...
pause >nul
