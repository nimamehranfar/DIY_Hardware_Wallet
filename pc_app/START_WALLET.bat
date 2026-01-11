@echo off
REM ========================================
REM  DIY Hardware Wallet - SETUP & RUN
REM  Just double-click this file!
REM ========================================

echo.
echo ========================================
echo   DIY Hardware Wallet
echo ========================================
echo.

REM Check if first run (requirements not installed)
if not exist ".installed" (
    echo [*] First run - Installing dependencies...
    echo.
    
    REM Check Python
    python --version >nul 2>&1
    if %errorlevel% neq 0 (
        echo [ERROR] Python not found!
        echo Download from: https://www.python.org/downloads/
        pause
        exit /b 1
    )
    
    echo [OK] Python found
    pip install -r requirements.txt
    
    if %errorlevel% equ 0 (
        echo. > .installed
        echo [OK] Setup complete!
    )
    echo.
)

REM Check config
if not exist "config.json" (
    echo [!] config.json not found, creating default...
    echo {"esp32_ip": "192.168.1.100", "port": 8443, "use_tls": true, "rpc_url": "https://api.devnet.solana.com"} > config.json
    echo.
    echo [IMPORTANT] Edit config.json with your ESP32 IP address!
    echo.
    notepad config.json
    pause
)

echo [*] Starting wallet...
echo.
python wallet_cli.py
pause
