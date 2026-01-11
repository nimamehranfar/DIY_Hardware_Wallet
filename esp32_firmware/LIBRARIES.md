# Arduino Library Dependencies for espresSol Hardware Wallet

Install these libraries via Arduino IDE:
**Sketch → Include Library → Manage Libraries**

## Required Libraries

| Library | Version | Author | Purpose |
|---------|---------|--------|---------|
| U8g2 | 2.34+ | olikraus | OLED display driver (SSD1306) |
| ArduinoJson | 6.x | Benoit Blanchon | JSON parsing for commands |
| WebSocketsServer | 2.4+ | Markus Sattler | Mobile app WebSocket connectivity |

## Built-in (No Install Needed)

These are included with ESP32 board package:
- `WiFi.h` - WiFi connectivity
- `WiFiClientSecure.h` - TLS support
- `Preferences.h` - NVS storage
- `mbedtls/*` - Cryptographic functions (AES, SHA, RSA, ECDH)

## ESP32 Board Package

Install via Arduino IDE:
**File → Preferences → Additional Boards Manager URLs:**
```
https://raw.githubusercontent.com/espressif/arduino-esp32/gh-pages/package_esp32_index.json
```

Then: **Tools → Board → Boards Manager → Search "ESP32" → Install**

Recommended version: **2.0.11** or newer

## Quick Install Commands (PlatformIO)

If using PlatformIO instead of Arduino IDE:
```ini
[env:esp32dev]
platform = espressif32
board = esp32dev
framework = arduino
lib_deps =
    olikraus/U8g2@^2.34.0
    bblanchon/ArduinoJson@^6.21.0
    links2004/WebSocketsServer@^2.4.0
```
