/**
 * menu_system.h - OLED Menu Navigation for ESP32 Hardware Wallet
 * 
 * Provides interactive menu system using 4 buttons:
 * - BTN_UP: Navigate up / scroll
 * - BTN_DOWN: Navigate down / scroll  
 * - BTN_OK: Select / Confirm
 * - BTN_BACK: Go back / Exit menu
 */
#pragma once
#include <Arduino.h>
#include <U8g2lib.h>
#include <WiFi.h>
#include <Preferences.h>
#include <esp_random.h>
#include <WebSocketsServer.h>
#include "mbedtls/gcm.h"
#if USE_TLS_SERVER
#include "tls_server.h"
#endif

// External references
extern U8G2_SSD1306_128X64_NONAME_F_HW_I2C u8g2;
extern const int BTN_UP;
extern const int BTN_DOWN;
extern const int BTN_OK;
extern const int BTN_BACK;
extern const uint16_t SERVER_PORT;
extern uint8_t ed25519_pk[32];
extern String mnemonicWords[12];
extern bool pin_verified;
extern unsigned long lastActivityTime;
extern String bytesToBase58(const uint8_t* data, size_t len);

// Forward declarations for actions
void displayMnemonic();
void displayIPQRCode(const char* ip, int port);

// ===== MENU STATES =====
enum MenuState {
  MENU_IDLE,           // Show connection info (IP/QR)
  MENU_MAIN,           // Main menu
  MENU_CONNECTION,     // Connection mode submenu
  MENU_SHOW_ADDRESS,   // Display public key
  MENU_SHOW_SEED,      // Display seed phrase
  MENU_DEVICE_INFO,    // Show device info
  MENU_SETTINGS,       // Settings submenu
  MENU_CHANGE_PIN,     // Change PIN screen
  MENU_FACTORY_RESET   // Factory reset confirmation
};

// ===== MENU ITEMS =====
struct MenuItem {
  const char* label;
  MenuState targetState;
};

// Main menu items
const MenuItem MAIN_MENU[] = {
  {"Connection Mode", MENU_CONNECTION},
  {"Show Address", MENU_SHOW_ADDRESS},
  {"View Seed Phrase", MENU_SHOW_SEED},
  {"Device Info", MENU_DEVICE_INFO},
  {"Settings", MENU_SETTINGS},
  {"Factory Reset", MENU_FACTORY_RESET}
};
const int MAIN_MENU_SIZE = 6;

// Connection submenu
const MenuItem CONNECTION_MENU[] = {
  {"WiFi Mode", MENU_IDLE},
  {"USB Mode", MENU_IDLE}
};
const int CONNECTION_MENU_SIZE = 2;

// Settings submenu - only Change PIN now
const MenuItem SETTINGS_MENU[] = {
  {"Change PIN", MENU_CHANGE_PIN}
};
const int SETTINGS_MENU_SIZE = 1;

// ===== MENU STATE VARIABLES =====
MenuState currentMenu = MENU_IDLE;
int menuSelection = 0;
int menuScrollOffset = 0;

// Per-button debouncing for responsive navigation
unsigned long lastPressUp = 0;
unsigned long lastPressDown = 0;
unsigned long lastPressOK = 0;
unsigned long lastPressBack = 0;
bool wasPressed[4] = {false, false, false, false}; // Track button states for edge detection

const unsigned long DEBOUNCE_MS = 150; // Reduced for snappier response
const unsigned long MENU_TIMEOUT_MS = 30000; // Return to idle after 30s

// ===== BUTTON READING =====
// Returns true only on button press (falling edge), not while held
inline bool buttonPressed(int pin) {
  bool isPressed = (digitalRead(pin) == LOW);
  int btnIdx = (pin == BTN_UP) ? 0 : (pin == BTN_DOWN) ? 1 : (pin == BTN_OK) ? 2 : 3;
  unsigned long* lastPress = (pin == BTN_UP) ? &lastPressUp : 
                              (pin == BTN_DOWN) ? &lastPressDown : 
                              (pin == BTN_OK) ? &lastPressOK : &lastPressBack;
  
  if (isPressed && !wasPressed[btnIdx]) {
    // Button just pressed (falling edge)
    if (millis() - *lastPress > DEBOUNCE_MS) {
      *lastPress = millis();
      wasPressed[btnIdx] = true;
      return true;
    }
  } else if (!isPressed) {
    // Button released
    wasPressed[btnIdx] = false;
  }
  return false;
}

// ===== MENU RENDERING =====
inline void drawMenuHeader(const char* title) {
  u8g2.setFont(u8g2_font_7x14B_tf);
  u8g2.drawStr(0, 12, title);
  u8g2.drawHLine(0, 15, 128);
}

inline void drawMenuList(const MenuItem* items, int itemCount, int selected, int scrollOffset) {
  u8g2.setFont(u8g2_font_6x10_tf);
  int visibleItems = 4; // Max items visible on screen
  int yStart = 26;
  int lineHeight = 10;
  
  for (int i = 0; i < visibleItems && (scrollOffset + i) < itemCount; i++) {
    int idx = scrollOffset + i;
    int y = yStart + (i * lineHeight);
    
    if (idx == selected) {
      // Highlight selected item
      u8g2.drawBox(0, y - 8, 128, lineHeight);
      u8g2.setDrawColor(0);
      u8g2.drawStr(4, y, items[idx].label);
      u8g2.setDrawColor(1);
    } else {
      u8g2.drawStr(4, y, items[idx].label);
    }
  }
  
  // Scroll indicators
  if (scrollOffset > 0) {
    u8g2.drawTriangle(120, 18, 124, 22, 128, 18); // Up arrow
  }
  if (scrollOffset + visibleItems < itemCount) {
    u8g2.drawTriangle(120, 62, 124, 58, 128, 62); // Down arrow
  }
}

inline void drawCenteredLarge(const char* text, int yOffset = 0) {
  u8g2.setFont(u8g2_font_9x15_tf);
  int w = u8g2.getStrWidth(text);
  u8g2.drawStr((128 - w) / 2, 32 + yOffset, text);
}

// ===== MENU SCREENS =====
inline void showMainMenu() {
  u8g2.clearBuffer();
  drawMenuHeader("espresSol");
  drawMenuList(MAIN_MENU, MAIN_MENU_SIZE, menuSelection, menuScrollOffset);
  u8g2.sendBuffer();
}

inline void showConnectionMenu() {
  u8g2.clearBuffer();
  drawMenuHeader("Connection");
  drawMenuList(CONNECTION_MENU, CONNECTION_MENU_SIZE, menuSelection, 0);
  u8g2.sendBuffer();
}

inline void showSettingsMenu() {
  u8g2.clearBuffer();
  drawMenuHeader("Settings");
  drawMenuList(SETTINGS_MENU, SETTINGS_MENU_SIZE, menuSelection, 0);
  u8g2.sendBuffer();
}

inline void showAddressScreen() {
  u8g2.clearBuffer();
  drawMenuHeader("Your Address");
  
  String pubkeyB58 = bytesToBase58(ed25519_pk, 32);
  u8g2.setFont(u8g2_font_5x7_tf);
  
  // Display in two lines
  String line1 = pubkeyB58.substring(0, 22);
  String line2 = pubkeyB58.substring(22);
  
  u8g2.drawStr(0, 32, line1.c_str());
  u8g2.drawStr(0, 42, line2.c_str());
  
  u8g2.setFont(u8g2_font_6x10_tf);
  u8g2.drawStr(0, 60, "[BACK] to return");
  u8g2.sendBuffer();
}

inline void showDeviceInfoScreen() {
  u8g2.clearBuffer();
  drawMenuHeader("Device Info");
  
  u8g2.setFont(u8g2_font_6x10_tf);
  u8g2.drawStr(0, 28, "Firmware: v1.0.0");
  
  // Uptime
  unsigned long uptime = millis() / 1000;
  char uptimeStr[32];
  snprintf(uptimeStr, sizeof(uptimeStr), "Uptime: %lum %lus", uptime / 60, uptime % 60);
  u8g2.drawStr(0, 40, uptimeStr);
  
  // WiFi RSSI
  int rssi = WiFi.RSSI();
  char rssiStr[32];
  snprintf(rssiStr, sizeof(rssiStr), "WiFi: %ddBm", rssi);
  u8g2.drawStr(0, 52, rssiStr);
  
  u8g2.drawStr(0, 62, "[BACK] to return");
  u8g2.sendBuffer();
}

inline void showFactoryResetScreen() {
  u8g2.clearBuffer();
  u8g2.setFont(u8g2_font_9x15_tf);
  u8g2.drawStr(0, 14, "!! DANGER !!");
  
  u8g2.setFont(u8g2_font_6x10_tf);
  u8g2.drawStr(0, 30, "This will ERASE:");
  u8g2.drawStr(0, 42, "- All keys & seeds");
  u8g2.drawStr(0, 54, "- WiFi & settings");
  
  u8g2.setFont(u8g2_font_7x14_tf);
  u8g2.drawStr(0, 64, "OK=WIPE BACK=Cancel");
  u8g2.sendBuffer();
}

// ===== MENU INPUT HANDLER =====
inline void handleMenuInput() {
  // Check for menu timeout (use most recent button press as activity timer)
  unsigned long lastActivity = max(max(lastPressUp, lastPressDown), max(lastPressOK, lastPressBack));
  if (currentMenu != MENU_IDLE && lastActivity > 0 && millis() - lastActivity > MENU_TIMEOUT_MS) {
    currentMenu = MENU_IDLE;
    menuSelection = 0;
    menuScrollOffset = 0;
    return;
  }
  
  switch (currentMenu) {
    case MENU_IDLE:
      // Long press BACK to enter menu
      if (buttonPressed(BTN_BACK)) {
        currentMenu = MENU_MAIN;
        menuSelection = 0;
        menuScrollOffset = 0;
        showMainMenu();
      }
      break;
      
    case MENU_MAIN:
      if (buttonPressed(BTN_UP)) {
        if (menuSelection > 0) menuSelection--;
        if (menuSelection < menuScrollOffset) menuScrollOffset = menuSelection;
        showMainMenu();
      }
      else if (buttonPressed(BTN_DOWN)) {
        if (menuSelection < MAIN_MENU_SIZE - 1) menuSelection++;
        if (menuSelection >= menuScrollOffset + 4) menuScrollOffset = menuSelection - 3;
        showMainMenu();
      }
      else if (buttonPressed(BTN_OK)) {
        MenuState target = MAIN_MENU[menuSelection].targetState;
        currentMenu = target;
        menuSelection = 0;
        menuScrollOffset = 0;
        
        // Render target screen
        switch (target) {
          case MENU_CONNECTION: showConnectionMenu(); break;
          case MENU_SHOW_ADDRESS: showAddressScreen(); break;
          case MENU_SHOW_SEED: displayMnemonic(); currentMenu = MENU_MAIN; break;
          case MENU_DEVICE_INFO: showDeviceInfoScreen(); break;
          case MENU_SETTINGS: showSettingsMenu(); break;
          case MENU_FACTORY_RESET: showFactoryResetScreen(); break;
          default: break;
        }
      }
      else if (buttonPressed(BTN_BACK)) {
        currentMenu = MENU_IDLE;
        menuSelection = 0;
      }
      break;
      
    case MENU_CONNECTION:
      if (buttonPressed(BTN_UP) && menuSelection > 0) {
        menuSelection--;
        showConnectionMenu();
      }
      else if (buttonPressed(BTN_DOWN) && menuSelection < CONNECTION_MENU_SIZE - 1) {
        menuSelection++;
        showConnectionMenu();
      }
      else if (buttonPressed(BTN_OK)) {
        // Handle WiFi/USB mode selection
        extern bool usbModeActive;  // Mode flag from wallet_main.ino
        
        if (menuSelection == 0) {
          // WiFi mode - connect and start servers
          usbModeActive = false;  // Disable USB mode
          
          u8g2.clearBuffer();
          u8g2.setFont(u8g2_font_9x15_tf);
          u8g2.drawStr(10, 35, "Connecting...");
          u8g2.sendBuffer();
          
          // Connect to WiFi
          extern void connectWiFi();
          connectWiFi();
          
          // TLS server is started in connectWiFi() after cert init
          
          // Start WebSocket server
          extern WebSocketsServer wsServer;
          extern void wsEvent(uint8_t, WStype_t, uint8_t*, size_t);
          wsServer.begin();
          wsServer.onEvent(wsEvent);
          Serial.println("[WS] WebSocket server started on port 8444");
          
          // Show QR code for pairing
          String ipMsg = WiFi.localIP().toString() + ":" + String(SERVER_PORT);
          Serial.print("[WiFi] IP: "); Serial.println(ipMsg);
          displayIPQRCode(ipMsg);
          currentMenu = MENU_IDLE;
        } else {
          // USB mode - initiate USB pairing with ECDH
          usbModeActive = true;  // Enable USB mode flag
          
          // Disconnect WiFi if connected (ensures clean USB mode)
          if (WiFi.status() == WL_CONNECTED) {
            WiFi.disconnect();
            Serial.println("[USB] Disconnected WiFi for USB mode");
          }
          
          u8g2.clearBuffer();
          u8g2.setFont(u8g2_font_9x15B_tf);
          u8g2.drawStr(20, 20, "USB Mode");
          u8g2.setFont(u8g2_font_6x10_tf);
          u8g2.drawStr(0, 38, "Press OK to start");
          u8g2.drawStr(0, 50, "USB pairing...");
          u8g2.sendBuffer();
          
          // Wait for OK button to start pairing
          while (digitalRead(BTN_OK) == LOW) delay(50);  // Wait for release
          delay(200);  // Debounce
          
          // Wait for OK press to start pairing
          while (digitalRead(BTN_OK) == HIGH && digitalRead(BTN_BACK) == HIGH) {
            delay(50);
          }
          
          if (digitalRead(BTN_BACK) == LOW) {
            // Cancelled
            currentMenu = MENU_MAIN;
            menuSelection = 0;
            showMainMenu();
          } else {
            // OK pressed - start USB pairing
            u8g2.clearBuffer();
            u8g2.setFont(u8g2_font_9x15_tf);
            u8g2.drawStr(10, 30, "USB Pairing...");
            u8g2.setFont(u8g2_font_6x10_tf);
            u8g2.drawStr(0, 50, "Connect PC now");
            u8g2.sendBuffer();
            
            // Start USB pairing sequence
            extern void sendUSBReady();
            extern void handleUSBPairing();
            sendUSBReady();
            handleUSBPairing();
            
            // After pairing, show USB ready screen
            u8g2.clearBuffer();
            u8g2.setFont(u8g2_font_9x15B_tf);
            u8g2.drawStr(15, 25, "USB Ready");
            u8g2.setFont(u8g2_font_6x10_tf);
            u8g2.drawStr(0, 45, "Run wallet_cli.py");
            u8g2.sendBuffer();
            currentMenu = MENU_IDLE;
          }
        }
      }
      else if (buttonPressed(BTN_BACK)) {
        currentMenu = MENU_MAIN;
        menuSelection = 0;
        showMainMenu();
      }
      break;
      
    case MENU_SHOW_ADDRESS:
    case MENU_DEVICE_INFO:
      if (buttonPressed(BTN_BACK)) {
        currentMenu = MENU_MAIN;
        menuSelection = 0;
        showMainMenu();
      }
      break;
      
    case MENU_SETTINGS:
      if (buttonPressed(BTN_UP) && menuSelection > 0) {
        menuSelection--;
        showSettingsMenu();
      }
      else if (buttonPressed(BTN_DOWN) && menuSelection < SETTINGS_MENU_SIZE - 1) {
        menuSelection++;
        showSettingsMenu();
      }
      else if (buttonPressed(BTN_OK)) {
        // Currently only Change PIN option
        currentMenu = MENU_CHANGE_PIN;
        // Show PIN change intro screen
        u8g2.clearBuffer();
        drawMenuHeader("Change PIN");
        u8g2.setFont(u8g2_font_6x10_tf);
        u8g2.drawStr(0, 30, "Press OK to start");
        u8g2.drawStr(0, 42, "BACK to cancel");
        u8g2.sendBuffer();
      }
      else if (buttonPressed(BTN_BACK)) {
        currentMenu = MENU_MAIN;
        menuSelection = 0;
        showMainMenu();
      }
      break;
      
    case MENU_CHANGE_PIN:
      if (buttonPressed(BTN_OK)) {
        // Start PIN change process
        // First verify current PIN
        u8g2.clearBuffer();
        u8g2.setFont(u8g2_font_6x10_tf);
        u8g2.drawStr(0, 30, "Verify current PIN...");
        u8g2.sendBuffer();
        delay(500);
        
        uint8_t oldPIN[6], newPIN1[6], newPIN2[6];
        
        // Enter current PIN
        extern bool enterPIN(const char*, uint8_t[6]);
        if (!enterPIN("Current PIN:", oldPIN)) {
          u8g2.clearBuffer();
          drawCenteredLarge("Cancelled", 0);
          u8g2.sendBuffer();
          delay(1000);
          currentMenu = MENU_MAIN;
          menuSelection = 0;
          showMainMenu();
          break;
        }
        
        // Verify current PIN matches
        extern uint8_t pin_key[16], pin_salt[16];
        extern void deriveKeyFromPIN(const uint8_t pin[6], const uint8_t salt[16], uint8_t outKey[16]);
        extern Preferences prefs;
        uint8_t testKey[16];
        deriveKeyFromPIN(oldPIN, pin_salt, testKey);
        if (memcmp(testKey, pin_key, 16) != 0) {
          u8g2.clearBuffer();
          drawCenteredLarge("Wrong PIN!", 0);
          u8g2.sendBuffer();
          delay(2000);
          currentMenu = MENU_MAIN;
          menuSelection = 0;
          showMainMenu();
          break;
        }
        
        // Enter new PIN
        if (!enterPIN("New PIN:", newPIN1)) {
          u8g2.clearBuffer();
          drawCenteredLarge("Cancelled", 0);
          u8g2.sendBuffer();
          delay(1000);
          currentMenu = MENU_MAIN;
          menuSelection = 0;
          showMainMenu();
          break;
        }
        
        // Confirm new PIN
        if (!enterPIN("Confirm PIN:", newPIN2)) {
          u8g2.clearBuffer();
          drawCenteredLarge("Cancelled", 0);
          u8g2.sendBuffer();
          delay(1000);
          currentMenu = MENU_MAIN;
          menuSelection = 0;
          showMainMenu();
          break;
        }
        
        // Check PINs match
        if (memcmp(newPIN1, newPIN2, 6) != 0) {
          u8g2.clearBuffer();
          drawCenteredLarge("No Match!", 0);
          u8g2.sendBuffer();
          delay(2000);
          currentMenu = MENU_MAIN;
          menuSelection = 0;
          showMainMenu();
          break;
        }
        
        // Generate new salt and derive new key
        u8g2.clearBuffer();
        drawCenteredLarge("Saving...", 0);
        u8g2.sendBuffer();
        
        uint8_t newSalt[16];
        esp_fill_random(newSalt, 16);
        uint8_t newKey[16];
        deriveKeyFromPIN(newPIN1, newSalt, newKey);
        
        // Re-encrypt wallet key with new PIN key
        extern uint8_t ed25519_sk[32], ed25519_pk[32];
        extern String mnemonicWords[12];
        prefs.begin("wallet", false);
        
        // Store new salt
        prefs.putBytes("pin_salt", newSalt, 16);
        
        // Re-encrypt private key with new key (must match original format!)
        // Format: enc_sk = 48 bytes (32 ciphertext + 16 tag), sk_iv = 12 bytes
        uint8_t iv[12];
        uint8_t encrypted[48];  // 32 ciphertext + 16 tag
        esp_fill_random(iv, 12);
        
        mbedtls_gcm_context gcm;
        mbedtls_gcm_init(&gcm);
        mbedtls_gcm_setkey(&gcm, MBEDTLS_CIPHER_ID_AES, newKey, 128);
        
        uint8_t tag[16];
        mbedtls_gcm_crypt_and_tag(&gcm, MBEDTLS_GCM_ENCRYPT, 32,
                                   iv, 12, NULL, 0,
                                   ed25519_sk, encrypted, 16, tag);
        mbedtls_gcm_free(&gcm);
        
        // Append tag to encrypted (matching original format)
        memcpy(encrypted + 32, tag, 16);
        
        prefs.putBytes("enc_sk", encrypted, 48);
        prefs.putBytes("sk_iv", iv, 12);
        prefs.end();
        
        // Update global PIN key
        memcpy(pin_salt, newSalt, 16);
        memcpy(pin_key, newKey, 16);
        
        u8g2.clearBuffer();
        drawCenteredLarge("PIN Changed!", 0);
        u8g2.sendBuffer();
        delay(2000);
        
        currentMenu = MENU_MAIN;
        menuSelection = 0;
        showMainMenu();
      }
      else if (buttonPressed(BTN_BACK)) {
        currentMenu = MENU_MAIN;
        menuSelection = 0;
        showMainMenu();
      }
      break;
      
    case MENU_FACTORY_RESET:
      if (buttonPressed(BTN_OK)) {
        // Perform factory reset
        u8g2.clearBuffer();
        drawCenteredLarge("Wiping...", 0);
        u8g2.sendBuffer();
        
        // Clear all NVS namespaces
        Preferences wipePrefs;
        wipePrefs.begin("wallet", false);
        wipePrefs.clear();
        wipePrefs.end();
        
        wipePrefs.begin("wifi", false);
        wipePrefs.clear();
        wipePrefs.end();
        
        delay(1000);
        u8g2.clearBuffer();
        drawCenteredLarge("Done!", -10);
        u8g2.setFont(u8g2_font_6x10_tf);
        u8g2.drawStr(20, 50, "Restarting...");
        u8g2.sendBuffer();
        delay(2000);
        ESP.restart();
      }
      else if (buttonPressed(BTN_BACK)) {
        currentMenu = MENU_MAIN;
        menuSelection = 0;
        showMainMenu();
      }
      break;
      
    default:
      currentMenu = MENU_IDLE;
      break;
  }
}

// ===== MENU UPDATE (call from loop) =====
inline bool isMenuActive() {
  return currentMenu != MENU_IDLE;
}

inline void updateMenu() {
  handleMenuInput();
}
