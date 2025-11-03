/**
 * Solana Wallet Test (ESP32 + Adafruit SSD1306)
 * - WiFi + TLS to PC
 * - Generates 12-word BIP39 mnemonic (via Trezor Crypto) on first boot
 * - Derives Solana ed25519 key at m/44'/501'/0'/0'
 * - Saves private key in NVS (Preferences)
 * - Displays mnemonic words auto-scrolling, text size ~2
 * - Sends Base58 public key to Python TLS server as JSON:
 *     {"action":"pubkey","pubkey":"<BASE58>"}
 *
 * Requirements (Arduino/PlatformIO):
 * - Adafruit SSD1306 + Adafruit GFX
 * - ArduinoJson
 * - Trezor Crypto sources (bip39, pbkdf2, ed25519, slip10)
 * - This project expects a rootCA.h file containing:
 *     extern const char* ROOT_CA;  // PEM string of server cert
 */

#include <WiFi.h>
#include <WiFiClientSecure.h>
#include <Preferences.h>
#include <ArduinoJson.h>

#include <Adafruit_GFX.h>
#include <Adafruit_SSD1306.h>

#include "mnemonic_handler.h"
#include "rootCA.h"  // must define: extern const char* ROOT_CA

// ========= USER CONFIG =========
const char* WIFI_SSID = "iPhone";     // Rename hotspot to remove apostrophe
const char* WIFI_PASS = "bigmannet32";

const char* SERVER_HOST = "172.20.10.10";  // PC Hotspot default IP
const uint16_t SERVER_PORT = 8443;

// ========= OLED CONFIG =========
#define SCREEN_WIDTH 128
#define SCREEN_HEIGHT 64
#define OLED_RESET   -1
Adafruit_SSD1306 display(SCREEN_WIDTH, SCREEN_HEIGHT, &Wire, OLED_RESET);

// ========= TLS CLIENT =========
WiFiClientSecure tls;

// ========= HELPERS =========

// Base58 encoding for Solana pubkey
String base58_encode(const uint8_t* data, size_t len) {
  static const char* ALPHABET = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz";
  // Count leading zeros
  size_t zeros = 0;
  while (zeros < len && data[zeros] == 0) zeros++;

  // Allocate enough space for big-endian base58 representation.
  size_t size = (len - zeros) * 138 / 100 + 1; // log(256)/log(58), +1 for safety
  uint8_t* b58 = (uint8_t*)malloc(size);
  memset(b58, 0, size);

  // Process the bytes
  for (size_t i = zeros; i < len; i++) {
    int carry = data[i];
    for (ssize_t j = size - 1; j >= 0; j--) {
      carry += 256 * b58[j];
      b58[j] = carry % 58;
      carry /= 58;
    }
  }

  // Skip leading zeros in base58 result
  size_t it = 0;
  while (it < size && b58[it] == 0) it++;

  // Compose string
  String result;
  result.reserve(zeros + (size - it));
  // Leading zeros as '1'
  for (size_t i = 0; i < zeros; i++) result += '1';
  for (; it < size; it++) result += ALPHABET[b58[it]];

  free(b58);
  return result;
}

void showCentered(const String& line1, const String& line2="") {
  display.clearDisplay();
  display.setTextSize(2);             // size ~2
  display.setTextColor(SSD1306_WHITE);
  display.setCursor(0, 16);
  display.println(line1);
  if (line2.length()) {
    display.setCursor(0, 40);
    display.println(line2);
  }
  display.display();
}

void showMnemonicScroll(const String& mnemonic) {
  // Split words
  const int maxWords = 24;
  String words[maxWords];
  int count = 0;
  int start = 0;
  for (int i=0; i<mnemonic.length(); ++i) {
    if (mnemonic[i] == ' ') {
      words[count++] = mnemonic.substring(start, i);
      start = i+1;
      if (count >= maxWords) break;
    }
  }
  if (start < mnemonic.length() && count < maxWords) words[count++] = mnemonic.substring(start);

  // Render 2 words per screen (size 2 font)
  for (int i=0; i<count; i+=2) {
    display.clearDisplay();
    display.setTextSize(2);
    display.setTextColor(SSD1306_WHITE);
    display.setCursor(0, 8);
    display.print(i+1); display.print(". "); display.println(words[i]);
    if (i+1 < count) {
      display.setCursor(0, 36);
      display.print(i+2); display.print(". "); display.println(words[i+1]);
    }
    display.display();
    delay(1500);
  }
}

// ========= MAIN =========
Preferences prefs;

void setup() {
  Serial.begin(9600);
  delay(200);

  if(!display.begin(SSD1306_SWITCHCAPVCC, 0x3C)) {
    Serial.println("SSD1306 allocation failed");
    while(true) delay(1000);
  }
  display.clearDisplay();
  display.display();

  showCentered("WiFi connect");
  WiFi.mode(WIFI_STA);
  WiFi.begin(WIFI_SSID, WIFI_PASS);
  uint32_t t0 = millis();
  while (WiFi.status() != WL_CONNECTED) {
    delay(250);
    if (millis() - t0 > 15000) break;
  }
  if (WiFi.status() != WL_CONNECTED) {
    showCentered("WiFi FAIL");
    Serial.println("WiFi connect failed.");
    while(true) delay(2000);
  }
  showCentered("WiFi OK", WiFi.localIP().toString());

  // Load or create wallet
  bool hasWallet = load_wallet_from_nvs();
  if (!hasWallet) {
    create_new_wallet();
  }
  String mnemonic = get_mnemonic();
  showMnemonicScroll(mnemonic);

  // Compute Base58 pubkey string
  const uint8_t* pub = get_public_key();
  String pub58 = base58_encode(pub, 32);
  Serial.print("Pubkey (Base58): ");
  Serial.println(pub58);

  // TLS connect to server
  tls.setCACert(ROOT_CA);
  showCentered("TLS connect");
  if (!tls.connect(SERVER_HOST, SERVER_PORT)) {
    showCentered("TLS FAIL");
    Serial.println("TLS connect failed");
    while(true) delay(2000);
  }
  showCentered("TLS OK");

  // Send JSON: {"action":"pubkey","pubkey":"<base58>"}
  StaticJsonDocument<256> doc;
  doc["action"] = "pubkey";
  doc["pubkey"] = pub58;
  String payload;
  serializeJson(doc, payload);
  payload += "\n";
  tls.print(payload);
  Serial.print("Sent: ");
  Serial.println(payload);

  // Read server response
  String line = tls.readStringUntil('\n');
  Serial.print("Server: ");
  Serial.println(line);

  showCentered("Done", "Check PC");
}

void loop() {
  // Nothing else; mnemonic already shown once
}
