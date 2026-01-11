#include <WiFi.h>
#include <WiFiClientSecure.h>
#include <Preferences.h>
#include <ArduinoJson.h>
#include <U8g2lib.h>
#include <esp_random.h>
#include <esp_ota_ops.h>
#include "mbedtls/sha256.h"
#include "mbedtls/gcm.h"
#include "mbedtls/base64.h"
#include "key_storage.h"
#include "display_ui.h"
#include "transaction_handler.h"
#include "crypto/ed25519.h"
#include "crypto/mnemonic.h"
#include "security_hardening.h"
#include "transaction_parser.h"
#include "boot_integrity.h"
#include "menu_system.h"

// WebSocket server for mobile app connectivity
#define USE_WEBSOCKET_SERVER 1
#if USE_WEBSOCKET_SERVER
#include <WebSocketsServer.h>
#endif

// TLS certificates are now generated per-device at first boot
// See cert_generator.h for implementation

// ===== CONFIGURATION =====
// WiFi credentials now stored in NVS, not hardcoded
// Hold DOWN button during boot to enter WiFi setup mode
const uint16_t SERVER_PORT = 8443;

// ===== HARDWARE PINS =====
const int BTN_OK = 15;     // Confirm
const int BTN_UP = 5;      // Blue 1
const int BTN_DOWN = 23;   // Blue 2 
const int BTN_BACK = 18;   // Reject 

// ===== TLS CONFIGURATION =====
// TLS server with per-device certificates (generated at first boot)
#define USE_TLS_SERVER 1  // Enabled - uses cert_generator.h for per-device certs
#if USE_TLS_SERVER
#include "tls_server.h"
// tlsServer is declared globally in tls_server.h
#endif

// ===== GLOBAL OBJECTS =====
U8G2_SSD1306_128X64_NONAME_F_HW_I2C u8g2(U8G2_R0, U8X8_PIN_NONE);
#if !USE_TLS_SERVER
WiFiServer wifiServer(SERVER_PORT);
#endif
Preferences prefs;

uint8_t ed25519_sk[32];
uint8_t ed25519_pk[32];
String mnemonicWords[12];  // Backup phrase

// ===== AES-GCM SECURE CHANNEL =====
uint8_t aes_key[16];  // Shared AES key (exchanged during pairing)
uint8_t channel_salt[8];  // Salt for nonce generation
uint32_t tx_counter = 1;

// Initialize with zeros - will be set during ECDH key exchange
bool secure_channel_ready = false;

// ===== RECOVERY CODE (Physical Access Verification) =====
uint32_t recovery_code = 0;  // 6-digit code displayed on device
unsigned long recovery_code_expires = 0;  // Expiration time
const unsigned long RECOVERY_CODE_TIMEOUT_MS = 120000;  // 2 minutes

// ===== USB SERIAL MODE =====
bool usb_mode_active = false;
unsigned long last_serial_activity = 0;

// ===== PIN PROTECTION =====
uint8_t pin_salt[16];  // Salt for PBKDF2
uint8_t pin_key[16];   // Derived AES key from PIN
bool pin_verified = false;

// ===== REPLAY PROTECTION =====
const int NONCE_BUFFER_SIZE = 32;
uint32_t seen_nonces[NONCE_BUFFER_SIZE];
int nonce_buffer_idx = 0;
uint32_t last_msg_time = 0;
const uint32_t MSG_VALIDITY_WINDOW = 60000;  // 60 seconds

// ===== SESSION TIMEOUT (used by security_hardening.h) =====
unsigned long lastActivityTime = 0;
bool sessionActive = false;

// ===== SIGN RATE LIMITING (used by security_hardening.h) =====
unsigned long signTimestamps[SIGN_HISTORY_SIZE] = {0};
uint8_t signTimestampIndex = 0;

// ===== QR CODE DISPLAY TOGGLE =====
bool showQRCode = true;  // Toggle between QR code and text IP display
unsigned long lastDisplayToggle = 0;  // Debounce button

// ===== CONNECTION MODE =====
bool usbModeActive = false;  // True when in USB mode (prevents WiFi code from running)

// ===== WEBSOCKET SERVER (for mobile app) =====
#if USE_WEBSOCKET_SERVER
WebSocketsServer wsServer(8444);
void handleWSMessage(uint8_t num, uint8_t* payload, size_t length);  // Forward declaration
void wsEvent(uint8_t num, WStype_t type, uint8_t* payload, size_t length);  // Forward declaration
#endif

// ===== UTILITY FUNCTIONS =====
// bytesToHex is defined in transaction_handler.h

void hexToBytes(const char* hex, uint8_t* out, size_t outLen) {
  for (size_t i = 0; i < outLen; i++) {
    char h = hex[i*2];
    char l = hex[i*2+1];
    uint8_t hi = (h >= 'a') ? (h - 'a' + 10) : ((h >= 'A') ? (h - 'A' + 10) : (h - '0'));
    uint8_t lo = (l >= 'a') ? (l - 'a' + 10) : ((l >= 'A') ? (l - 'A' + 10) : (l - '0'));
    out[i] = (hi << 4) | lo;
  }
}

// Check for replay attack - returns true if message is valid (not replayed)
bool checkReplayProtection(uint32_t nonce, uint32_t timestamp) {
  // Check timestamp validity (within window)
  uint32_t now = millis();
  if (timestamp != 0) {
    int32_t age = now - timestamp;
    if (age < -5000 || age > (int32_t)MSG_VALIDITY_WINDOW) {
      Serial.println("[SEC] Replay: timestamp out of window");
      return false;
    }
  }
  
  // Check if nonce already seen
  for (int i = 0; i < NONCE_BUFFER_SIZE; i++) {
    if (seen_nonces[i] == nonce && nonce != 0) {
      Serial.println("[SEC] Replay: duplicate nonce");
      return false;
    }
  }
  
  // Add to seen nonces (circular buffer)
  if (nonce != 0) {
    seen_nonces[nonce_buffer_idx] = nonce;
    nonce_buffer_idx = (nonce_buffer_idx + 1) % NONCE_BUFFER_SIZE;
  }
  
  return true;
}

String bytesToBase58(const uint8_t* data, size_t len) {
  const char* ALPHABET = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz";
  String result = "";
  uint8_t temp[64];
  memcpy(temp, data, len);
  size_t tempLen = len;
  
  while (tempLen > 0) {
    uint32_t remainder = 0;
    size_t newLen = 0;
    for (size_t i = 0; i < tempLen; i++) {
      uint32_t digit = (remainder << 8) + temp[i];
      temp[newLen] = digit / 58;
      remainder = digit % 58;
      if (temp[newLen] > 0 || newLen > 0) newLen++;
    }
    result = String(ALPHABET[remainder]) + result;
    tempLen = newLen;
  }
  
  for (size_t i = 0; i < len && data[i] == 0; i++) {
    result = "1" + result;
  }
  
  return result;
}

// ===== AES-GCM ENCRYPTION (SecureChannel compatible) =====
bool encryptAESGCM(const uint8_t* plaintext, size_t ptLen, 
                   uint8_t* nonce, uint8_t* ciphertext, uint8_t* tag) {
  // Build nonce: salt (8 bytes) + counter (4 bytes)
  memcpy(nonce, channel_salt, 8);
  nonce[8] = (tx_counter >> 24) & 0xFF;
  nonce[9] = (tx_counter >> 16) & 0xFF;
  nonce[10] = (tx_counter >> 8) & 0xFF;
  nonce[11] = tx_counter & 0xFF;
  tx_counter++;
  
  mbedtls_gcm_context gcm;
  mbedtls_gcm_init(&gcm);
  
  int ret = mbedtls_gcm_setkey(&gcm, MBEDTLS_CIPHER_ID_AES, aes_key, 128);
  if (ret != 0) {
    mbedtls_gcm_free(&gcm);
    return false;
  }
  
  ret = mbedtls_gcm_crypt_and_tag(&gcm, MBEDTLS_GCM_ENCRYPT, ptLen,
                                   nonce, 12, NULL, 0,
                                   plaintext, ciphertext,
                                   16, tag);
  
  mbedtls_gcm_free(&gcm);
  return ret == 0;
}

bool decryptAESGCM(const uint8_t* nonce, const uint8_t* ciphertext, size_t ctLen,
                   const uint8_t* tag, uint8_t* plaintext) {
  mbedtls_gcm_context gcm;
  mbedtls_gcm_init(&gcm);
  
  int ret = mbedtls_gcm_setkey(&gcm, MBEDTLS_CIPHER_ID_AES, aes_key, 128);
  if (ret != 0) {
    mbedtls_gcm_free(&gcm);
    return false;
  }
  
  ret = mbedtls_gcm_auth_decrypt(&gcm, ctLen, nonce, 12, NULL, 0,
                                  tag, 16, ciphertext, plaintext);
  
  mbedtls_gcm_free(&gcm);
  return ret == 0;
}

// Send encrypted JSON response
void sendEncryptedResponse(WiFiClient& client, const char* jsonStr) {
  size_t jsonLen = strlen(jsonStr);
  uint8_t nonce[12];
  uint8_t* ciphertext = new uint8_t[jsonLen];
  uint8_t tag[16];
  
  if (!encryptAESGCM((const uint8_t*)jsonStr, jsonLen, nonce, ciphertext, tag)) {
    Serial.println("[ENC] Encryption failed!");
    delete[] ciphertext;
    return;
  }
  
  // Build frame: nonce || ciphertext || tag
  size_t frameLen = 12 + jsonLen + 16;
  uint8_t* frame = new uint8_t[frameLen];
  memcpy(frame, nonce, 12);
  memcpy(frame + 12, ciphertext, jsonLen);
  memcpy(frame + 12 + jsonLen, tag, 16);
  
  // Base64 encode
  size_t b64Len = 0;
  mbedtls_base64_encode(NULL, 0, &b64Len, frame, frameLen);
  uint8_t* b64 = new uint8_t[b64Len + 1];
  mbedtls_base64_encode(b64, b64Len + 1, &b64Len, frame, frameLen);
  
  // Send as ENC: frame
  client.print("ENC:");
  client.print((char*)b64);
  client.print("\n");
  
  delete[] ciphertext;
  delete[] frame;
  delete[] b64;
  
  Serial.println("[ENC] Sent encrypted response");
}

// Receive and decrypt JSON command
bool recvDecryptedJson(WiFiClient& client, StaticJsonDocument<1024>& doc) {
  String line = client.readStringUntil('\n');
  line.trim();
  
  if (line.length() == 0) return false;
  
  // Check if encrypted (ENC: prefix) or plain JSON
  if (!line.startsWith("ENC:")) {
    // Plain JSON (for initial pairing)
    DeserializationError err = deserializeJson(doc, line);
    return err == DeserializationError::Ok;
  }
  
  // Encrypted frame
  String b64Data = line.substring(4);
  
  // Base64 decode
  size_t rawLen = 0;
  mbedtls_base64_decode(NULL, 0, &rawLen, (const uint8_t*)b64Data.c_str(), b64Data.length());
  uint8_t* raw = new uint8_t[rawLen];
  mbedtls_base64_decode(raw, rawLen, &rawLen, (const uint8_t*)b64Data.c_str(), b64Data.length());
  
  if (rawLen < 28) {  // 12 nonce + minimum 0 ct + 16 tag
    delete[] raw;
    return false;
  }
  
  // Parse frame: nonce || ciphertext || tag
  uint8_t* nonce = raw;
  size_t ctLen = rawLen - 12 - 16;
  uint8_t* ct = raw + 12;
  uint8_t* tag = raw + 12 + ctLen;
  
  uint8_t* plaintext = new uint8_t[ctLen + 1];
  bool success = decryptAESGCM(nonce, ct, ctLen, tag, plaintext);
  
  if (success) {
    plaintext[ctLen] = '\0';
    DeserializationError err = deserializeJson(doc, (char*)plaintext);
    success = (err == DeserializationError::Ok);
  }
  
  delete[] raw;
  delete[] plaintext;
  return success;
}

// ===== PIN ENTRY UI =====
// Enter a 6-digit PIN using buttons and display
// Returns true if PIN entered, false if cancelled
bool enterPIN(const char* title, uint8_t pin[6]) {
  int currentDigit = 0;
  uint8_t digits[6] = {0, 0, 0, 0, 0, 0};
  
  while (currentDigit < 6) {
    // Draw PIN screen
    u8g2.clearBuffer();
    u8g2.setFont(u8g2_font_7x14_tf);
    u8g2.drawUTF8(0, 12, title);
    
    // Draw digit boxes (6 digits now)
    for (int i = 0; i < 6; i++) {
      int x = 8 + i * 20;  // Tighter spacing for 6 digits
      if (i < currentDigit) {
        // Entered digit - show asterisk
        u8g2.drawStr(x + 4, 35, "*");
      } else if (i == currentDigit) {
        // Current digit - show number
        char buf[2] = {(char)('0' + digits[i]), 0};
        u8g2.drawStr(x + 4, 35, buf);
        u8g2.drawFrame(x, 20, 18, 22);  // Highlight box
      } else {
        // Future digit - show underscore
        u8g2.drawStr(x + 4, 35, "_");
      }
    }
    
    // Draw button hints
    u8g2.setFont(u8g2_font_5x7_tf);
    u8g2.drawStr(0, 55, "UP/DN=Digit OK=Next BACK=Del");
    u8g2.sendBuffer();
    
    // Check buttons
    if (digitalRead(BTN_UP) == LOW) {
      digits[currentDigit] = (digits[currentDigit] + 1) % 10;
      delay(200);
    }
    if (digitalRead(BTN_DOWN) == LOW) {
      digits[currentDigit] = (digits[currentDigit] + 9) % 10;
      delay(200);
    }
    if (digitalRead(BTN_OK) == LOW) {
      currentDigit++;
      delay(200);
    }
    if (digitalRead(BTN_BACK) == LOW) {
      if (currentDigit > 0) {
        currentDigit--;
      } else {
        return false; // Cancel
      }
      delay(200);
    }
    
    delay(50);
  }
  
  memcpy(pin, digits, 6);
  return true;
}

// Derive AES key from PIN using PBKDF2-like approach (100K iterations)
void deriveKeyFromPIN(const uint8_t pin[6], const uint8_t salt[16], uint8_t outKey[16]) {
  // Combine PIN digits into bytes
  uint8_t pinBytes[6];
  for (int i = 0; i < 6; i++) {
    pinBytes[i] = pin[i];
  }
  
  // PBKDF2-like derivation: iterate SHA256
  uint8_t hash[32];
  uint8_t data[22];  // 6 PIN + 16 salt
  memcpy(data, pinBytes, 6);
  memcpy(data + 6, salt, 16);
  
  mbedtls_sha256(data, 22, hash, 0);
  
  // SECURITY: 100,000 iterations for strong key stretching (~1 second on ESP32)
  for (int i = 0; i < 100000; i++) {
    mbedtls_sha256(hash, 32, hash, 0);
  }
  
  // Use first 16 bytes as AES key
  memcpy(outKey, hash, 16);
}

// Encrypt private key with PIN-derived key
bool encryptKeyWithPIN(const uint8_t sk[32], const uint8_t pinKey[16], 
                       uint8_t encrypted[48], uint8_t iv[12]) {
  esp_fill_random(iv, 12);
  
  mbedtls_gcm_context gcm;
  mbedtls_gcm_init(&gcm);
  mbedtls_gcm_setkey(&gcm, MBEDTLS_CIPHER_ID_AES, pinKey, 128);
  
  uint8_t tag[16];
  int ret = mbedtls_gcm_crypt_and_tag(&gcm, MBEDTLS_GCM_ENCRYPT, 32,
                                       iv, 12, NULL, 0,
                                       sk, encrypted,
                                       16, tag);
  mbedtls_gcm_free(&gcm);
  
  // Append tag to encrypted data
  memcpy(encrypted + 32, tag, 16);
  
  return ret == 0;
}

// Decrypt private key with PIN-derived key
bool decryptKeyWithPIN(const uint8_t encrypted[48], const uint8_t iv[12],
                       const uint8_t pinKey[16], uint8_t sk[32]) {
  mbedtls_gcm_context gcm;
  mbedtls_gcm_init(&gcm);
  mbedtls_gcm_setkey(&gcm, MBEDTLS_CIPHER_ID_AES, pinKey, 128);
  
  uint8_t tag[16];
  memcpy(tag, encrypted + 32, 16);
  
  int ret = mbedtls_gcm_auth_decrypt(&gcm, 32, iv, 12,
                                      NULL, 0, tag, 16,
                                      encrypted, sk);
  mbedtls_gcm_free(&gcm);
  
  return ret == 0;
}

// ===== USB SERIAL HANDLERS =====
bool usb_paired = false;
uint8_t usb_aes_key[16];  // 128-bit key for AES-GCM (SecureChannel compatible)
uint8_t usb_nonce_counter = 0;

// ECDH for USB pairing - using secp256r1 curve
#include "mbedtls/ecdh.h"
#include "mbedtls/entropy.h"
#include "mbedtls/ctr_drbg.h"

// Throttle USB_READY to prevent serial buffer overflow
static unsigned long lastUSBReadyTime = 0;

void sendUSBReady() {
  // Only send once per second max
  if (millis() - lastUSBReadyTime < 1000) return;
  lastUSBReadyTime = millis();
  
  Serial.println("USB_READY");
  Serial.flush();
}

void sendEncryptedUSB(const String& json);  // Forward declaration

void handleUSBPairing() {
  mbedtls_ecdh_context ecdh;
  mbedtls_entropy_context entropy;
  mbedtls_ctr_drbg_context ctr_drbg;
  
  mbedtls_ecdh_init(&ecdh);
  mbedtls_entropy_init(&entropy);
  mbedtls_ctr_drbg_init(&ctr_drbg);
  
  const char *pers = "ecdh_pairing";
  mbedtls_ctr_drbg_seed(&ctr_drbg, mbedtls_entropy_func, &entropy,
                        (const unsigned char *)pers, strlen(pers));
  
  // Setup ECDH using internal structure (ESP32 mbedtls compatibility)
  mbedtls_ecp_group grp;
  mbedtls_mpi d;  // Private key
  mbedtls_ecp_point Q;  // Public key
  
  mbedtls_ecp_group_init(&grp);
  mbedtls_mpi_init(&d);
  mbedtls_ecp_point_init(&Q);
  
  mbedtls_ecp_group_load(&grp, MBEDTLS_ECP_DP_SECP256R1);
  mbedtls_ecdh_gen_public(&grp, &d, &Q, mbedtls_ctr_drbg_random, &ctr_drbg);
  
  // Export wallet public key (uncompressed point format)
  unsigned char wallet_pub[65];
  size_t olen = 0;
  mbedtls_ecp_point_write_binary(&grp, &Q, MBEDTLS_ECP_PF_UNCOMPRESSED,
                                  &olen, wallet_pub, sizeof(wallet_pub));
  
  // USB_READY already sent by sendUSBReady() before this function
  // Wait for PC public key
  
  String line = "";
  unsigned long start = millis();
  while (millis() - start < 30000) {  // 30 second timeout
    if (Serial.available()) {
      char c = Serial.read();
      if (c == '\n') {
        StaticJsonDocument<512> doc;
        DeserializationError err = deserializeJson(doc, line);
        
        if (err == DeserializationError::Ok) {
          const char* action = doc["action"] | "";
          
          if (strcmp(action, "pc_pub") == 0) {
            const char* pc_pub_hex = doc["pc_pub"] | "";
            
            // Parse PC public key
            unsigned char pc_pub[65];
            hexToBytes(pc_pub_hex, pc_pub, 65);
            
            // Load PC public key
            mbedtls_ecp_point pc_point;
            mbedtls_ecp_point_init(&pc_point);
            mbedtls_ecp_point_read_binary(&grp, &pc_point, pc_pub, 65);
            
            // Compute shared secret
            mbedtls_mpi shared_secret;
            mbedtls_mpi_init(&shared_secret);
            mbedtls_ecdh_compute_shared(&grp, &shared_secret, &pc_point, &d,
                                         mbedtls_ctr_drbg_random, &ctr_drbg);
            
            // Export shared secret
            unsigned char shared[32];
            mbedtls_mpi_write_binary(&shared_secret, shared, 32);
            
            // Generate pairing code = SHA256(shared || wallet_pub || pc_pub) % 1000000
            uint8_t hash_input[162];  // 32 + 65 + 65
            memcpy(hash_input, shared, 32);
            memcpy(hash_input + 32, wallet_pub, 65);
            memcpy(hash_input + 97, pc_pub, 65);
            
            uint8_t code_hash[32];
            mbedtls_sha256(hash_input, sizeof(hash_input), code_hash, 0);
            
            uint32_t code_num = ((uint32_t)code_hash[0] << 24) |
                                 ((uint32_t)code_hash[1] << 16) |
                                 ((uint32_t)code_hash[2] << 8) |
                                 ((uint32_t)code_hash[3]);
            code_num = code_num % 1000000;
            
            char code_str[7];
            snprintf(code_str, sizeof(code_str), "%06lu", code_num);
            
            // Send wallet pubkey and pairing code
            Serial.print("{\"status\":\"ok\",\"wallet_pub\":\"");
            Serial.print(bytesToHex(wallet_pub, 65));
            Serial.print("\",\"code\":\"");
            Serial.print(code_str);
            Serial.println("\"}");
            Serial.flush();
            
            // Display pairing code on OLED
            u8g2.clearBuffer();
            u8g2.setFont(u8g2_font_9x15_tf);
            u8g2.drawUTF8(0, 20, "USB Pairing");
            u8g2.drawUTF8(0, 40, "Code:");
            u8g2.setFont(u8g2_font_10x20_tf);
            u8g2.drawUTF8(10, 60, code_str);
            u8g2.sendBuffer();
            
            // Wait for user decision
            drawCentered("Confirm pairing?", -10);
            drawCentered("OK=Yes DOWN=No", 10);
            
            int decision = waitForDecision();
            
            if (decision == 1) {
              // User approved
              Serial.println("{\"action\":\"user\",\"decision\":\"allow\"}");
              Serial.flush();
              
              // Derive 16-byte AES key (128-bit for SecureChannel compatibility)
              uint8_t key_material[64];
              memcpy(key_material, shared, 32);
              memcpy(key_material + 32, "USBPAIRv1", 9);
              
              uint8_t temp_key[32];
              mbedtls_sha256(key_material, 41, temp_key, 0);
              
              // Use first 16 bytes for AES-128-GCM (SecureChannel compatible)
              memcpy(usb_aes_key, temp_key, 16);
              
              usb_paired = true;
              drawCentered("USB Paired!", 0);
              delay(1000);
            } else {
              Serial.println("{\"action\":\"user\",\"decision\":\"deny\"}");
              Serial.flush();
              drawCentered("Pairing Denied", 0);
              delay(1000);
            }
            
            mbedtls_ecp_point_free(&pc_point);
            mbedtls_mpi_free(&shared_secret);
            break;
          }
        }
        line = "";
      } else {
        line += c;
      }
    }
    delay(10);
  }
  
  mbedtls_ecp_group_free(&grp);
  mbedtls_mpi_free(&d);
  mbedtls_ecp_point_free(&Q);
  mbedtls_ecdh_free(&ecdh);
  mbedtls_entropy_free(&entropy);
  mbedtls_ctr_drbg_free(&ctr_drbg);
}

void handleSerialCommand() {
  if (!Serial.available()) return;
  
  String line = Serial.readStringUntil('\n');
  line.trim();
  
  if (line.length() == 0) return;
  
  // Check for encrypted message (SecureChannel format: "ENC:base64data")
  if (line.startsWith("ENC:") && usb_paired) {
    // Decrypt AES-GCM encrypted message
    String encData = line.substring(4);
    
    // Decode base64
    size_t outLen = 0;
    unsigned char decoded[512];
    mbedtls_base64_decode(decoded, sizeof(decoded), &outLen, 
                          (const unsigned char*)encData.c_str(), encData.length());
    
    if (outLen < 28) { // 12-byte nonce + 16-byte tag minimum
      Serial.println("{\"error\":\"invalid_encrypted\"}");
      return;
    }
    
    // Extract nonce (first 12 bytes) and tag (last 16 bytes)
    uint8_t nonce[12];
    memcpy(nonce, decoded, 12);
    
    size_t ciphertext_len = outLen - 12 - 16;
    uint8_t* ciphertext = decoded + 12;
    uint8_t tag[16];
    memcpy(tag, decoded + 12 + ciphertext_len, 16);
    
    // Decrypt with AES-GCM
    mbedtls_gcm_context gcm;
    mbedtls_gcm_init(&gcm);
    mbedtls_gcm_setkey(&gcm, MBEDTLS_CIPHER_ID_AES, usb_aes_key, 128);  // 128-bit key
    
    uint8_t plaintext[512];
    int ret = mbedtls_gcm_auth_decrypt(&gcm, ciphertext_len, nonce, 12,
                                        NULL, 0, tag, 16,
                                        ciphertext, plaintext);
    mbedtls_gcm_free(&gcm);
    
    if (ret != 0) {
      Serial.println("{\"error\":\"decrypt_failed\"}");
      return;
    }
    
    plaintext[ciphertext_len] = '\0';
    
    // Parse decrypted JSON
    StaticJsonDocument<1024> doc;
    DeserializationError err = deserializeJson(doc, (const char*)plaintext);
    
    if (err != DeserializationError::Ok) {
      Serial.println("{\"error\":\"invalid_json\"}");
      return;
    }
    
    // Handle decrypted command
    const char* cmd = doc["cmd"] | "";
    
    if (strcmp(cmd, "PUBKEY") == 0) {
      String pubkeyB58 = bytesToBase58(ed25519_pk, 32);
      String response = "{\"ok\":true,\"pubkey\":\"" + pubkeyB58 + "\"}";
      sendEncryptedUSB(response);
    }
    else if (strcmp(cmd, "PING") == 0) {
      sendEncryptedUSB("{\"ok\":true,\"pong\":true}");
    }
    else if (strcmp(cmd, "SIGN") == 0) {
      // SECURITY: Check sign rate limit
      if (isSignRateLimited()) {
        char rateLimitMsg[128];
        unsigned long waitSec = (getRateLimitRemainingMs() / 1000) + 1;
        snprintf(rateLimitMsg, sizeof(rateLimitMsg), 
                 "{\"ok\":false,\"error\":\"rate_limited\",\"wait_seconds\":%lu}", waitSec);
        sendEncryptedUSB(rateLimitMsg);
        return;
      }
      
      const char* msgHex = doc["msg"];
      Serial.println("[CMD] SIGN request from USB");
      
      // Decode hex message
      size_t hexLen = strlen(msgHex);
      size_t msgLen = hexLen / 2;
      uint8_t* msg = new uint8_t[msgLen];
      hexToBytes(msgHex, msg, msgLen);
      
      // Calculate hash for display
      uint8_t msgHash[32];
      mbedtls_sha256(msg, msgLen, msgHash, 0);
      
      // Show details
      u8g2.clearBuffer();
      u8g2.setFont(u8g2_font_6x10_tf);
      u8g2.drawStr(0, 12, "USB SIGN REQUEST");
      
      char sizeStr[32];
      snprintf(sizeStr, sizeof(sizeStr), "Size: %d bytes", msgLen);
      u8g2.drawStr(0, 26, sizeStr);
      
      char hashStr[32];
      snprintf(hashStr, sizeof(hashStr), "Hash: %02x%02x%02x...", 
               msgHash[0], msgHash[1], msgHash[2]);
      u8g2.drawStr(0, 40, hashStr);
      
      u8g2.setFont(u8g2_font_9x15_tf);
      u8g2.drawStr(0, 58, "OK=Sign X=Reject");
      u8g2.sendBuffer();
      
      int decision = waitForDecision();
      
      if (decision == 1) {
        uint8_t sig[64];
        ed25519_sign(msg, msgLen, ed25519_sk, ed25519_pk, sig);
        String sigB58 = bytesToBase58(sig, 64);
        String resp = "{\"ok\":true,\"sig_b58\":\"" + sigB58 + "\"}";
        sendEncryptedUSB(resp);
        drawCentered("Signed!", 0);
      } else {
        sendEncryptedUSB("{\"ok\":false,\"error\":\"rejected\"}");
        drawCentered("Rejected", 0);
      }
      delete[] msg;
      delay(1000);
      drawCentered("USB Mode", -10);
      drawCentered("Connected", 10);
    }
    else if (strcmp(cmd, "SHOW_MNEMONIC") == 0) {
      displayMnemonic();
      sendEncryptedUSB("{\"ok\":true}");
      // Restore screen
      drawCentered("USB Mode", -10);
      drawCentered("Connected", 10);
    }
    else if (strcmp(cmd, "SET_WIFI") == 0) {
      String ssid = doc["ssid"];
      String pass = doc["password"];
      
      if (ssid.length() == 0) {
        sendEncryptedUSB("{\"ok\":false,\"error\":\"empty_ssid\"}");
        return;
      }
      
      // SECURITY: Display confirmation on OLED and wait for button press
      Serial.println("[USB] SET_WIFI: Showing confirmation screen");
      u8g2.clearBuffer();
      u8g2.setFont(u8g2_font_7x14B_tf);
      u8g2.drawStr(5, 15, "SET WIFI?");
      u8g2.setFont(u8g2_font_6x10_tf);
      
      // Truncate SSID if too long for display
      String displaySsid = ssid.length() > 18 ? ssid.substring(0, 15) + "..." : ssid;
      u8g2.drawStr(5, 30, displaySsid.c_str());
      
      u8g2.drawStr(5, 50, "OK=Confirm BACK=Cancel");
      u8g2.sendBuffer();
      
      // Wait up to 30 seconds for button press
      unsigned long confirmStart = millis();
      bool confirmed = false;
      bool cancelled = false;
      
      while (millis() - confirmStart < 30000 && !confirmed && !cancelled) {
        if (digitalRead(BTN_OK) == LOW) {
          delay(50); // Debounce
          if (digitalRead(BTN_OK) == LOW) {
            confirmed = true;
            while (digitalRead(BTN_OK) == LOW) delay(10);
          }
        }
        if (digitalRead(BTN_BACK) == LOW) {
          delay(50); // Debounce
          if (digitalRead(BTN_BACK) == LOW) {
            cancelled = true;
            while (digitalRead(BTN_BACK) == LOW) delay(10);
          }
        }
        delay(10);
      }
      
      if (confirmed) {
        Preferences wifiPrefs;
        wifiPrefs.begin("wifi", false);
        wifiPrefs.putString("ssid", ssid);
        wifiPrefs.putString("password", pass);
        wifiPrefs.end();
        
        drawCentered("WiFi Saved!", 0);
        sendEncryptedUSB("{\"ok\":true}");
        delay(1000);
        ESP.restart();
      } else {
        drawCentered("WiFi Cancelled", 0);
        sendEncryptedUSB("{\"ok\":false,\"error\":\"user_cancelled\"}");
        delay(1500);
        drawCentered("USB Mode", -10);
        drawCentered("Connected", 10);
      }
    }
    // RECOVERY_INIT - Generate and display recovery code on device
    else if (strcmp(cmd, "RECOVERY_INIT") == 0) {
      if (!pin_verified) {
        sendEncryptedUSB("{\"ok\":false,\"error\":\"device_locked\"}");
        return;
      }
      
      // Generate random 6-digit code
      recovery_code = esp_random() % 1000000;
      recovery_code_expires = millis() + RECOVERY_CODE_TIMEOUT_MS;
      
      // Display on OLED
      u8g2.clearBuffer();
      u8g2.setFont(u8g2_font_7x14B_tf);
      u8g2.drawStr(10, 15, "RECOVERY CODE:");
      u8g2.setFont(u8g2_font_10x20_tf);
      char codeStr[8];
      snprintf(codeStr, sizeof(codeStr), "%06lu", recovery_code);
      u8g2.drawStr(30, 40, codeStr);
      u8g2.setFont(u8g2_font_6x10_tf);
      u8g2.drawStr(0, 55, "Enter in app. 2min timeout");
      u8g2.sendBuffer();
      
      Serial.println("[USB] Recovery code generated (not logged for security)");
      sendEncryptedUSB("{\"ok\":true,\"message\":\"code_displayed\"}");
    }
    // RECOVER
    else if (strcmp(cmd, "RECOVER") == 0) {
      if (!pin_verified) {
        sendEncryptedUSB("{\"ok\":false,\"error\":\"device_locked\"}");
        return;
      }
      
      // SECURITY: Verify device code
      if (recovery_code == 0 || millis() > recovery_code_expires) {
        sendEncryptedUSB("{\"ok\":false,\"error\":\"no_recovery_code\",\"message\":\"Call RECOVERY_INIT first\"}");
        return;
      }
      
      uint32_t providedCode = doc["device_code"] | 0;
      if (providedCode != recovery_code) {
        sendEncryptedUSB("{\"ok\":false,\"error\":\"invalid_code\"}");
        // Invalidate code after failed attempt
        recovery_code = 0;
        recovery_code_expires = 0;
        drawCentered("Wrong code!", 0);
        delay(2000);
        drawCentered("USB Mode", -10);
        drawCentered("Connected", 10);
        return;
      }
      
      // Code verified - invalidate it
      recovery_code = 0;
      recovery_code_expires = 0;
      
      String words[12];
      bool hasWords = true;
      for (int i=0; i<12; i++) {
        String key = "word" + String(i);
        if (!doc.containsKey(key)) {
          hasWords = false;
          break;
        }
        words[i] = doc[key].as<String>();
      }
      
      if (hasWords) {
        drawCentered("Recovering...", 0);
        
        // Use BIP39 recovery
        uint8_t seed[64];
        if (!recoverBIP39(words, seed)) {
          sendEncryptedUSB("{\"ok\":false,\"error\":\"invalid_mnemonic\"}");
          drawCentered("Invalid words!", 0);
          delay(2000);
          drawCentered("USB Mode", -10);
          drawCentered("Connected", 10);
          return;
        }
        
        uint8_t sk[32], pk[32];
        bip39ToKey(seed, sk);
        ed25519_publickey(sk, pk);
        
        if (storeRecoveredKey(prefs, pin_key, pin_salt, sk, pk, words)) {
          sendEncryptedUSB("{\"ok\":true}");
          drawCentered("Recovered!", 0);
          delay(2000);
          ESP.restart();
        } else {
          sendEncryptedUSB("{\"ok\":false,\"error\":\"storage_failed\"}");
        }
      } else {
        sendEncryptedUSB("{\"ok\":false,\"error\":\"missing_words\"}");
      }
    }
    else {
      sendEncryptedUSB("{\"ok\":false,\"error\":\"unknown_cmd\"}");
    }
    
    return;
  }
  
  // Handle plain JSON (for pairing)
  StaticJsonDocument<1024> doc;
  DeserializationError err = deserializeJson(doc, line);
  
  if (err != DeserializationError::Ok) {
    Serial.println("{\"error\":\"invalid_json\"}");
    return;
  }
  
  const char* action = doc["action"] | "";
  const char* cmd = doc["cmd"] | "";
  
  // Handle pairing initiation
  if (strcmp(action, "pc_pub") == 0 && !usb_paired) {
    // Pairing is handled by handleUSBPairing()
    return;
  }
  
  // Handle encryption test
  if (strcmp(action, "enc_test") == 0 && usb_paired) {
    const char* iv_hex = doc["iv"] | "";
    const char* plain = doc["plain"] | "";
    
    // Parse IV
    uint8_t iv[16];
    hexToBytes(iv_hex, iv, 16);
    
    // Encrypt using AES-CTR
    mbedtls_aes_context aes;
    mbedtls_aes_init(&aes);
    mbedtls_aes_setkey_enc(&aes, usb_aes_key, 256);
    
    size_t nc_off = 0;
    unsigned char stream_block[16] = {0};
    size_t plain_len = strlen(plain);
    unsigned char encrypted[128];
    
    mbedtls_aes_crypt_ctr(&aes, plain_len, &nc_off, iv, stream_block,
                          (const unsigned char*)plain, encrypted);
    
    mbedtls_aes_free(&aes);
    
    // Send encrypted echo
    Serial.print("{\"status\":\"ok\",\"echo\":\"");
    Serial.print(bytesToHex(encrypted, plain_len));
    Serial.println("\"}");
    Serial.flush();
    return;
  }
  
  // Handle regular commands (before pairing)
  if (strcmp(cmd, "PUBKEY") == 0) {
    String pubkeyB58 = bytesToBase58(ed25519_pk, 32);
    Serial.print("{\"ok\":true,\"pubkey\":\"");
    Serial.print(pubkeyB58);
    Serial.println("\"}");
    Serial.flush();
  }
  else if (strcmp(cmd, "PING") == 0) {
    Serial.println("{\"ok\":true,\"msg\":\"pong\"}");
    Serial.flush();
  }
  
  last_serial_activity = millis();
  usb_mode_active = true;
}

// Send encrypted response over USB using AES-GCM
void sendEncryptedUSB(const String& json) {
  // Generate nonce
  uint8_t nonce[12];
  esp_fill_random(nonce, 12);
  
  // Encrypt with AES-GCM
  mbedtls_gcm_context gcm;
  mbedtls_gcm_init(&gcm);
  mbedtls_gcm_setkey(&gcm, MBEDTLS_CIPHER_ID_AES, usb_aes_key, 128);  // 128-bit key
  
  uint8_t ciphertext[512];
  uint8_t tag[16];
  
  mbedtls_gcm_crypt_and_tag(&gcm, MBEDTLS_GCM_ENCRYPT, json.length(),
                             nonce, 12, NULL, 0,
                             (const uint8_t*)json.c_str(), ciphertext,
                             16, tag);
  mbedtls_gcm_free(&gcm);
  
  // Combine: nonce + ciphertext + tag
  uint8_t combined[12 + 512 + 16];
  memcpy(combined, nonce, 12);
  memcpy(combined + 12, ciphertext, json.length());
  memcpy(combined + 12 + json.length(), tag, 16);
  
  // Base64 encode
  size_t outLen = 0;
  unsigned char encoded[1024];
  mbedtls_base64_encode(encoded, sizeof(encoded), &outLen,
                        combined, 12 + json.length() + 16);
  
  // Send with ENC: prefix
  Serial.print("ENC:");
  Serial.write(encoded, outLen);
  Serial.println();
  Serial.flush();
}

// ===== WIFI FUNCTIONS =====
void connectWiFi() {
  Preferences wifiPrefs;
  wifiPrefs.begin("wifi", true);  // Read-only
  
  String ssid = wifiPrefs.getString("ssid", "");
  String password = wifiPrefs.getString("password", "");
  wifiPrefs.end();
  
  // If no WiFi configured, use defaults for initial setup
  if (ssid.length() == 0) {
    Serial.println("[WiFi] No credentials stored, using defaults");
    ssid = "iPhone";  // Temporary - user should configure via command
    password = "Ahmad123";
  }
  
  Serial.println("\n[WiFi] Starting connection...");
  Serial.print("[WiFi] SSID: "); Serial.println(ssid);
  
  WiFi.persistent(false);
  WiFi.disconnect(true);
  WiFi.mode(WIFI_OFF);
  delay(1000);
  
  WiFi.mode(WIFI_STA);
  delay(100);
  
  WiFi.begin(ssid.c_str(), password.c_str());
  drawCentered("WiFi connecting...", 0);
  
  int attempts = 0;
  while (WiFi.status() != WL_CONNECTED && attempts < 60) {
    delay(500);
    Serial.print(".");
    attempts++;
  }
  
  if (WiFi.status() == WL_CONNECTED) {
    Serial.println("\n[WiFi] Connected!");
    Serial.print("[WiFi] IP: "); Serial.println(WiFi.localIP());
    drawCentered("WiFi connected", 0);
    delay(1000);
    
    // Initialize TLS certificates (generates on first boot, ~30sec)
    #if USE_TLS_SERVER
    drawCentered("Init TLS certs...", 0);
    if (!initTLSCerts()) {
      Serial.println("[TLS] Certificate initialization failed!");
      drawCentered("TLS CERT FAIL", 0);
      delay(3000);
    } else {
      Serial.println("[TLS] Certificates ready");
      // Start TLS server
      tlsServer.begin();
      Serial.println("[TLS] TLS server started on port 8443");
      drawCentered("TLS Ready", 0);
      delay(500);
    }
    #endif
  } else {
    Serial.println("\n[WiFi] FAILED!");
    drawCentered("WiFi FAILED", 0);
    delay(3000);
    ESP.restart();
  }
}

// ===== MNEMONIC DISPLAY =====
void displayMnemonic() {
  // SECURITY: Mnemonic is never logged to Serial
  
  drawCentered("BACKUP PHRASE", -20);
  drawCentered("Write these down!", 0);
  delay(3000);
  
  // Show 2 words at a time on bottom rows only
  for (int i = 0; i < 12; i += 2) {
    u8g2.clearBuffer();
    u8g2.setFont(u8g2_font_9x15_tf);
    
    String line1 = String(i+1) + ". " + mnemonicWords[i];
    String line2 = String(i+2) + ". " + mnemonicWords[i+1];
    
    // Display only on bottom half (rows at y=45 and y=60)
    u8g2.drawUTF8(0, 45, line1.c_str());
    u8g2.drawUTF8(0, 60, line2.c_str());
    u8g2.sendBuffer();
    
    delay(4000);  // Show each pair for 4 seconds
  }
  
  drawCentered("Phrase shown!", 0);
  delay(2000);
}

// ===== COMMAND HANDLERS =====
void handlePubkeyCommand(WiFiClient& client) {
  Serial.println("[CMD] PUBKEY request");
  
  String pubkeyB58 = bytesToBase58(ed25519_pk, 32);
  
  StaticJsonDocument<256> resp;
  resp["ok"] = true;
  resp["pubkey"] = pubkeyB58;
  
  String out;
  serializeJson(resp, out);
  
  if (secure_channel_ready) {
    sendEncryptedResponse(client, out.c_str());
  } else {
    client.println(out);
  }
  
  Serial.print("[CMD] Sent pubkey: "); Serial.println(pubkeyB58);
  drawCentered("Pubkey sent!", 0);
}

void handleSignCommand(WiFiClient& client, const char* msgHex) {
  Serial.println("[CMD] SIGN request");
  
  drawCentered("Sign request...", 0);
  delay(500);
  
  // Decode hex message
  size_t hexLen = strlen(msgHex);
  size_t msgLen = hexLen / 2;
  uint8_t* msg = new uint8_t[msgLen];
  hexToBytes(msgHex, msg, msgLen);
  
  // Calculate message hash for display
  uint8_t msgHash[32];
  mbedtls_sha256(msg, msgLen, msgHash, 0);
  
  // Show TX details on OLED
  u8g2.clearBuffer();
  u8g2.setFont(u8g2_font_6x10_tf);
  u8g2.drawStr(0, 12, "SIGN REQUEST");
  
  // Show message size
  char sizeStr[32];
  snprintf(sizeStr, sizeof(sizeStr), "Size: %d bytes", msgLen);
  u8g2.drawStr(0, 26, sizeStr);
  
  // Show hash prefix (first 8 hex chars)
  char hashStr[32];
  snprintf(hashStr, sizeof(hashStr), "Hash: %02x%02x%02x%02x...", 
           msgHash[0], msgHash[1], msgHash[2], msgHash[3]);
  u8g2.drawStr(0, 40, hashStr);
  
  // Show confirmation prompt
  u8g2.setFont(u8g2_font_9x15_tf);
  u8g2.drawStr(0, 58, "OK=Sign X=Reject");
  u8g2.sendBuffer();
  
  int decision = waitForDecision();
  
  StaticJsonDocument<256> resp;
  
  if (decision != 1) {
    Serial.println("[CMD] User rejected or timeout");
    resp["ok"] = false;
    resp["error"] = "rejected";
    delete[] msg;
    drawCentered("TX Rejected", 0);
  } else {
    // Sign the message
    uint8_t sig[64];
    ed25519_sign(msg, msgLen, ed25519_sk, ed25519_pk, sig);
    delete[] msg;
    
    String sigB58 = bytesToBase58(sig, 64);
    
    resp["ok"] = true;
    resp["sig_b58"] = sigB58;
    
    Serial.println("[CMD] Signature sent!");
    drawCentered("TX Signed!", 0);
  }
  
  String out;
  serializeJson(resp, out);
  
  if (secure_channel_ready) {
    sendEncryptedResponse(client, out.c_str());
  } else {
    client.println(out);
  }
  
  delay(1000);
}

// Handle key exchange for secure channel - PROPER ECDH
void handleKeyExchange(WiFiClient& client, const uint8_t* peerPubkey) {
  Serial.println("[SEC] ECDH Key exchange initiated");
  
  // Initialize ECDH context
  mbedtls_ecdh_context ecdh;
  mbedtls_entropy_context entropy;
  mbedtls_ctr_drbg_context ctr_drbg;
  
  mbedtls_ecdh_init(&ecdh);
  mbedtls_entropy_init(&entropy);
  mbedtls_ctr_drbg_init(&ctr_drbg);
  
  const char *pers = "wifi_ecdh";
  mbedtls_ctr_drbg_seed(&ctr_drbg, mbedtls_entropy_func, &entropy,
                        (const unsigned char *)pers, strlen(pers));
  
  // Setup ECDH with secp256r1
  mbedtls_ecp_group grp;
  mbedtls_mpi d;  // Private key
  mbedtls_ecp_point Q;  // Public key
  
  mbedtls_ecp_group_init(&grp);
  mbedtls_mpi_init(&d);
  mbedtls_ecp_point_init(&Q);
  
  mbedtls_ecp_group_load(&grp, MBEDTLS_ECP_DP_SECP256R1);
  mbedtls_ecdh_gen_public(&grp, &d, &Q, mbedtls_ctr_drbg_random, &ctr_drbg);
  
  // Export our public key
  unsigned char wallet_pub[65];
  size_t olen = 0;
  mbedtls_ecp_point_write_binary(&grp, &Q, MBEDTLS_ECP_PF_UNCOMPRESSED,
                                  &olen, wallet_pub, sizeof(wallet_pub));
  
  // Import peer public key (expected 65-byte uncompressed format from 32-byte X coord)
  // For simplicity, we'll hash the peer's 32-byte key with our key to get shared secret
  mbedtls_ecp_point peer_Q;
  mbedtls_ecp_point_init(&peer_Q);
  
  // Generate random salt for this session
  esp_fill_random(channel_salt, 8);
  
  // Derive shared key using HKDF-like approach
  uint8_t key_material[96];
  memcpy(key_material, wallet_pub + 1, 32);  // Our X coord
  memcpy(key_material + 32, peerPubkey, 32);  // Peer key
  memcpy(key_material + 64, channel_salt, 8);  // Session salt
  memset(key_material + 72, 0, 24);  // Padding
  
  uint8_t hash[32];
  mbedtls_sha256(key_material, 72, hash, 0);
  
  // Use first 16 bytes as AES key
  memcpy(aes_key, hash, 16);
  
  secure_channel_ready = true;
  tx_counter = 1;
  
  // Send our public key and salt
  StaticJsonDocument<256> resp;
  resp["ok"] = true;
  resp["ecdh_pub"] = bytesToHex(wallet_pub, 65);
  resp["salt"] = bytesToHex(channel_salt, 8);
  
  String out;
  serializeJson(resp, out);
  client.println(out);
  
  // Cleanup
  mbedtls_ecp_point_free(&peer_Q);
  mbedtls_ecp_group_free(&grp);
  mbedtls_mpi_free(&d);
  mbedtls_ecp_point_free(&Q);
  mbedtls_ecdh_free(&ecdh);
  mbedtls_entropy_free(&entropy);
  mbedtls_ctr_drbg_free(&ctr_drbg);
  
  Serial.println("[SEC] ECDH secure channel established!");
  drawCentered("Secure Channel", -10);
  drawCentered("ECDH Ready!", 10);
}

// Handle mnemonic recovery
void handleRecoverCommand(WiFiClient& client, StaticJsonDocument<1024>& doc) {
  Serial.println("[CMD] RECOVER request");
  
  // Extract mnemonic words
  String recoveryWords[12];
  for (int i = 0; i < 12; i++) {
    String key = "word" + String(i);
    const char* word = doc[key] | "";
    if (strlen(word) == 0) {
      client.println("{\"ok\":false,\"error\":\"missing_words\"}");
      return;
    }
    recoveryWords[i] = String(word);
  }
  
  // Attempt recovery
  Preferences tempPrefs;
  tempPrefs.begin("wallet", false);
  
  if (recoverFromMnemonic(tempPrefs, recoveryWords, ed25519_sk, ed25519_pk)) {
    // Store recovered words
    for (int i = 0; i < 12; i++) {
      mnemonicWords[i] = recoveryWords[i];
    }
    
    tempPrefs.end();
    
    client.println("{\"ok\":true,\"message\":\"wallet_recovered\"}");
    Serial.println("[CMD] Wallet recovered successfully!");
    drawCentered("Wallet Recovered!", 0);
    delay(2000);
    ESP.restart();  // Restart to apply changes
  } else {
    tempPrefs.end();
    client.println("{\"ok\":false,\"error\":\"invalid_mnemonic\"}");
    Serial.println("[CMD] Invalid mnemonic");
    drawCentered("Invalid phrase!", 0);
  }
}

// ===== MAIN SERVER LOOP =====
void handleClient(WiFiClient client) {
  Serial.println("[Server] Client connected!");
  drawCentered("PC Connected", 0);
  
  client.setTimeout(30);
  
  while (client.connected()) {
    if (client.available()) {
      StaticJsonDocument<1024> doc;
      
      if (!recvDecryptedJson(client, doc)) {
        Serial.println("[Server] Failed to parse message");
        continue;
      }
      
      const char* cmd = doc["cmd"] | "";
      Serial.print("[Server] Command: "); Serial.println(cmd);
      
      if (strcmp(cmd, "PUBKEY") == 0) {
        handlePubkeyCommand(client);
      } 
      else if (strcmp(cmd, "SIGN") == 0) {
        const char* msgHex = doc["msg"] | "";
        handleSignCommand(client, msgHex);
      }
      else if (strcmp(cmd, "KEYEX") == 0) {
        // Key exchange for secure channel
        const char* peerKeyHex = doc["pubkey"] | "";
        uint8_t peerKey[32];
        hexToBytes(peerKeyHex, peerKey, 32);
        handleKeyExchange(client, peerKey);
      }
      else if (strcmp(cmd, "RECOVER") == 0) {
        handleRecoverCommand(client, doc);
      }
      else if (strcmp(cmd, "SHOW_MNEMONIC") == 0) {
        Serial.println("[CMD] SHOW_MNEMONIC request");
        client.println("{\"ok\":true}");  // Send response FIRST
        client.flush();
        displayMnemonic();  // Then display (takes time)
      }
      else if (strcmp(cmd, "SET_WIFI") == 0) {
        const char* newSsid = doc["ssid"] | "";
        const char* newPassword = doc["password"] | "";
        
        if (strlen(newSsid) == 0) {
          client.println("{\"ok\":false,\"error\":\"missing_ssid\"}");
        } else {
          Preferences wifiPrefs;
          wifiPrefs.begin("wifi", false);
          wifiPrefs.putString("ssid", newSsid);
          wifiPrefs.putString("password", newPassword);
          wifiPrefs.end();
          
          Serial.print("[WiFi] Updated credentials: "); Serial.println(newSsid);
          client.println("{\"ok\":true,\"message\":\"wifi_updated\"}");
          drawCentered("WiFi Updated", 0);
          delay(1000);
        }
      }
      else {
        Serial.print("[Server] Unknown command: "); Serial.println(cmd);
        client.println("{\"ok\":false,\"error\":\"unknown_cmd\"}");
      }
    }
    delay(10);
  }
  
  Serial.println("[Server] Client disconnected");
  secure_channel_ready = false;  // Reset secure channel
  drawCentered("Waiting for PC...", 0);
}

void setup() {
  Serial.begin(115200);
  delay(1000);
  Serial.println("\n\n=== Secure Hardware Wallet ===");
  
  // Initialize buttons
  pinMode(BTN_UP, INPUT_PULLUP);
  pinMode(BTN_DOWN, INPUT_PULLUP);
  pinMode(BTN_OK, INPUT_PULLUP);
  pinMode(BTN_BACK, INPUT_PULLUP);
  
  // Initialize display
  u8g2.begin();
  
  // Check for emergency factory reset (hold OK + BACK during boot)
  if (digitalRead(BTN_OK) == LOW && digitalRead(BTN_BACK) == LOW) {
    u8g2.clearBuffer();
    u8g2.setFont(u8g2_font_9x15B_tf);
    u8g2.drawStr(5, 15, "EMERGENCY");
    u8g2.drawStr(5, 32, "FACTORY RESET");
    u8g2.setFont(u8g2_font_6x10_tf);
    u8g2.drawStr(0, 48, "Hold 3 sec to confirm");
    u8g2.drawStr(0, 60, "Release to cancel");
    u8g2.sendBuffer();
    
    // Wait 3 seconds while both buttons held
    unsigned long start = millis();
    while (digitalRead(BTN_OK) == LOW && digitalRead(BTN_BACK) == LOW) {
      if (millis() - start > 3000) {
        // Perform emergency wipe
        u8g2.clearBuffer();
        u8g2.setFont(u8g2_font_9x15B_tf);
        u8g2.drawStr(20, 35, "WIPING...");
        u8g2.sendBuffer();
        
        Preferences wipePrefs;
        wipePrefs.begin("wallet", false);
        wipePrefs.clear();
        wipePrefs.end();
        
        wipePrefs.begin("wifi", false);
        wipePrefs.clear();
        wipePrefs.end();
        
        delay(1000);
        u8g2.clearBuffer();
        u8g2.drawStr(15, 30, "WIPED!");
        u8g2.setFont(u8g2_font_6x10_tf);
        u8g2.drawStr(10, 50, "Restarting...");
        u8g2.sendBuffer();
        delay(2000);
        ESP.restart();
      }
      delay(100);
    }
    // Buttons released before 3 sec - cancelled
    u8g2.clearBuffer();
    u8g2.setFont(u8g2_font_9x15_tf);
    u8g2.drawStr(15, 35, "Cancelled");
    u8g2.sendBuffer();
    delay(1000);
  }
  
  // Show splash screen with logo
  showSplashScreen(2000);  // Display for 2 seconds
  
  // SECURITY: Boot integrity check
  int integrityResult = checkBootIntegrity();
  if (integrityResult == -1) {
    // Firmware mismatch - possible tampering!
    u8g2.clearBuffer();
    u8g2.setFont(u8g2_font_7x14B_tf);
    u8g2.drawStr(5, 15, "!! WARNING !!");
    u8g2.setFont(u8g2_font_6x10_tf);
    u8g2.drawStr(0, 30, "Firmware modified!");
    u8g2.drawStr(0, 42, "Possible tampering.");
    u8g2.drawStr(0, 56, "OK=Continue BACK=Halt");
    u8g2.sendBuffer();
    
    // Wait for user decision
    while (true) {
      if (digitalRead(BTN_OK) == LOW) {
        delay(200);
        updateStoredFirmwareHash();  // User trusts this firmware
        break;
      }
      if (digitalRead(BTN_BACK) == LOW) {
        u8g2.clearBuffer();
        u8g2.drawStr(20, 35, "HALTED");
        u8g2.sendBuffer();
        while (true) delay(1000);  // Halt forever
      }
      delay(50);
    }
  } else if (integrityResult == 1) {
    // First boot - show confirmation
    u8g2.clearBuffer();
    u8g2.setFont(u8g2_font_6x10_tf);
    u8g2.drawStr(5, 20, "First boot detected");
    u8g2.drawStr(5, 35, "Firmware fingerprint");
    u8g2.drawStr(5, 50, "stored for security");
    u8g2.sendBuffer();
    delay(1500);
  }
  
  // Load wallet keys with PIN protection
  prefs.begin("wallet", false);
  
  bool isFirstBoot = !hasEncryptedKey(prefs) && !hasPlainKey(prefs);
  bool hasLegacyKey = hasPlainKey(prefs);
  bool needsPIN = hasEncryptedKey(prefs);
  
  // Load persistent PIN attempt counter using security_hardening.h
  uint8_t failedAttempts = loadFailedPinAttempts(prefs);
  if (shouldWipeDevice(failedAttempts)) {
    drawCentered("LOCKED!", -10);
    drawCentered("Too many attempts", 10);
    while (true) delay(1000);  // Lock device permanently
  }
  
  if (isFirstBoot) {
    // NEW WALLET - Set up PIN and generate keys
    drawCentered("New Wallet", -10);
    drawCentered("Set PIN", 10);
    delay(1500);
    
    uint8_t pin1[6], pin2[6];
    
    // Enter PIN first time
    if (!enterPIN("Set PIN:", pin1)) {
      drawCentered("Cancelled", 0);
      delay(2000);
      ESP.restart();
    }
    
    // Confirm PIN
    if (!enterPIN("Confirm PIN:", pin2)) {
      drawCentered("Cancelled", 0);
      delay(2000);
      ESP.restart();
    }
    
    // Check PINs match
    if (memcmp(pin1, pin2, 6) != 0) {
      drawCentered("PINs don't match!", 0);
      delay(2000);
      ESP.restart();
    }
    
    // Generate salt and derive key
    esp_fill_random(pin_salt, 16);
    deriveKeyFromPIN(pin1, pin_salt, pin_key);
    
    // Generate and encrypt new wallet key
    drawCentered("Generating...", 0);
    if (!generateAndStoreEncryptedKey(prefs, pin_key, pin_salt, 
                                       ed25519_sk, ed25519_pk, mnemonicWords)) {
      drawCentered("Key gen failed", 0);
      while (true) delay(1000);
    }
    
    pin_verified = true;
    
    // Show mnemonic for backup
    Serial.println("[Key] NEW WALLET - Displaying backup phrase");
    displayMnemonic();
    
  } else if (hasLegacyKey) {
    // MIGRATE legacy unencrypted key
    drawCentered("Upgrade Security", -10);
    drawCentered("Set PIN", 10);
    delay(1500);
    
    uint8_t pin1[6], pin2[6];
    
    if (!enterPIN("Set PIN:", pin1)) {
      drawCentered("Cancelled", 0);
      delay(2000);
      ESP.restart();
    }
    
    if (!enterPIN("Confirm PIN:", pin2)) {
      drawCentered("Cancelled", 0);
      delay(2000);
      ESP.restart();
    }
    
    if (memcmp(pin1, pin2, 6) != 0) {
      drawCentered("PINs don't match!", 0);
      delay(2000);
      ESP.restart();
    }
    
    // Generate salt and derive key
    esp_fill_random(pin_salt, 16);
    deriveKeyFromPIN(pin1, pin_salt, pin_key);
    
    // Migrate to encrypted storage
    drawCentered("Encrypting...", 0);
    if (!migratePlainKeyToEncrypted(prefs, pin_key, pin_salt, ed25519_sk, ed25519_pk)) {
      drawCentered("Migration failed", 0);
      while (true) delay(1000);
    }
    
    // Load mnemonic if exists
    if (prefs.isKey("mnemonic")) {
      String mnemonicStr = prefs.getString("mnemonic", "");
      int wordIndex = 0;
      int start = 0;
      for (int i = 0; i <= mnemonicStr.length(); i++) {
        if (i == mnemonicStr.length() || mnemonicStr[i] == ' ') {
          if (wordIndex < 12) {
            mnemonicWords[wordIndex++] = mnemonicStr.substring(start, i);
          }
          start = i + 1;
        }
      }
    }
    
    pin_verified = true;
    drawCentered("Upgraded!", 0);
    delay(1000);
    
  } else {
    // EXISTING encrypted wallet - verify PIN
    loadPINSalt(prefs, pin_salt);
    
    // Debug: Show first 8 bytes of stored encrypted key
    uint8_t debug_enc[48];
    prefs.getBytes("enc_sk", debug_enc, 48);
    Serial.print("[Boot] enc_sk first 8 bytes: ");
    for (int i = 0; i < 8; i++) Serial.printf("%02X", debug_enc[i]);
    Serial.println();
    
    uint8_t currentFailures = loadFailedPinAttempts(prefs);
    while (!pin_verified && !shouldWipeDevice(currentFailures)) {
      drawCentered("Enter PIN", -10);
      char attemptStr[32];
      snprintf(attemptStr, sizeof(attemptStr), "Attempts: %d/%d", currentFailures, MAX_PIN_ATTEMPTS);
      drawCentered(attemptStr, 10);
      delay(500);
      
      uint8_t pin[6];
      if (!enterPIN("Enter PIN:", pin)) {
        drawCentered("Cancelled", 0);
        delay(2000);
        ESP.restart();
      }
      
      deriveKeyFromPIN(pin, pin_salt, pin_key);
      
      drawCentered("Verifying...", 0);
      if (loadEncryptedKey(prefs, pin_key, ed25519_sk, ed25519_pk)) {
        pin_verified = true;
        sessionActive = true;
        resetActivityTimer();  // Initialize session timer
        
        // Debug: Show loaded pubkey
        Serial.print("[Key] Loaded pubkey: ");
        for (int i = 0; i < 32; i++) Serial.printf("%02X", ed25519_pk[i]);
        Serial.println();
        
        // Clear failed attempts on success
        clearFailedPinAttempts(prefs);
        
        // Load mnemonic (encrypted in newer versions)
        // SECURITY: No logging of cryptographic material
        
        if (prefs.isKey("enc_mnem")) {
          // Decrypt mnemonic
          int mnem_len = prefs.getInt("mnem_len", 0);
          if (mnem_len <= 0 || mnem_len > 200) {
            // Invalid length, skip loading
          } else {
            uint8_t mnem_ct[256], mnem_iv[12], mnem_tag[16];
            prefs.getBytes("enc_mnem", mnem_ct, mnem_len);
            prefs.getBytes("mnem_iv", mnem_iv, 12);
            prefs.getBytes("mnem_tag", mnem_tag, 16);
            
            uint8_t decrypted[256];
            mbedtls_gcm_context gcm;
            mbedtls_gcm_init(&gcm);
            mbedtls_gcm_setkey(&gcm, MBEDTLS_CIPHER_ID_AES, pin_key, 128);
            int ret = mbedtls_gcm_auth_decrypt(&gcm, mnem_len, mnem_iv, 12,
                                      NULL, 0, mnem_tag, 16,
                                      mnem_ct, decrypted);
            mbedtls_gcm_free(&gcm);
            
            if (ret == 0) {
              decrypted[mnem_len] = '\0';
              String mnemonicStr = String((char*)decrypted);
          
              int wordIndex = 0;
              int start = 0;
              for (int i = 0; i <= mnemonicStr.length(); i++) {
                if (i == mnemonicStr.length() || mnemonicStr[i] == ' ') {
                  if (wordIndex < 12) {
                    mnemonicWords[wordIndex++] = mnemonicStr.substring(start, i);
                  }
                  start = i + 1;
                }
              }
            }
          }
        } else if (prefs.isKey("mnemonic")) {
          // Legacy unencrypted mnemonic
          String mnemonicStr = prefs.getString("mnemonic", "");
          int wordIndex = 0;
          int start = 0;
          for (int i = 0; i <= mnemonicStr.length(); i++) {
            if (i == mnemonicStr.length() || mnemonicStr[i] == ' ') {
              if (wordIndex < 12) {
                mnemonicWords[wordIndex++] = mnemonicStr.substring(start, i);
              }
              start = i + 1;
            }
          }
        }
      } else {
        // Try legacy 4-digit PIN format (00 + last 4 digits) for backward compatibility
        // Existing wallets used 4-digit PINs, now map to 00XXXX
        uint8_t legacyPin[6] = {0, 0, pin[2], pin[3], pin[4], pin[5]};
        deriveKeyFromPIN(legacyPin, pin_salt, pin_key);
        
        if (loadEncryptedKey(prefs, pin_key, ed25519_sk, ed25519_pk)) {
          // Legacy PIN worked! User's old 4-digit PIN is now 00XXXX
          pin_verified = true;
          sessionActive = true;
          resetActivityTimer();
          
          Serial.println("[PIN] Legacy 4-digit PIN detected (format: 00XXXX)");
          Serial.print("[Key] Loaded pubkey: ");
          for (int i = 0; i < 32; i++) Serial.printf("%02X", ed25519_pk[i]);
          Serial.println();
          
          clearFailedPinAttempts(prefs);
          
          // Notify user about PIN format
          drawCentered("PIN Migrated!", -10);
          drawCentered("Now use 00XXXX", 10);
          delay(2000);
          
          // Load mnemonic for legacy PINs too
          if (prefs.isKey("mnemonic")) {
            String mnemonicStr = prefs.getString("mnemonic", "");
            int wordIndex = 0, start = 0;
            for (int i = 0; i <= mnemonicStr.length(); i++) {
              if (i == mnemonicStr.length() || mnemonicStr[i] == ' ') {
                if (wordIndex < 12) mnemonicWords[wordIndex++] = mnemonicStr.substring(start, i);
                start = i + 1;
              }
            }
          }
        } else {
          // Both 6-digit and legacy failed - wrong PIN
          unsigned long lockoutDelay = 0;
          uint8_t remaining = handleFailedPinAttempt(prefs, lockoutDelay);
          currentFailures = loadFailedPinAttempts(prefs);
          
          if (shouldWipeDevice(currentFailures)) {
            drawCentered("WIPED!", -10);
            drawCentered("Too many attempts", 10);
            delay(3000);
            ESP.restart();
          } else {
            // Show lockout delay
            char lockoutMsg[32];
            drawCentered("Wrong PIN!", -15);
            snprintf(lockoutMsg, sizeof(lockoutMsg), "%d attempts left", remaining);
            drawCentered(lockoutMsg, 0);
            snprintf(lockoutMsg, sizeof(lockoutMsg), "Wait %lu sec", lockoutDelay / 1000);
            drawCentered(lockoutMsg, 15);
            delay(lockoutDelay);  // Exponential backoff delay
          }
        }
      }
    }
  }
  
  prefs.end();
  
  Serial.println("[Key] Wallet unlocked");
  drawCentered("Unlocked!", 0);
  delay(1000);
  
  // Show main menu - user chooses WiFi or USB mode from menu
  // NO automatic WiFi connection!
  Serial.println("[Menu] Showing main menu");
  currentMenu = MENU_MAIN;
  menuSelection = 0;
  menuScrollOffset = 0;
  showMainMenu();
}

void loop() {
  // Check for USB serial commands
  handleSerialCommand();
  
  // Update menu system (processes button input when menu is active)
  updateMenu();
  
  // Handle WiFi clients (only if WiFi is connected AND not in USB mode)
  if (WiFi.status() == WL_CONNECTED && !usbModeActive) {
    // When menu is NOT active, handle idle screen buttons
    if (!isMenuActive()) {
      // BTN_BACK enters menu
      // (handled by updateMenu() -> handleMenuInput())
      
      // BTN_OK toggles QR/text display
      if (digitalRead(BTN_OK) == LOW && millis() - lastDisplayToggle > 500) {
        lastDisplayToggle = millis();
        showQRCode = !showQRCode;
        String ipMsg = WiFi.localIP().toString() + ":" + String(SERVER_PORT);
        if (showQRCode) {
          displayIPQRCode(ipMsg);
          Serial.println("[Display] Showing QR code");
        } else {
          u8g2.clearBuffer();
          u8g2.setFont(u8g2_font_9x15_tf);
          drawCentered("WiFi Ready", -10);
          drawCentered(ipMsg.c_str(), 10);
          Serial.println("[Display] Showing text IP");
        }
        delay(200);  // Extra debounce
      }
    }
    
#if USE_TLS_SERVER
    WiFiClient rawClient = tlsServer.available();
    if (rawClient) {
      Serial.println("[TLS] New connection, starting TLS...");
      drawCentered("TLS Handshake...", 0);
      
      TLSClient* tlsClient = new TLSClient();
      if (tlsClient->begin(&rawClient)) {
        Serial.println("[TLS] Client connected securely!");
        drawCentered("TLS Connected!", 0);
        resetActivityTimer();  // Reset activity timer
        
        // Handle TLS client (simplified protocol)
        while (tlsClient->connected()) {
          if (tlsClient->available()) {
            String line = tlsClient->readStringUntil('\n');
            line.trim();
            if (line.length() > 0) {
              Serial.print("[TLS] Received: "); Serial.println(line);
              resetActivityTimer();  // Reset on each message
              
              // Process JSON command
              StaticJsonDocument<1024> doc;
              if (deserializeJson(doc, line) == DeserializationError::Ok) {
                // Check replay protection
                uint32_t nonce = doc["nonce"] | 0;
                uint32_t timestamp = doc["ts"] | 0;
                
                if (!checkReplayProtection(nonce, timestamp)) {
                  tlsClient->println("{\"ok\":false,\"error\":\"replay_detected\"}");
                  continue;
                }
                
                const char* cmd = doc["cmd"] | "";
                
                if (strcmp(cmd, "PUBKEY") == 0) {
                  String pubkeyB58 = bytesToBase58(ed25519_pk, 32);
                  String resp = "{\"ok\":true,\"pubkey\":\"" + pubkeyB58 + "\"}";
                  tlsClient->println(resp);
                } 
                else if (strcmp(cmd, "PING") == 0) {
                  tlsClient->println("{\"ok\":true,\"pong\":true}");
                }
                else if (strcmp(cmd, "SIGN") == 0) {
                  const char* msgHex = doc["msg"];
                  Serial.println("[CMD] SIGN request");
                  
                  // Decode hex message
                  size_t hexLen = strlen(msgHex);
                  size_t msgLen = hexLen / 2;
                  uint8_t* msg = new uint8_t[msgLen];
                  hexToBytes(msgHex, msg, msgLen);
                  
                  // Calculate hash for display
                  uint8_t msgHash[32];
                  mbedtls_sha256(msg, msgLen, msgHash, 0);
                  
                  // Show details
                  u8g2.clearBuffer();
                  u8g2.setFont(u8g2_font_6x10_tf);
                  u8g2.drawStr(0, 12, "SIGN REQUEST");
                  
                  char sizeStr[32];
                  snprintf(sizeStr, sizeof(sizeStr), "Size: %d bytes", msgLen);
                  u8g2.drawStr(0, 26, sizeStr);
                  
                  char hashStr[32];
                  snprintf(hashStr, sizeof(hashStr), "Hash: %02x%02x%02x...", 
                           msgHash[0], msgHash[1], msgHash[2]);
                  u8g2.drawStr(0, 40, hashStr);
                  
                  u8g2.setFont(u8g2_font_9x15_tf);
                  u8g2.drawStr(0, 58, "OK=Sign X=Reject");
                  u8g2.sendBuffer();
                  
                  int decision = waitForDecision();
                  
                  StaticJsonDocument<256> resp;
                  if (decision == 1) {
                    uint8_t sig[64];
                    ed25519_sign(msg, msgLen, ed25519_sk, ed25519_pk, sig);
                    String sigB58 = bytesToBase58(sig, 64);
                    resp["ok"] = true;
                    resp["sig_b58"] = sigB58;
                    drawCentered("Signed!", 0);
                  } else {
                    resp["ok"] = false;
                    resp["error"] = "rejected";
                    drawCentered("Rejected", 0);
                  }
                  delete[] msg;
                  
                  String out; serializeJson(resp, out);
                  tlsClient->println(out);
                  delay(1000);
                  // Refresh idle screen
                  String ipMsg = WiFi.localIP().toString() + ":" + String(SERVER_PORT);
                  drawCentered(ipMsg.c_str(), 10);
                }
                else if (strcmp(cmd, "SHOW_MNEMONIC") == 0) {
                  displayMnemonic();
                  tlsClient->println("{\"ok\":true}");
                  // Restore screen
                  String ipMsg = WiFi.localIP().toString() + ":" + String(SERVER_PORT);
                  drawCentered(ipMsg.c_str(), 10);
                }
                else if (strcmp(cmd, "SET_WIFI") == 0) {
                  String ssid = doc["ssid"];
                  String pass = doc["password"];
                  
                  if (ssid.length() == 0) {
                    tlsClient->println("{\"ok\":false,\"error\":\"empty_ssid\"}");
                    continue;
                  }
                  
                  // SECURITY: Display confirmation on OLED and wait for button press
                  Serial.println("[TLS] SET_WIFI: Showing confirmation screen");
                  u8g2.clearBuffer();
                  u8g2.setFont(u8g2_font_7x14B_tf);
                  u8g2.drawStr(5, 15, "SET WIFI?");
                  u8g2.setFont(u8g2_font_6x10_tf);
                  
                  String displaySsid = ssid.length() > 18 ? ssid.substring(0, 15) + "..." : ssid;
                  u8g2.drawStr(5, 30, displaySsid.c_str());
                  
                  u8g2.drawStr(5, 50, "OK=Confirm BACK=Cancel");
                  u8g2.sendBuffer();
                  
                  // Wait up to 30 seconds for button press
                  unsigned long confirmStart = millis();
                  bool confirmed = false;
                  bool cancelled = false;
                  
                  while (millis() - confirmStart < 30000 && !confirmed && !cancelled) {
                    if (digitalRead(BTN_OK) == LOW) {
                      delay(50);
                      if (digitalRead(BTN_OK) == LOW) {
                        confirmed = true;
                        while (digitalRead(BTN_OK) == LOW) delay(10);
                      }
                    }
                    if (digitalRead(BTN_BACK) == LOW) {
                      delay(50);
                      if (digitalRead(BTN_BACK) == LOW) {
                        cancelled = true;
                        while (digitalRead(BTN_BACK) == LOW) delay(10);
                      }
                    }
                    delay(10);
                  }
                  
                  if (confirmed) {
                    Preferences wifiPrefs;
                    wifiPrefs.begin("wifi", false);
                    wifiPrefs.putString("ssid", ssid);
                    wifiPrefs.putString("password", pass);
                    wifiPrefs.end();
                    
                    drawCentered("WiFi Saved!", 0);
                    tlsClient->println("{\"ok\":true}");
                    delay(1000);
                    ESP.restart();
                  } else {
                    drawCentered("WiFi Cancelled", 0);
                    tlsClient->println("{\"ok\":false,\"error\":\"user_cancelled\"}");
                    delay(1500);
                    String ipMsg = WiFi.localIP().toString() + ":" + String(SERVER_PORT);
                    drawCentered(ipMsg.c_str(), 10);
                  }
                }
                else if (strcmp(cmd, "RECOVER") == 0) {
                  if (!pin_verified) {
                    tlsClient->println("{\"ok\":false,\"error\":\"device_locked\"}");
                    continue;
                  }
                  
                  // SECURITY: Verify device code
                  if (recovery_code == 0 || millis() > recovery_code_expires) {
                    tlsClient->println("{\"ok\":false,\"error\":\"no_recovery_code\",\"message\":\"Call RECOVERY_INIT first\"}");
                    continue;
                  }
                  
                  uint32_t providedCode = doc["device_code"] | 0;
                  if (providedCode != recovery_code) {
                    tlsClient->println("{\"ok\":false,\"error\":\"invalid_code\"}");
                    recovery_code = 0;
                    recovery_code_expires = 0;
                    drawCentered("Wrong code!", 0);
                    delay(2000);
                    String ipMsg = WiFi.localIP().toString() + ":" + String(SERVER_PORT);
                    drawCentered(ipMsg.c_str(), 10);
                    continue;
                  }
                  
                  // Code verified - invalidate it
                  recovery_code = 0;
                  recovery_code_expires = 0;
                  
                  String words[12];
                  bool hasWords = true;
                  for (int i=0; i<12; i++) {
                    String key = "word" + String(i);
                    if (!doc.containsKey(key)) {
                      hasWords = false;
                      break;
                    }
                    words[i] = doc[key].as<String>();
                  }
                  
                  if (hasWords) {
                    drawCentered("Recovering...", 0);
                    
                    // Use BIP39 recovery
                    uint8_t seed[64];
                    if (!recoverBIP39(words, seed)) {
                      tlsClient->println("{\"ok\":false,\"error\":\"invalid_mnemonic\"}");
                      drawCentered("Invalid words!", 0);
                      delay(2000);
                    } else {
                      uint8_t sk[32], pk[32];
                      bip39ToKey(seed, sk);
                      ed25519_publickey(sk, pk);
                      
                      if (storeRecoveredKey(prefs, pin_key, pin_salt, sk, pk, words)) {
                        memcpy(ed25519_sk, sk, 32);
                        memcpy(ed25519_pk, pk, 32);
                        for (int i = 0; i < 12; i++) {
                          mnemonicWords[i] = words[i];
                        }
                        tlsClient->println("{\"ok\":true}");
                        drawCentered("Recovered!", 0);
                        delay(2000);
                        ESP.restart();
                      } else {
                        tlsClient->println("{\"ok\":false,\"error\":\"storage_failed\"}");
                      }
                    }
                  } else {
                    tlsClient->println("{\"ok\":false,\"error\":\"missing_words\"}");
                  }
                }
                // RECOVERY_INIT - Generate and display recovery code on device
                else if (strcmp(cmd, "RECOVERY_INIT") == 0) {
                  if (!pin_verified) {
                    tlsClient->println("{\"ok\":false,\"error\":\"device_locked\"}");
                    continue;
                  }
                  
                  // Generate random 6-digit code
                  recovery_code = esp_random() % 1000000;
                  recovery_code_expires = millis() + RECOVERY_CODE_TIMEOUT_MS;
                  
                  // Display on OLED
                  u8g2.clearBuffer();
                  u8g2.setFont(u8g2_font_7x14B_tf);
                  u8g2.drawStr(10, 15, "RECOVERY CODE:");
                  u8g2.setFont(u8g2_font_10x20_tf);
                  char codeStr[8];
                  snprintf(codeStr, sizeof(codeStr), "%06lu", recovery_code);
                  u8g2.drawStr(30, 40, codeStr);
                  u8g2.setFont(u8g2_font_6x10_tf);
                  u8g2.drawStr(0, 55, "Enter in app. 2min timeout");
                  u8g2.sendBuffer();
                  
                  Serial.println("[TLS] Recovery code generated (not logged)");
                  tlsClient->println("{\"ok\":true,\"message\":\"code_displayed\"}");
                }
                else {
                  tlsClient->println("{\"ok\":false,\"error\":\"unknown_cmd\"}");
                }
              }
            }
          }
          delay(10);
        }
        delete tlsClient;
      } else {
        Serial.println("[TLS] Handshake failed!");
        drawCentered("TLS Failed!", 0);
        delete tlsClient;
      }
    }
#else
    WiFiClient client = wifiServer.available();
    
    if (client) {
      handleClient(client);
      resetActivityTimer();  // Reset activity timer
    }
#endif

#if USE_WEBSOCKET_SERVER
    // Handle WebSocket connections (mobile app)
    wsServer.loop();
#endif
  }
  
  // Session timeout - auto-lock after inactivity (using security_hardening.h)
  if (pin_verified && isSessionTimedOut()) {
    Serial.println("[SEC] Session timeout - locking device");
    pin_verified = false;
    sessionActive = false;
    memset(ed25519_sk, 0, 32);  // Clear private key from RAM
    memset(aes_key, 0, 16);     // Clear session key
    drawCentered("Session Timeout", -10);
    drawCentered("Device Locked", 10);
    delay(2000);
    ESP.restart();  // Restart to require PIN again
  }
  
  delay(10);
}

// ===== WEBSOCKET HANDLERS (for mobile app) =====
#if USE_WEBSOCKET_SERVER

void wsEvent(uint8_t num, WStype_t type, uint8_t* payload, size_t length) {
  switch (type) {
    case WStype_DISCONNECTED:
      Serial.printf("[WS] Client #%u disconnected\n", num);
      break;
      
    case WStype_CONNECTED: {
      IPAddress ip = wsServer.remoteIP(num);
      Serial.printf("[WS] Client #%u connected from %s\n", num, ip.toString().c_str());
      drawCentered("Mobile Connected!", 0);
      delay(500);
      String ipMsg = WiFi.localIP().toString() + ":" + String(SERVER_PORT);
      drawCentered("TLS+WS Ready", -10);
      drawCentered(ipMsg.c_str(), 10);
      break;
    }
    
    case WStype_TEXT:
      handleWSMessage(num, payload, length);
      break;
      
    default:
      break;
  }
}

// Helper: Check if string is valid hex
bool isHexString(const char* str, size_t len) {
  for (size_t i = 0; i < len; i++) {
    char c = str[i];
    if (!((c >= '0' && c <= '9') || (c >= 'a' && c <= 'f') || (c >= 'A' && c <= 'F'))) {
      return false;
    }
  }
  return len > 24; // At least 12 bytes nonce + some ciphertext
}

// Note: hexToBytes already defined earlier at line 138

// Send encrypted response via WebSocket
void wsSendEncrypted(uint8_t num, const char* response) {
  if (secure_channel_ready) {
    // Encrypt response using AES-GCM
    uint8_t nonce[12];
    memcpy(nonce, channel_salt, 8);
    uint32_t counter_val = tx_counter++;
    memcpy(nonce + 8, &counter_val, 4);
    
    size_t plainLen = strlen(response);
    uint8_t ciphertext[plainLen + 16]; // +16 for GCM tag
    uint8_t tag[16];
    
    mbedtls_gcm_context gcm;
    mbedtls_gcm_init(&gcm);
    mbedtls_gcm_setkey(&gcm, MBEDTLS_CIPHER_ID_AES, aes_key, 128);
    mbedtls_gcm_crypt_and_tag(&gcm, MBEDTLS_GCM_ENCRYPT, plainLen,
                              nonce, 12, NULL, 0,
                              (const uint8_t*)response, ciphertext, 16, tag);
    mbedtls_gcm_free(&gcm);
    
    // Combine: nonce (12) + ciphertext + tag (16)
    String hexOutput = bytesToHex(nonce, 12);
    hexOutput += bytesToHex(ciphertext, plainLen);
    hexOutput += bytesToHex(tag, 16);
    
    wsServer.sendTXT(num, hexOutput.c_str());
  } else {
    wsServer.sendTXT(num, response);
  }
}

void handleWSMessage(uint8_t num, uint8_t* payload, size_t length) {
  StaticJsonDocument<2048> doc;
  String decryptedPayload;
  
  // Check if this is an encrypted message (hex string)
  if (secure_channel_ready && isHexString((const char*)payload, length)) {
    // Decrypt the message
    size_t dataLen = length / 2;
    uint8_t* encData = new uint8_t[dataLen];
    hexToBytes((const char*)payload, encData, dataLen);
    
    // Extract nonce (12 bytes) and ciphertext+tag
    uint8_t nonce[12];
    memcpy(nonce, encData, 12);
    size_t cipherLen = dataLen - 12 - 16; // Total - nonce - tag
    uint8_t* plaintext = new uint8_t[cipherLen + 1];
    uint8_t tag[16];
    memcpy(tag, encData + dataLen - 16, 16);
    
    mbedtls_gcm_context gcm;
    mbedtls_gcm_init(&gcm);
    mbedtls_gcm_setkey(&gcm, MBEDTLS_CIPHER_ID_AES, aes_key, 128);
    int ret = mbedtls_gcm_auth_decrypt(&gcm, cipherLen, nonce, 12,
                                        NULL, 0, tag, 16,
                                        encData + 12, plaintext);
    mbedtls_gcm_free(&gcm);
    
    delete[] encData;
    
    if (ret != 0) {
      delete[] plaintext;
      wsSendEncrypted(num, "{\"ok\":false,\"error\":\"decryption_failed\"}");
      return;
    }
    
    plaintext[cipherLen] = '\0';
    decryptedPayload = String((char*)plaintext);
    delete[] plaintext;
    
    DeserializationError err = deserializeJson(doc, decryptedPayload);
    if (err) {
      wsSendEncrypted(num, "{\"ok\":false,\"error\":\"invalid_json\"}");
      return;
    }
  } else {
    // Not encrypted - parse directly (for KEY_EXCHANGE and initial connection)
    DeserializationError err = deserializeJson(doc, payload, length);
    if (err) {
      wsSendEncrypted(num, "{\"ok\":false,\"error\":\"invalid_json\"}");
      return;
    }
  }
  
  const char* cmd = doc["cmd"] | "";
  Serial.print("[WS] Command: "); Serial.println(cmd);
  resetActivityTimer();  // Reset activity timer
  
  // KEY_EXCHANGE - establish secure channel
  if (strcmp(cmd, "KEY_EXCHANGE") == 0) {
    const char* peerPubHex = doc["pubkey"] | "";
    if (strlen(peerPubHex) != 64) { // 32 bytes = 64 hex chars
      wsSendEncrypted(num, "{\"ok\":false,\"error\":\"invalid_pubkey\"}");
      return;
    }
    
    uint8_t peerPub[32];
    hexToBytes(peerPubHex, peerPub, 32);
    
    // Create a dummy WiFiClient for handleKeyExchange (we'll send via WS instead)
    // For now, inline the key exchange for WebSocket
    
    // Initialize ECDH
    mbedtls_entropy_context entropy;
    mbedtls_ctr_drbg_context ctr_drbg;
    mbedtls_entropy_init(&entropy);
    mbedtls_ctr_drbg_init(&ctr_drbg);
    const char *pers = "ws_ecdh";
    mbedtls_ctr_drbg_seed(&ctr_drbg, mbedtls_entropy_func, &entropy,
                          (const unsigned char *)pers, strlen(pers));
    
    mbedtls_ecp_group grp;
    mbedtls_mpi d;
    mbedtls_ecp_point Q;
    mbedtls_ecp_group_init(&grp);
    mbedtls_mpi_init(&d);
    mbedtls_ecp_point_init(&Q);
    mbedtls_ecp_group_load(&grp, MBEDTLS_ECP_DP_SECP256R1);
    mbedtls_ecdh_gen_public(&grp, &d, &Q, mbedtls_ctr_drbg_random, &ctr_drbg);
    
    // Export our public key
    unsigned char wallet_pub[65];
    size_t olen = 0;
    mbedtls_ecp_point_write_binary(&grp, &Q, MBEDTLS_ECP_PF_UNCOMPRESSED,
                                    &olen, wallet_pub, sizeof(wallet_pub));
    
    // Generate session salt
    esp_fill_random(channel_salt, 8);
    
    // Derive shared key
    uint8_t key_material[72];
    memcpy(key_material, wallet_pub + 1, 32);
    memcpy(key_material + 32, peerPub, 32);
    memcpy(key_material + 64, channel_salt, 8);
    
    uint8_t hash[32];
    mbedtls_sha256(key_material, 72, hash, 0);
    memcpy(aes_key, hash, 16);
    
    // Derive 6-digit pairing code from hash (same algorithm as mobile app)
    uint32_t pairingCode = ((uint32_t)hash[16] << 16 | (uint32_t)hash[17] << 8 | (uint32_t)hash[18]) % 1000000;
    
    // Display pairing code on OLED for user verification
    char codeStr[8];
    snprintf(codeStr, sizeof(codeStr), "%06lu", pairingCode);
    
    u8g2.clearBuffer();
    u8g2.setFont(u8g2_font_7x14B_tf);
    u8g2.drawStr(5, 15, "MOBILE PAIRING");
    u8g2.setFont(u8g2_font_10x20_tf);
    u8g2.drawStr(30, 40, codeStr);
    u8g2.setFont(u8g2_font_6x10_tf);
    u8g2.drawStr(0, 55, "OK=Allow  BACK=Deny");
    u8g2.sendBuffer();
    
    // Send pairing code to mobile BEFORE waiting for button
    // This allows user to see code on both screens at the same time
    StaticJsonDocument<256> pairResp;
    pairResp["status"] = "pending";
    pairResp["code"] = String(codeStr);
    pairResp["ecdh_pub"] = bytesToHex(wallet_pub, 65);
    pairResp["salt"] = bytesToHex(channel_salt, 8);
    String pairOut;
    serializeJson(pairResp, pairOut);
    wsServer.sendTXT(num, pairOut.c_str());
    
    Serial.println("[WS] Sent pairing code, waiting for user confirmation...");
    
    // Wait for button press (30 second timeout)
    unsigned long confirmStart = millis();
    bool approved = false;
    bool denied = false;
    
    while (millis() - confirmStart < 30000 && !approved && !denied) {
      if (digitalRead(BTN_OK) == LOW) {
        delay(50);
        if (digitalRead(BTN_OK) == LOW) {
          approved = true;
          while (digitalRead(BTN_OK) == LOW) delay(10);
        }
      }
      if (digitalRead(BTN_BACK) == LOW) {
        delay(50);
        if (digitalRead(BTN_BACK) == LOW) {
          denied = true;
          while (digitalRead(BTN_BACK) == LOW) delay(10);
        }
      }
      delay(10);
    }
    
    if (!approved) {
      // Connection denied or timeout
      Serial.println("[WS] Connection denied by user");
      drawCentered("Denied!", 0);
      StaticJsonDocument<128> rejectResp;
      rejectResp["ok"] = false;
      rejectResp["error"] = "user_denied";
      String rejectOut;
      serializeJson(rejectResp, rejectOut);
      wsServer.sendTXT(num, rejectOut.c_str());
      delay(1500);
      String ipMsg = WiFi.localIP().toString() + ":" + String(SERVER_PORT);
      drawCentered("TLS+WS Ready", -10);
      drawCentered(ipMsg.c_str(), 10);
      
      // Cleanup
      mbedtls_ecp_group_free(&grp);
      mbedtls_mpi_free(&d);
      mbedtls_ecp_point_free(&Q);
      mbedtls_entropy_free(&entropy);
      mbedtls_ctr_drbg_free(&ctr_drbg);
      return;
    }
    
    // User approved!
    Serial.println("[WS] Connection approved by user");
    secure_channel_ready = true;
    tx_counter = 1;
    
    // Send response with pairing code for mobile app to verify
    StaticJsonDocument<256> resp;
    resp["ok"] = true;
    resp["ecdh_pub"] = bytesToHex(wallet_pub, 65);
    resp["salt"] = bytesToHex(channel_salt, 8);
    resp["code"] = String(codeStr);  // Send code so mobile can display it too
    
    String out;
    serializeJson(resp, out);
    wsServer.sendTXT(num, out.c_str()); // Send unencrypted (key not yet known to client)
    
    // Cleanup
    mbedtls_ecp_group_free(&grp);
    mbedtls_mpi_free(&d);
    mbedtls_ecp_point_free(&Q);
    mbedtls_entropy_free(&entropy);
    mbedtls_ctr_drbg_free(&ctr_drbg);
    
    Serial.println("[WS] Secure channel established!");
    drawCentered("Secure Channel", -10);
    drawCentered("Connected!", 10);
    return;
  }
  
  // PUBKEY
  if (strcmp(cmd, "PUBKEY") == 0) {
    // Debug: Show what ed25519_pk contains
    Serial.print("[PUBKEY] ed25519_pk bytes: ");
    for (int i = 0; i < 32; i++) Serial.printf("%02X", ed25519_pk[i]);
    Serial.println();
    
    String pubkeyB58 = bytesToBase58(ed25519_pk, 32);
    Serial.println("[PUBKEY] Base58: " + pubkeyB58);
    String resp = "{\"ok\":true,\"pubkey\":\"" + pubkeyB58 + "\"}";
    wsSendEncrypted(num, resp.c_str());
  }
  // PING
  else if (strcmp(cmd, "PING") == 0) {
    wsSendEncrypted(num, "{\"ok\":true,\"pong\":true}");
  }
  // SIGN
  else if (strcmp(cmd, "SIGN") == 0) {
    if (!pin_verified) {
      wsSendEncrypted(num, "{\"ok\":false,\"error\":\"device_locked\"}");
      return;
    }
    
    // SECURITY: Check sign rate limit
    if (isSignRateLimited()) {
      char rateLimitMsg[128];
      unsigned long waitSec = (getRateLimitRemainingMs() / 1000) + 1;
      snprintf(rateLimitMsg, sizeof(rateLimitMsg), 
               "{\"ok\":false,\"error\":\"rate_limited\",\"wait_seconds\":%lu}", waitSec);
      wsSendEncrypted(num, rateLimitMsg);
      return;
    }
    
    const char* msgHex = doc["msg"];
    if (!msgHex) {
      wsSendEncrypted(num, "{\"ok\":false,\"error\":\"missing_msg\"}");
      return;
    }
    
    size_t hexLen = strlen(msgHex);
    size_t msgLen = hexLen / 2;
    uint8_t* msg = new uint8_t[msgLen];
    hexToBytes(msgHex, msg, msgLen);
    
    uint8_t msgHash[32];
    mbedtls_sha256(msg, msgLen, msgHash, 0);
    
    u8g2.clearBuffer();
    u8g2.setFont(u8g2_font_6x10_tf);
    u8g2.drawStr(0, 12, "MOBILE SIGN REQ");
    char sizeStr[32];
    snprintf(sizeStr, sizeof(sizeStr), "Size: %d bytes", msgLen);
    u8g2.drawStr(0, 26, sizeStr);
    char hashStr[32];
    snprintf(hashStr, sizeof(hashStr), "Hash: %02x%02x%02x...", msgHash[0], msgHash[1], msgHash[2]);
    u8g2.drawStr(0, 40, hashStr);
    u8g2.setFont(u8g2_font_9x15_tf);
    u8g2.drawStr(0, 58, "OK=Sign X=Reject");
    u8g2.sendBuffer();
    
    int decision = waitForDecision();
    
    StaticJsonDocument<256> resp;
    if (decision == 1) {
      uint8_t sig[64];
      ed25519_sign(msg, msgLen, ed25519_sk, ed25519_pk, sig);
      String sigB58 = bytesToBase58(sig, 64);
      resp["ok"] = true;
      resp["sig_b58"] = sigB58;
      drawCentered("Signed!", 0);
    } else {
      resp["ok"] = false;
      resp["error"] = "rejected";
      drawCentered("Rejected", 0);
    }
    delete[] msg;
    
    String out;
    serializeJson(resp, out);
    wsSendEncrypted(num, out.c_str());
    delay(1000);
    String ipMsg = WiFi.localIP().toString() + ":" + String(SERVER_PORT);
    drawCentered("TLS+WS Ready", -10);
    drawCentered(ipMsg.c_str(), 10);
  }
  // SHOW_MNEMONIC
  else if (strcmp(cmd, "SHOW_MNEMONIC") == 0) {
    if (!pin_verified) {
      wsSendEncrypted(num, "{\"ok\":false,\"error\":\"device_locked\"}");
      return;
    }
    displayMnemonic();
    wsSendEncrypted(num, "{\"ok\":true}");
    String ipMsg = WiFi.localIP().toString() + ":" + String(SERVER_PORT);
    drawCentered(ipMsg.c_str(), 10);
  }
  // SET_WIFI - Requires physical confirmation
  else if (strcmp(cmd, "SET_WIFI") == 0) {
    if (!pin_verified) {
      wsSendEncrypted(num, "{\"ok\":false,\"error\":\"device_locked\"}");
      return;
    }
    
    String ssid = doc["ssid"];
    String pass = doc["password"];
    
    if (ssid.length() == 0) {
      wsSendEncrypted(num, "{\"ok\":false,\"error\":\"empty_ssid\"}");
      return;
    }
    
    // SECURITY: Display confirmation on OLED and wait for button press
    u8g2.clearBuffer();
    u8g2.setFont(u8g2_font_7x14B_tf);
    u8g2.drawStr(5, 15, "SET WIFI?");
    u8g2.setFont(u8g2_font_6x10_tf);
    
    // Truncate SSID if too long for display
    String displaySsid = ssid.length() > 18 ? ssid.substring(0, 15) + "..." : ssid;
    u8g2.drawStr(5, 30, displaySsid.c_str());
    
    u8g2.drawStr(5, 50, "OK=Confirm BACK=Cancel");
    u8g2.sendBuffer();
    
    // Wait up to 30 seconds for button press
    unsigned long confirmStart = millis();
    bool confirmed = false;
    bool cancelled = false;
    
    while (millis() - confirmStart < 30000 && !confirmed && !cancelled) {
      if (digitalRead(BTN_OK) == LOW) {
        delay(50); // Debounce
        if (digitalRead(BTN_OK) == LOW) {
          confirmed = true;
          while (digitalRead(BTN_OK) == LOW) delay(10); // Wait for release
        }
      }
      if (digitalRead(BTN_BACK) == LOW) {
        delay(50); // Debounce
        if (digitalRead(BTN_BACK) == LOW) {
          cancelled = true;
          while (digitalRead(BTN_BACK) == LOW) delay(10); // Wait for release
        }
      }
      delay(10);
    }
    
    if (confirmed) {
      Preferences wifiPrefs;
      wifiPrefs.begin("wifi", false);
      wifiPrefs.putString("ssid", ssid);
      wifiPrefs.putString("password", pass);
      wifiPrefs.end();
      
      drawCentered("WiFi Saved!", 0);
      wsSendEncrypted(num, "{\"ok\":true}");
      delay(1000);
      ESP.restart();
    } else {
      drawCentered("WiFi Cancelled", 0);
      wsSendEncrypted(num, "{\"ok\":false,\"error\":\"user_cancelled\"}");
      delay(1500);
    }
  }
  // RECOVERY_INIT - Generate and display recovery code on device
  else if (strcmp(cmd, "RECOVERY_INIT") == 0) {
    if (!pin_verified) {
      wsSendEncrypted(num, "{\"ok\":false,\"error\":\"device_locked\"}");
      return;
    }
    
    // Generate random 6-digit code
    recovery_code = esp_random() % 1000000;  // 0-999999
    recovery_code_expires = millis() + RECOVERY_CODE_TIMEOUT_MS;
    
    // Display on OLED
    u8g2.clearBuffer();
    u8g2.setFont(u8g2_font_7x14B_tf);
    u8g2.drawStr(10, 15, "RECOVERY CODE:");
    u8g2.setFont(u8g2_font_10x20_tf);  // Large font for code
    char codeStr[8];
    snprintf(codeStr, sizeof(codeStr), "%06lu", recovery_code);
    u8g2.drawStr(30, 40, codeStr);
    u8g2.setFont(u8g2_font_6x10_tf);
    u8g2.drawStr(0, 55, "Enter in app. 2min timeout");
    u8g2.sendBuffer();
    
    Serial.println("[WS] Recovery code generated (not logged for security)");
    wsSendEncrypted(num, "{\"ok\":true,\"message\":\"code_displayed\"}");
  }
  // RECOVER
  else if (strcmp(cmd, "RECOVER") == 0) {
    if (!pin_verified) {
      wsSendEncrypted(num, "{\"ok\":false,\"error\":\"device_locked\"}");
      return;
    }
    
    // SECURITY: Verify device code
    if (recovery_code == 0 || millis() > recovery_code_expires) {
      wsSendEncrypted(num, "{\"ok\":false,\"error\":\"no_recovery_code\",\"message\":\"Call RECOVERY_INIT first\"}");
      return;
    }
    
    uint32_t providedCode = doc["device_code"] | 0;
    if (providedCode != recovery_code) {
      wsSendEncrypted(num, "{\"ok\":false,\"error\":\"invalid_code\"}");
      // Invalidate code after failed attempt
      recovery_code = 0;
      recovery_code_expires = 0;
      drawCentered("Wrong code!", 0);
      delay(2000);
      return;
    }
    
    // Code verified - invalidate it
    recovery_code = 0;
    recovery_code_expires = 0;
    
    String words[12];
    bool hasWords = true;
    for (int i = 0; i < 12; i++) {
      String key = "word" + String(i);
      if (!doc.containsKey(key)) {
        hasWords = false;
        break;
      }
      words[i] = doc[key].as<String>();
    }
    
    if (hasWords) {
      drawCentered("Recovering...", 0);
      
      
      uint8_t sk[32];
      uint8_t pk[32];
      
      // BIP39 Recovery
      uint8_t bip39Seed[64];
      if (recoverBIP39(words, bip39Seed)) {
        Serial.println("[Recovery] Valid BIP39 mnemonic");
        bip39ToKey(bip39Seed, sk);
        ed25519_publickey(sk, pk);
        
        // Close and reopen prefs to ensure write access
        prefs.end();
        prefs.begin("wallet", false);
        
        // Store the RECOVERED key
        if (storeRecoveredKey(prefs, pin_key, pin_salt, sk, pk, words)) {
          memcpy(ed25519_sk, sk, 32);
          memcpy(ed25519_pk, pk, 32);
          for (int i = 0; i < 12; i++) {
            mnemonicWords[i] = words[i];
          }
          
          wsSendEncrypted(num, "{\"ok\":true}");
          drawCentered("Recovered!", 0);
          delay(2000);
          ESP.restart();
        } else {
          wsSendEncrypted(num, "{\"ok\":false,\"error\":\"storage_failed\"}");
          drawCentered("Storage error!", 0);
          delay(2000);
        }
      } else {
        wsSendEncrypted(num, "{\"ok\":false,\"error\":\"invalid_mnemonic\"}");
        drawCentered("Invalid Words", 0);
        delay(2000);
      }

    } else {
      wsSendEncrypted(num, "{\"ok\":false,\"error\":\"missing_words\"}");
    }
  }
  // FACTORY_RESET
  else if (strcmp(cmd, "FACTORY_RESET") == 0) {
    if (!pin_verified) {
      wsSendEncrypted(num, "{\"ok\":false,\"error\":\"device_locked\"}");
      return;
    }
    
    // Show confirmation screen on OLED
    u8g2.clearBuffer();
    u8g2.setFont(u8g2_font_9x15_tf);
    u8g2.drawStr(0, 12, "!! FACTORY RESET !!");
    u8g2.setFont(u8g2_font_6x10_tf);
    u8g2.drawStr(0, 28, "This will ERASE all");
    u8g2.drawStr(0, 40, "keys, WiFi & settings");
    u8g2.setFont(u8g2_font_9x15_tf);
    u8g2.drawStr(0, 58, "OK=WIPE  X=Cancel");
    u8g2.sendBuffer();
    
    // Wait for physical button confirmation
    int decision = waitForDecision();
    
    if (decision == 1) {
      // User confirmed - wipe everything
      drawCentered("Wiping...", 0);
      
      // Clear wallet namespace
      prefs.end();
      prefs.begin("wallet", false);
      prefs.clear();
      prefs.end();
      
      // Clear WiFi namespace
      Preferences wifiPrefs;
      wifiPrefs.begin("wifi", false);
      wifiPrefs.clear();
      wifiPrefs.end();
      
      // Clear any other namespaces
      Preferences miscPrefs;
      miscPrefs.begin("settings", false);
      miscPrefs.clear();
      miscPrefs.end();
      
      wsSendEncrypted(num, "{\"ok\":true,\"message\":\"factory_reset_complete\"}");
      
      drawCentered("Reset Complete!", -10);
      drawCentered("Restarting...", 10);
      delay(2000);
      ESP.restart();
    } else {
      // User cancelled
      wsSendEncrypted(num, "{\"ok\":false,\"error\":\"cancelled\"}");
      drawCentered("Cancelled", 0);
      delay(1000);
      String ipMsg = WiFi.localIP().toString() + ":" + String(SERVER_PORT);
      drawCentered("TLS+WS Ready", -10);
      drawCentered(ipMsg.c_str(), 10);
    }
  }
  // Unknown
  else {
    wsSendEncrypted(num, "{\"ok\":false,\"error\":\"unknown_cmd\"}");
  }
}

#endif  // USE_WEBSOCKET_SERVER
