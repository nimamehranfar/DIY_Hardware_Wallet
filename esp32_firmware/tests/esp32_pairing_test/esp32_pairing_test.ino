#include <Arduino.h>
#include <Wire.h>
#include <Adafruit_GFX.h>
#include <Adafruit_SSD1306.h>
#include <string.h>

#include "mbedtls/pk.h"
#include "mbedtls/ecp.h"
#include "mbedtls/ecdh.h"
#include "mbedtls/entropy.h"
#include "mbedtls/ctr_drbg.h"
#include "mbedtls/sha256.h"
#include <Preferences.h>
Preferences prefs;

#define OLED_ADDR      0x3C
#define SCREEN_WIDTH   128
#define SCREEN_HEIGHT  64
Adafruit_SSD1306 display(SCREEN_WIDTH, SCREEN_HEIGHT, &Wire, -1);

#define BTN_APPROVE 19   // Approve button
#define BTN_DENY    18   // Deny button

// mbedTLS contexts
mbedtls_pk_context      keypair;
mbedtls_ecdh_context    ecdh;
mbedtls_entropy_context entropy;
mbedtls_ctr_drbg_context ctr_drbg;

uint8_t shared_secret[32];
uint8_t pc_pubkey65[65]; // 0x04 + 64 bytes (X||Y)

uint8_t saved_wallet_pub[64];
uint8_t saved_pc_pub[64];
uint8_t saved_secret[32];
bool has_saved = false;

static void showOLED(const String &l1, const String &l2 = "", const String &l3 = "") {
  display.clearDisplay();
  display.setTextSize(2);
  display.setTextColor(SSD1306_WHITE);
  display.setCursor(0, 0);
  display.println(l1);
  if (l2.length()) display.println(l2);
  if (l3.length()) display.println(l3);
  display.display();
}

static uint8_t hex2byte(const char *p) {
  uint8_t v = 0;
  for (int i = 0; i < 2; ++i) {
    char c = p[i];
    v <<= 4;
    if (c >= '0' && c <= '9') v |= (c - '0');
    else if (c >= 'a' && c <= 'f') v |= (c - 'a' + 10);
    else if (c >= 'A' && c <= 'F') v |= (c - 'A' + 10);
  }
  return v;
}

void setup() {
  Serial.begin(115200);
  Serial.setTimeout(10); 
  Wire.begin();
  display.begin(SSD1306_SWITCHCAPVCC, OLED_ADDR);
  showOLED("Init crypto...");
  delay(500);

  prefs.begin("pair", false);
  if (prefs.getBytesLength("wallet_pub") == 64 && prefs.getBytesLength("pc_pub") == 64 && prefs.getBytesLength("secret") == 32) {
    prefs.getBytes("wallet_pub", saved_wallet_pub, 64); // ESP's own public key
    prefs.getBytes("pc_pub", saved_pc_pub, 64);
    prefs.getBytes("secret", saved_secret, 32);
    has_saved = true;
  }
  else{
    has_saved = false;
  }
  prefs.end();

  // Init RNG and contexts
  mbedtls_pk_init(&keypair);
  mbedtls_ecdh_init(&ecdh);
  mbedtls_entropy_init(&entropy);
  mbedtls_ctr_drbg_init(&ctr_drbg);

  const char *pers = "esp32_pairing";
  mbedtls_ctr_drbg_seed(&ctr_drbg, mbedtls_entropy_func, &entropy,
                        (const unsigned char*)pers, strlen(pers));

  // Generate EC key (secp256r1)
  mbedtls_pk_setup(&keypair, mbedtls_pk_info_from_type(MBEDTLS_PK_ECKEY));
  mbedtls_ecp_gen_key(MBEDTLS_ECP_DP_SECP256R1,
                      mbedtls_pk_ec(keypair),
                      mbedtls_ctr_drbg_random, &ctr_drbg);

  // Export public key (X9.62 uncompressed, 65 bytes: 0x04 || X(32) || Y(32))
  uint8_t wallet_pub65[65];
  size_t pub_len = 0;
  mbedtls_ecp_point_write_binary(
      &mbedtls_pk_ec(keypair)->MBEDTLS_PRIVATE(grp),
      &mbedtls_pk_ec(keypair)->MBEDTLS_PRIVATE(Q),
      MBEDTLS_ECP_PF_UNCOMPRESSED,
      &pub_len,
      wallet_pub65,
      sizeof(wallet_pub65)
  );

  if(has_saved){
    memcpy(&wallet_pub65[1], saved_wallet_pub, 64);
  }
  else{
    showOLED("No saved secret", "skipping");
    delay(1000);
  }

  bool pcKeyReceived = false;
  String keyhex;

  while (!pcKeyReceived) {
    // Send our pub every 1s until PC responds
    Serial.println("WALLET_PUB_BEGIN");
    for (int i = 1; i < (int)pub_len; i++) Serial.printf("%02X", wallet_pub65[i]);
    Serial.println();
    Serial.println("WALLET_PUB_END");
    showOLED("Waiting for", "PC public key...");

    unsigned long start = millis();
    while (millis() - start < 1000) {
      // read line (fast timeout)
      if (Serial.available()) {
        String line = Serial.readStringUntil('\n');
        line.trim();
        if (line.length() == 0) continue;

        // 1) Explicit marker
        if (line == "PC_PUB_BEGIN") {
          keyhex = Serial.readStringUntil('\n');
          keyhex.trim();
          if (keyhex.length() == 128) { pcKeyReceived = true; break; }
        }

        // 2) Fallback: direct 128-hex line (no marker)
        if (line.length() == 128) {
          keyhex = line;
          pcKeyReceived = true;
          break;
        }
      }
    }
  }

  // Build 65-byte uncompressed point with 0x04 prefix
  pc_pubkey65[0] = 0x04;
  for (int i = 0; i < 64; i++) {
    pc_pubkey65[i + 1] = hex2byte(keyhex.substring(i * 2, i * 2 + 2).c_str());
  }

  bool match = false;
  if (has_saved) {
    // showOLED(String(saved_pc_pub[63]), String(pc_pubkey65[64]));
    // delay(1500);
    if (memcmp(saved_pc_pub, pc_pubkey65 + 1, 64) == 0) match = true;
  }

  // Setup ECDH on secp256r1
  mbedtls_ecdh_setup(&ecdh, MBEDTLS_ECP_DP_SECP256R1);

  // Set our private key d
  mbedtls_mpi_copy(
    &ecdh.MBEDTLS_PRIVATE(ctx).MBEDTLS_PRIVATE(mbed_ecdh).MBEDTLS_PRIVATE(d),
    &mbedtls_pk_ec(keypair)->MBEDTLS_PRIVATE(d)
  );

  // Import peer public key Qp
  mbedtls_ecp_point_read_binary(
    &ecdh.MBEDTLS_PRIVATE(ctx).MBEDTLS_PRIVATE(mbed_ecdh).MBEDTLS_PRIVATE(grp),
    &ecdh.MBEDTLS_PRIVATE(ctx).MBEDTLS_PRIVATE(mbed_ecdh).MBEDTLS_PRIVATE(Qp),
    pc_pubkey65, 65
  );

  // Compute shared secret z
  size_t zlen = 0;
  mbedtls_ecdh_calc_secret(&ecdh, &zlen, shared_secret, sizeof(shared_secret),
                           mbedtls_ctr_drbg_random, &ctr_drbg);

  // Pairing code = first 3 bytes of SHA-256(shared_secret), hex uppercase
  uint8_t hash[32];
  mbedtls_sha256(shared_secret, 32, hash, 0);
  char code[7];
  snprintf(code, sizeof(code), "%02X%02X%02X", hash[0], hash[1], hash[2]);
  
  if (has_saved) {
    if (match) {
      Serial.println("PAIRING_APPROVAL");
      Serial.println("PAIRING_APPROVAL_APPROVED");
      Serial.println("PAIRING_APPROVAL_END");
      showOLED("Paired", "Auto skip");
      return;
    }
    else{
      Serial.println("PAIRING_APPROVAL");
      Serial.println("PAIRING_APPROVAL_DENIED");
      Serial.println("PAIRING_APPROVAL_END");
      prefs.begin("pair", false);   // open NVS namespace 'pair'
      prefs.remove("pc_pub");       // delete saved PC public key
      prefs.remove("wallet_pub");   // delete saved ESP own public key (if you store it)
      prefs.remove("secret");       // delete shared secret (if stored)
      prefs.end();
      ESP.restart();
    }
  }

  Serial.println("PAIR_CODE_BEGIN");
  Serial.println(code);
  Serial.println("PAIR_CODE_END");

  
  // Setup button pins
  pinMode(BTN_APPROVE, INPUT_PULLUP);
  pinMode(BTN_DENY, INPUT_PULLUP);

  showOLED("Pair Code:", code, "19=Allow 18=Deny");

  // Wait for user decision
  bool decisionMade = false;
  bool approved = false;
  while (!decisionMade) {
    if (digitalRead(BTN_APPROVE) == LOW) {  // Button pressed: GPIO19
      approved = true;
      decisionMade = true;
    }
    if (digitalRead(BTN_DENY) == LOW) {     // Button pressed: GPIO18
      approved = false;
      decisionMade = true;
    }
    delay(10); // Debounce
  }

  if (approved) {
    Serial.println("PAIRING_APPROVAL");
    Serial.println("PAIRING_APPROVAL_APPROVED");
    Serial.println("PAIRING_APPROVAL_END");
    showOLED("Approved", "Saving keys...");

    prefs.begin("pair", false);
    prefs.putBytes("wallet_pub", wallet_pub65 + 1, 64); // ESP's own public key
    prefs.putBytes("pc_pub", pc_pubkey65 + 1, 64);
    prefs.putBytes("secret", shared_secret, 32);
    prefs.end();
  } else {
    Serial.println("PAIRING_APPROVAL");
    Serial.println("PAIRING_APPROVAL_DENIED");
    Serial.println("PAIRING_APPROVAL_END");
    showOLED("Denied", "Restarting...");
    delay(1000);
    ESP.restart();
  }
}

void loop() {
  // idle
}
