#ifndef USB_COMM_H
#define USB_COMM_H

#include <Arduino.h>
#include <Adafruit_SSD1306.h>

#include <mbedtls/version.h>
#include <mbedtls/sha256.h>
#include <mbedtls/aes.h>
#include <string>

extern Adafruit_SSD1306 display;

// ===== OLED helper =====
static void usb_oled(const String &l1, const String &l2="", const String &l3="") {
  display.clearDisplay();
  display.setTextSize(2);
  display.setTextColor(SSD1306_WHITE);
  display.setCursor(0, 0);
  display.println(l1);
  if (l2.length()) display.println(l2);
  if (l3.length()) display.println(l3);
  display.display();
}

// ===== HEX helpers =====
static String toHex(const uint8_t* data, size_t len) {
  static const char* hex="0123456789ABCDEF";
  String s; s.reserve(len*2);
  for (size_t i=0;i<len;i++) { s += hex[(data[i]>>4)&0xF]; s += hex[data[i]&0xF]; }
  return s;
}

static int fromHex(const String &hex, uint8_t* out, size_t outlen) {
  String h = hex; h.trim();
  if (h.length()%2!=0) return -1;
  size_t need = h.length()/2;
  if (need>outlen) return -2;
  auto val=[&](char c)->int{
    if(c>='0'&&c<='9')return c-'0';
    if(c>='a'&&c<='f')return 10+(c-'a');
    if(c>='A'&&c<='F')return 10+(c-'A');
    return -1;
  };
  for (size_t i=0;i<need;i++) {
    int v1=val(h[2*i]), v2=val(h[2*i+1]);
    if(v1<0||v2<0) return -3;
    out[i]= (uint8_t)((v1<<4)|v2);
  }
  return (int)need;
}


static void sha256_bytes(const uint8_t* in, size_t len, uint8_t out[32]) {
  mbedtls_sha256_context ctx;
  mbedtls_sha256_init(&ctx);
#if defined(mbedtls_sha256_starts_ret)
  mbedtls_sha256_starts_ret(&ctx, 0);
  mbedtls_sha256_update_ret(&ctx, in, len);
  mbedtls_sha256_finish_ret(&ctx, out);
#else
  mbedtls_sha256_starts(&ctx, 0);
  mbedtls_sha256_update(&ctx, in, len);
  mbedtls_sha256_finish(&ctx, out);
#endif
  mbedtls_sha256_free(&ctx);
}


// ===== Minimal HMAC-SHA256 (no external deps) =====
static void hmac_sha256(const uint8_t* key, size_t keylen,
                        const uint8_t* msg, size_t msglen,
                        uint8_t out[32]) {
  const size_t B = 64;
  uint8_t kopad[B]; memset(kopad, 0, B);
  uint8_t kipad[B]; memset(kipad, 0, B);

  uint8_t k0[32];
  if (keylen > B) {
    sha256_bytes(key, keylen, k0);
    key = k0;
    keylen = 32;
  }

  memcpy(kopad, key, keylen);
  memcpy(kipad, key, keylen);
  for (size_t i = 0; i < B; i++) {
    kopad[i] ^= 0x5c;
    kipad[i] ^= 0x36;
  }

  // inner = SHA256(kipad || msg)
  uint8_t inner_in[B + msglen];
  memcpy(inner_in, kipad, B);
  memcpy(inner_in + B, msg, msglen);
  uint8_t inner[32];
  sha256_bytes(inner_in, B + msglen, inner);

  // out = SHA256(kopad || inner)
  uint8_t outer_in[B + 32];
  memcpy(outer_in, kopad, B);
  memcpy(outer_in + B, inner, 32);
  sha256_bytes(outer_in, B + 32, out);
}


// ===== AES-CTR (encrypt/decrypt) =====
static void aes_ctr_crypt(const uint8_t key[32], const uint8_t iv[16],
                          const uint8_t* in, uint8_t* out, size_t len) {
  mbedtls_aes_context aes;
  mbedtls_aes_init(&aes);
  mbedtls_aes_setkey_enc(&aes, key, 256);
  unsigned char nonce_counter[16];
  unsigned char stream_block[16];
  size_t nc_off = 0;
  memcpy(nonce_counter, iv, 16);
  memset(stream_block, 0, 16);
  mbedtls_aes_crypt_ctr(&aes, len, &nc_off, nonce_counter, stream_block, in, out);
  mbedtls_aes_free(&aes);
}

// ===== Serial helpers =====
static bool serialReadLine(String &out, uint32_t timeout_ms=8000) {
  out = "";
  uint32_t start = millis();
  while (millis() - start < timeout_ms) {
    while (Serial.available()) {
      char c = (char)Serial.read();
      if (c=='\n') { out.trim(); return true; }
      out += c;
    }
    delay(2);
  }
  return false;
}

// ===== Key derivation: SHA256( PIN ":" seed ) =====
extern const int correctPin[];    // from PasswordHandler.h
extern const int PIN_LENGTH;

static String pinToString() {
  String s;
  for (int i=0;i<PIN_LENGTH;i++) s += String(correctPin[i]);
  return s;
}

static void deriveKeyFromPINAndSeed(uint8_t key[32], const String &pinString, const String &seed) {
  String material = pinString + ":" + seed;
  sha256_bytes((const uint8_t*)material.c_str(), material.length(), key);
}

// ===== Main entry: USB pairing + one encrypted echo =====
static bool runUSBPairingAndEnc(Adafruit_SSD1306 &disp) {
  (void)disp;
  usb_oled("USB mode", "Waiting...");
  Serial.println("USB_READY");

  // Expect {"action":"pair","seed":"...","proof":"<hex>"}
  String line;
  if (!serialReadLine(line, 15000)) { usb_oled("USB timeout"); return false; }

  auto findField=[&](const String &src, const String &key)->String{
    int k = src.indexOf("\""+key+"\"");
    if (k<0) return "";
    int c = src.indexOf(":", k);
    if (c<0) return "";
    int q1 = src.indexOf("\"", c);
    int q2 = src.indexOf("\"", q1+1);
    if (q1<0||q2<0) return "";
    return src.substring(q1+1, q2);
  };
  String action = findField(line, "action");
  String seed   = findField(line, "seed");
  String proofH = findField(line, "proof");

  if (action != "pair" || seed.length()==0 || proofH.length()==0) {
    Serial.println("{\"status\":\"error\",\"reason\":\"bad_pair_msg\"}");
    usb_oled("Pair msg", "invalid");
    return false;
  }

  uint8_t key[32];
  deriveKeyFromPINAndSeed(key, pinToString(), seed);

  const char* proofMsg = "ESP32_PROOF";
  uint8_t expect[32];
  hmac_sha256(key, 32, (const uint8_t*)proofMsg, strlen(proofMsg), expect);

  uint8_t got[32];
  int n = fromHex(proofH, got, sizeof(got));
  if (n != 32 || memcmp(expect, got, 32)!=0) {
    Serial.println("{\"status\":\"error\",\"reason\":\"bad_proof\"}");
    usb_oled("Pair failed");
    return false;
  }

  Serial.println("{\"status\":\"ok\",\"phase\":\"paired\"}");
  usb_oled("Paired OK");

  // Expect {"action":"enc_test","iv":"<32hex>","plain":"..."}
  if (!serialReadLine(line, 8000)) { usb_oled("No enc msg"); return false; }

  String action2 = findField(line, "action");
  String ivHex   = findField(line, "iv");
  String plain   = findField(line, "plain");
  if (action2 != "enc_test" || ivHex.length()!=32 || plain.length()==0) {
    Serial.println("{\"status\":\"error\",\"reason\":\"bad_enc_msg\"}");
    usb_oled("Enc msg bad");
    return false;
  }

  uint8_t iv[16];
  if (fromHex(ivHex, iv, sizeof(iv)) != 16) {
    Serial.println("{\"status\":\"error\",\"reason\":\"iv_hex\"}");
    return false;
  }

  std::string p = std::string(plain.c_str());
  std::string c(p.size(), '\0');
  aes_ctr_crypt(key, iv, (const uint8_t*)p.data(), (uint8_t*)c.data(), c.size());

  String cHex = toHex((const uint8_t*)c.data(), c.size());
  Serial.print("{\"status\":\"ok\",\"echo\":\"");
  Serial.print(cHex);
  Serial.println("\"}");

  usb_oled("USB Enc OK");
  return true;
}

#endif
