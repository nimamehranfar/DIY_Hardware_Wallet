#ifndef USB_COMM_ECDH_H
#define USB_COMM_ECDH_H

#include <Arduino.h>
#include <Adafruit_SSD1306.h>
#include <Preferences.h>

#include "mbedtls/ecdh.h"
#include "mbedtls/entropy.h"
#include "mbedtls/ctr_drbg.h"
#include "mbedtls/sha256.h"
#include "mbedtls/aes.h"

extern Adafruit_SSD1306 display;

// ===== Buttons (adjust if needed) =====
#ifndef BTN_CONFIRM
#define BTN_CONFIRM 4     // OK
#endif
#ifndef BTN_DENY
#define BTN_DENY 23       // DENY / back
#endif

// ===== OLED helper =====
static void ecdh_oled(const String &l1, const String &l2 = "", const String &l3 = "") {
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
static String toHex(const uint8_t *buf, size_t len) {
  static const char *H = "0123456789ABCDEF";
  String s; s.reserve(len * 2);
  for (size_t i = 0; i < len; ++i) { s += H[buf[i] >> 4]; s += H[buf[i] & 0x0F]; }
  return s;
}
static int fromHex(const String &hex, uint8_t *out, size_t maxlen) {
  auto val = [](char c)->int{
    if (c>='0'&&c<='9') return c-'0';
    if (c>='a'&&c<='f') return 10+(c-'a');
    if (c>='A'&&c<='F') return 10+(c-'A');
    return -1;
  };
  String h = hex; h.trim();
  if (h.length() % 2) return -1;
  size_t need = h.length()/2; if (need > maxlen) return -2;
  for (size_t i=0;i<need;i++){
    int a=val(h[2*i]), b=val(h[2*i+1]); if(a<0||b<0) return -3;
    out[i] = (uint8_t)((a<<4)|b);
  }
  return (int)need;
}

// ===== SHA-256 =====
static void sha256_bytes(const uint8_t *in, size_t len, uint8_t out[32]) {
  mbedtls_sha256_context ctx; mbedtls_sha256_init(&ctx);
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

// ===== Minimal HKDF-SHA256 (1-block OKM) =====
static void hkdf_sha256(const uint8_t *secret, size_t slen,
                        const uint8_t *salt, size_t saltlen,
                        const uint8_t *info, size_t infolen,
                        uint8_t out[32]) {
  uint8_t zero[32] = {0};
  if (!salt || !saltlen) { salt = zero; saltlen = 32; }

  auto hmac = [&](const uint8_t *k, size_t klen,
                  const uint8_t *m, size_t mlen, uint8_t o[32]){
    // HMAC = SHA256((k^opad)||SHA256((k^ipad)||m))
    const size_t B=64;
    uint8_t kopad[B]={0}, kipad[B]={0}, tmp[B+mlen];
    uint8_t kh[32];
    if (klen > B) { sha256_bytes(k, klen, kh); k = kh; klen = 32; }
    memcpy(kopad, k, klen); memcpy(kipad, k, klen);
    for (size_t i=0;i<B;i++){ kopad[i]^=0x5c; kipad[i]^=0x36; }
    memcpy(tmp, kipad, B); memcpy(tmp+B, m, mlen);
    sha256_bytes(tmp, B+mlen, o);
    memcpy(tmp, kopad, B); memcpy(tmp+B, o, 32);
    sha256_bytes(tmp, B+32, o);
  };

  uint8_t prk[32];
  hmac(salt, saltlen, secret, slen, prk);

  // T(1) = HMAC(PRK, info || 0x01)
  uint8_t ibuf[64]; // infolen + 1 (<=64 here)
  memcpy(ibuf, info, infolen);
  ibuf[infolen] = 0x01;
  hmac(prk, 32, ibuf, infolen + 1, out);
}

// ===== AES-CTR =====
static void aes_ctr_crypt(const uint8_t key[32], const uint8_t iv[16],
                          const uint8_t *in, uint8_t *out, size_t len) {
  mbedtls_aes_context aes; mbedtls_aes_init(&aes);
  mbedtls_aes_setkey_enc(&aes, key, 256);
  unsigned char nonce_counter[16]; unsigned char stream_block[16]; size_t nc_off = 0;
  memcpy(nonce_counter, iv, 16); memset(stream_block, 0, sizeof(stream_block));
  mbedtls_aes_crypt_ctr(&aes, len, &nc_off, nonce_counter, stream_block, in, out);
  mbedtls_aes_free(&aes);
}

// ===== serial line reader =====
static bool serialReadLine(String &out, uint32_t timeout_ms=10000) {
  out = "";
  uint32_t start = millis();
  while (millis() - start < timeout_ms) {
    while (Serial.available()) {
      char c = (char)Serial.read();
      if (c == '\n') { out.trim(); return true; }
      out += c;
    }
    delay(2);
  }
  return false;
}

// ===== main flow: ECDH over USB, pairing code, AES session =====
static bool runUSBECDH(Adafruit_SSD1306 &disp) {
  pinMode(BTN_CONFIRM, INPUT_PULLUP);
  pinMode(BTN_DENY, INPUT_PULLUP);

  ecdh_oled("USB mode", "Waiting...");
  Serial.setTimeout(10);

  // Handshake wait loop so PC can open port at any time
  for (;;) {
    Serial.println("USB_READY");
    unsigned long t0 = millis();
    while (millis() - t0 < 2000) {
      if (Serial.available()) goto have_host;
      delay(10);
    }
  }
have_host:

  // --- Init RNG + ECDH context (public API only) ---
  mbedtls_entropy_context entropy; mbedtls_entropy_init(&entropy);
  mbedtls_ctr_drbg_context ctr_drbg; mbedtls_ctr_drbg_init(&ctr_drbg);
  const char *pers = "esp32_pairing";
  mbedtls_ctr_drbg_seed(&ctr_drbg, mbedtls_entropy_func, &entropy,
                        (const unsigned char*)pers, strlen(pers));

  mbedtls_ecdh_context ctx; mbedtls_ecdh_init(&ctx);
  if (mbedtls_ecdh_setup(&ctx, MBEDTLS_ECP_DP_SECP256R1) != 0) {
    Serial.println("{\"status\":\"error\",\"reason\":\"ecdh_setup\"}");
    ecdh_oled("ECDH", "setup fail");
    mbedtls_ecdh_free(&ctx);
    mbedtls_ctr_drbg_free(&ctr_drbg);
    mbedtls_entropy_free(&entropy);
    return false;
  }

  // --- Make our public key (uncompressed 65 bytes) ---
  uint8_t my_pub[65]; size_t my_pub_len = 0;
  int rc = mbedtls_ecdh_make_public(&ctx, &my_pub_len, my_pub, sizeof(my_pub),
                                    mbedtls_ctr_drbg_random, &ctr_drbg);
  if (rc != 0 || my_pub_len != 65 || my_pub[0] != 0x04) {
    Serial.println("{\"status\":\"error\",\"reason\":\"make_public\"}");
    ecdh_oled("ECDH", "pub fail");
    mbedtls_ecdh_free(&ctx);
    mbedtls_ctr_drbg_free(&ctr_drbg);
    mbedtls_entropy_free(&entropy);
    return false;
  }

  // --- Expect PC public key JSON: {"pc_pub":"04...."} ---
  String line;
  if (!serialReadLine(line, 15000)) {
    Serial.println("{\"status\":\"error\",\"reason\":\"timeout_pc_pub\"}");
    ecdh_oled("No PC pub");
    mbedtls_ecdh_free(&ctx);
    mbedtls_ctr_drbg_free(&ctr_drbg);
    mbedtls_entropy_free(&entropy);
    return false;
  }
  line.trim();
  int keyPos = line.indexOf("\"pc_pub\"");
  if (keyPos < 0) {
    Serial.println("{\"status\":\"error\",\"reason\":\"bad_msg\"}");
    ecdh_oled("Bad msg");
    mbedtls_ecdh_free(&ctx);
    mbedtls_ctr_drbg_free(&ctr_drbg);
    mbedtls_entropy_free(&entropy);
    return false;
  }
  int q1 = line.indexOf("\"", keyPos + 7);
  q1 = line.indexOf("\"", q1 + 1);
  int q2 = line.indexOf("\"", q1 + 1);
  String pc_pub_hex = line.substring(q1 + 1, q2);
  uint8_t pc_pub[65];
  if (fromHex(pc_pub_hex, pc_pub, sizeof(pc_pub)) != 65 || pc_pub[0] != 0x04) {
    Serial.println("{\"status\":\"error\",\"reason\":\"pc_pub_hex\"}");
    ecdh_oled("PC pub bad");
    mbedtls_ecdh_free(&ctx);
    mbedtls_ctr_drbg_free(&ctr_drbg);
    mbedtls_entropy_free(&entropy);
    return false;
  }

  // --- Read peer public into context ---
  if (mbedtls_ecdh_read_public(&ctx, pc_pub, 65) != 0) {
    Serial.println("{\"status\":\"error\",\"reason\":\"read_public\"}");
    ecdh_oled("ECDH", "read fail");
    mbedtls_ecdh_free(&ctx);
    mbedtls_ctr_drbg_free(&ctr_drbg);
    mbedtls_entropy_free(&entropy);
    return false;
  }

  // --- Compute the shared secret ---
  uint8_t shared[32]; size_t shared_len = 0;
  if (mbedtls_ecdh_calc_secret(&ctx, &shared_len, shared, sizeof(shared),
                               mbedtls_ctr_drbg_random, &ctr_drbg) != 0 || shared_len != 32) {
    Serial.println("{\"status\":\"error\",\"reason\":\"calc_secret\"}");
    ecdh_oled("ECDH", "secret fail");
    mbedtls_ecdh_free(&ctx);
    mbedtls_ctr_drbg_free(&ctr_drbg);
    mbedtls_entropy_free(&entropy);
    return false;
  }

  // --- 6-digit pairing code = SHA256(shared || my_pub || pc_pub) % 1e6 ---
  uint8_t mix[32 + 65 + 65];
  memcpy(mix, shared, 32);
  memcpy(mix + 32, my_pub, 65);
  memcpy(mix + 97, pc_pub, 65);
  uint8_t h[32]; sha256_bytes(mix, sizeof(mix), h);
  uint32_t code = ((uint32_t)h[0] << 24) | ((uint32_t)h[1] << 16) | ((uint32_t)h[2] << 8) | h[3];
  code %= 1000000;
  char codeStr[8]; snprintf(codeStr, sizeof(codeStr), "%06u", code);

  // --- Display & send our pub + code to PC ---
  ecdh_oled("PAIR CODE", codeStr, "OK=Allow");
  Serial.print("{\"status\":\"ok\",\"wallet_pub\":\"");
  Serial.print(toHex(my_pub, 65));
  Serial.print("\",\"code\":\"");
  Serial.print(codeStr);
  Serial.println("\"}");

  // --- Wait for local user to Allow / Deny ---
  unsigned long st = millis();
  for (;;) {
    if (digitalRead(BTN_CONFIRM) == LOW) {
      Serial.println("{\"action\":\"user\",\"decision\":\"allow\"}");
      break;
    }
    if (digitalRead(BTN_DENY) == LOW) {
      Serial.println("{\"action\":\"user\",\"decision\":\"deny\"}");
      ecdh_oled("Denied");
      mbedtls_ecdh_free(&ctx);
      mbedtls_ctr_drbg_free(&ctr_drbg);
      mbedtls_entropy_free(&entropy);
      return false;
    }
    if (millis() - st > 60000) {
      Serial.println("{\"action\":\"user\",\"decision\":\"timeout\"}");
      ecdh_oled("Timeout");
      mbedtls_ecdh_free(&ctx);
      mbedtls_ctr_drbg_free(&ctr_drbg);
      mbedtls_entropy_free(&entropy);
      return false;
    }
    delay(10);
  }

  // --- Persist only PC fingerprint (no secrets) ---
  Preferences p; p.begin("pair", false);
  uint8_t pc_fpr[32]; sha256_bytes(pc_pub, 65, pc_fpr);
  p.putBytes("pc_fpr", pc_fpr, 32);
  p.end();

  // --- Derive AES-256 session key via HKDF(shared, salt="USBPAIRv1", info="AES-256-CTR") ---
  const uint8_t salt[] = {'U','S','B','P','A','I','R','v','1'};
  const uint8_t info[] = {'A','E','S','-','2','5','6','-','C','T','R'};
  uint8_t aesKey[32];
  hkdf_sha256(shared, shared_len, salt, sizeof(salt), info, sizeof(info), aesKey);

  ecdh_oled("Paired OK", "Securing...");
  delay(300);

  // --- Encrypted echo test: expect {"action":"enc_test","iv":"<32hex>","plain":"..."} ---
  String msg;
  if (!serialReadLine(msg, 12000)) {
    Serial.println("{\"status\":\"error\",\"reason\":\"no_enc_msg\"}");
    ecdh_oled("No enc msg");
    mbedtls_ecdh_free(&ctx);
    mbedtls_ctr_drbg_free(&ctr_drbg);
    mbedtls_entropy_free(&entropy);
    return false;
  }
  msg.trim();
  if (msg.indexOf("\"enc_test\"") == -1) {
    Serial.println("{\"status\":\"error\",\"reason\":\"enc_format\"}");
    ecdh_oled("Enc bad");
    mbedtls_ecdh_free(&ctx);
    mbedtls_ctr_drbg_free(&ctr_drbg);
    mbedtls_entropy_free(&entropy);
    return false;
  }
  auto getField = [&](const String &src, const char *key)->String{
    int k = src.indexOf(String("\"") + key + "\""); if (k < 0) return "";
    int c = src.indexOf(":", k); int q1 = src.indexOf("\"", c); int q2 = src.indexOf("\"", q1+1);
    if (c<0||q1<0||q2<0) return "";
    return src.substring(q1+1, q2);
  };
  String ivHex = getField(msg, "iv");
  String plain = getField(msg, "plain");
  if (ivHex.length() != 32 || plain.length() == 0) {
    Serial.println("{\"status\":\"error\",\"reason\":\"enc_fields\"}");
    mbedtls_ecdh_free(&ctx);
    mbedtls_ctr_drbg_free(&ctr_drbg);
    mbedtls_entropy_free(&entropy);
    return false;
  }
  uint8_t iv[16]; if (fromHex(ivHex, iv, 16) != 16) {
    Serial.println("{\"status\":\"error\",\"reason\":\"iv_hex\"}");
    mbedtls_ecdh_free(&ctx);
    mbedtls_ctr_drbg_free(&ctr_drbg);
    mbedtls_entropy_free(&entropy);
    return false;
  }

  std::string in(plain.c_str());
  std::string out(in.size(), '\0');
  aes_ctr_crypt(aesKey, iv, (const uint8_t*)in.data(), (uint8_t*)out.data(), out.size());

  Serial.print("{\"status\":\"ok\",\"echo\":\"");
  Serial.print(toHex((const uint8_t*)out.data(), out.size()));
  Serial.println("\"}");
  ecdh_oled("USB Enc OK");

  // cleanup
  mbedtls_ecdh_free(&ctx);
  mbedtls_ctr_drbg_free(&ctr_drbg);
  mbedtls_entropy_free(&entropy);
  return true;
}

#endif
