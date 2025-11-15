#pragma once
#include <Arduino.h>
#include <mbedtls/gcm.h>
#include <mbedtls/base64.h>
#include <string.h>

// Abstract JSON channel interface used by wallet_handler.
class IChannel {
public:
  virtual ~IChannel() {}
  virtual bool recvJSON(String &out, uint32_t timeout_ms) = 0;
  virtual void sendJSON(const String &json) = 0;
};

// Plaintext JSON-over-line channel (used for WiFiClientSecure/TLS).
class PlainChannel : public IChannel {
public:
  explicit PlainChannel(Stream &io) : io_(io) {}

  bool recvJSON(String &out, uint32_t timeout_ms) override {
    uint32_t start = millis();
    while ((millis() - start) < timeout_ms) {
      if (io_.available()) {
        String line = io_.readStringUntil('\n');
        line.trim();
        if (line.length() == 0) {
          continue;
        }
        out = line;
        return true;
      }
      delay(1);
    }
    return false;
  }

  void sendJSON(const String &json) override {
    io_.print(json);
    io_.print('\n');
  }

private:
  Stream &io_;
};

// AES-GCM secure channel with line framing compatible with pc_app/secure_channel.py.
// Frame format:  "ENC:" + base64(nonce || ciphertext || tag) + "\n"
// Nonce = 12 bytes = 8-byte salt || 4-byte big-endian counter.
class SecureChannel : public IChannel {
public:
  explicit SecureChannel(Stream &io)
      : io_(io), key_len_(0), salt_set_(false), tx_counter_(1) {
    memset(key_, 0, sizeof(key_));
    memset(salt_, 0, sizeof(salt_));
    mbedtls_gcm_init(&gcm_);
  }

  ~SecureChannel() {
    mbedtls_gcm_free(&gcm_);
  }

  // key_len must be 16/24/32 bytes (AES-128/192/256).
  // salt_opt (8 bytes) may be null -> zero salt used (must match PC side).
  bool begin(const uint8_t *key, size_t key_len, const uint8_t *salt_opt = nullptr) {
    if (!(key_len == 16 || key_len == 24 || key_len == 32)) {
      return false;
    }
    memcpy(key_, key, key_len);
    key_len_ = key_len;

    if (salt_opt) {
      memcpy(salt_, salt_opt, 8);
    } else {
      memset(salt_, 0, 8);
    }
    salt_set_ = true;

    int rc = mbedtls_gcm_setkey(&gcm_, MBEDTLS_CIPHER_ID_AES, key_, key_len_ * 8);
    if (rc != 0) {
      key_len_ = 0;
      return false;
    }

    tx_counter_ = 1;
    io_.println("SC:READY");  // useful for debugging on PC side
    return true;
  }

  // Receive one JSON object (UTF-8) via AES-GCM framed line. Returns false on timeout.
  bool recvJSON(String &out, uint32_t timeout_ms) override {
    if (key_len_ == 0 || !salt_set_) {
      return false;
    }
    uint32_t start = millis();
    while ((millis() - start) < timeout_ms) {
      if (!io_.available()) {
        delay(1);
        continue;
      }

      String line = io_.readStringUntil('\n');
      line.trim();
      if (line.length() == 0) {
        continue;
      }
      if (!line.startsWith("ENC:")) {
        // ignore non-encrypted noise
        continue;
      }

      String b64 = line.substring(4);
      size_t b64_len = b64.length();
      if (b64_len == 0) {
        continue;
      }

      // Decode base64: raw = nonce(12) || ciphertext || tag(16)
      size_t raw_buf_len = (b64_len * 3) / 4 + 4;
      uint8_t *raw = (uint8_t *)malloc(raw_buf_len);
      if (!raw) {
        return false;
      }
      size_t raw_len = 0;
      int rc = mbedtls_base64_decode(raw, raw_buf_len, &raw_len,
                                     (const unsigned char *)b64.c_str(), b64_len);
      if (rc != 0 || raw_len < 12 + 16) {
        free(raw);
        continue;
      }

      uint8_t nonce[12];
      memcpy(nonce, raw, 12);
      size_t ct_len = raw_len - 12 - 16;
      uint8_t *ct = raw + 12;
      uint8_t *tag = raw + 12 + ct_len;

      uint8_t *pt = (uint8_t *)malloc(ct_len + 1);
      if (!pt) {
        free(raw);
        return false;
      }

      rc = mbedtls_gcm_auth_decrypt(&gcm_,
                                    ct_len,
                                    nonce, 12,
                                    nullptr, 0,
                                    tag, 16,
                                    ct, pt);
      if (rc != 0) {
        free(raw);
        free(pt);
        continue;
      }

      pt[ct_len] = 0;
      out = String((const char *)pt);
      free(raw);
      free(pt);
      return true;
    }
    return false;
  }

  // Send one JSON object via AES-GCM framed line.
  void sendJSON(const String &json) override {
    if (key_len_ == 0 || !salt_set_) {
      return;
    }
    const char *cstr = json.c_str();
    size_t pt_len = strlen(cstr);

    uint8_t *pt = (uint8_t *)malloc(pt_len);
    if (!pt) {
      return;
    }
    memcpy(pt, cstr, pt_len);

    // Build nonce = salt(8) || counter(4 big-endian)
    uint8_t nonce[12];
    memcpy(nonce, salt_, 8);
    uint32_t ctr = tx_counter_++;
    nonce[8]  = (uint8_t)((ctr >> 24) & 0xFF);
    nonce[9]  = (uint8_t)((ctr >> 16) & 0xFF);
    nonce[10] = (uint8_t)((ctr >> 8) & 0xFF);
    nonce[11] = (uint8_t)(ctr & 0xFF);

    uint8_t *ct = (uint8_t *)malloc(pt_len);
    uint8_t tag[16];
    if (!ct) {
      free(pt);
      return;
    }

    int rc = mbedtls_gcm_crypt_and_tag(&gcm_,
                                       MBEDTLS_GCM_ENCRYPT,
                                       pt_len,
                                       nonce, 12,
                                       nullptr, 0,
                                       pt,
                                       ct,
                                       16,
                                       tag);
    if (rc != 0) {
      free(pt);
      free(ct);
      return;
    }

    size_t raw_len = 12 + pt_len + 16;
    uint8_t *raw = (uint8_t *)malloc(raw_len);
    if (!raw) {
      free(pt);
      free(ct);
      return;
    }
    memcpy(raw, nonce, 12);
    memcpy(raw + 12, ct, pt_len);
    memcpy(raw + 12 + pt_len, tag, 16);

    // Base64 encode raw
    size_t b64_buf_len = 4 * ((raw_len + 2) / 3) + 4;
    uint8_t *b64 = (uint8_t *)malloc(b64_buf_len + 1);
    if (!b64) {
      free(pt);
      free(ct);
      free(raw);
      return;
    }
    size_t b64_len = 0;
    rc = mbedtls_base64_encode(b64, b64_buf_len + 1, &b64_len, raw, raw_len);
    if (rc != 0) {
      free(pt);
      free(ct);
      free(raw);
      free(b64);
      return;
    }
    b64[b64_len] = 0;

    io_.print("ENC:");
    io_.print((const char *)b64);
    io_.print('\n');

    free(pt);
    free(ct);
    free(raw);
    free(b64);
  }

private:
  Stream &io_;
  mbedtls_gcm_context gcm_;
  uint8_t key_[32];
  size_t key_len_;
  uint8_t salt_[8];
  bool salt_set_;
  uint32_t tx_counter_;
};
