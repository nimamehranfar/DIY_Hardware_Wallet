#pragma once
#include <Arduino.h>
#include <ArduinoJson.h>
#include "mbedtls/base64.h"
#include "display_ui.h"
#include "crypto/ed25519.h"
#include <memory>

extern uint8_t ed25519_sk[32];
extern uint8_t ed25519_pk[32];

// Convert bytes to hex string
inline String bytesToHex(const uint8_t* data, size_t len) {
  const char* hex = "0123456789abcdef";
  String s; s.reserve(len*2);
  for (size_t i=0;i<len;++i){ s += hex[(data[i]>>4)&0xF]; s += hex[data[i]&0xF]; }
  return s;
}

// Sign a message and return the signature as hex
inline String signMessage(const uint8_t* msg, size_t msgLen) {
  uint8_t sig[64];
  ed25519_sign(msg, msgLen, ed25519_sk, ed25519_pk, sig);
  return bytesToHex(sig, 64);
}

// Sign a base64-encoded message and return signature as hex
inline String signBase64Message(const char* msg_b64) {
  String b64 = String(msg_b64);
  size_t outLen = 0;
  // First call to get required output length
  mbedtls_base64_decode(NULL, 0, &outLen, (const unsigned char*)b64.c_str(), b64.length());
  std::unique_ptr<uint8_t[]> msg(new uint8_t[outLen]);
  // Decode the base64 data
  size_t actualLen = 0;
  mbedtls_base64_decode(msg.get(), outLen, &actualLen, (const unsigned char*)b64.c_str(), b64.length());
  return signMessage(msg.get(), actualLen);
}

