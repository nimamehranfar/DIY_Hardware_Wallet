#pragma once
#include <Arduino.h>
#include <ArduinoJson.h>
#include <base64.h>
#include "display_ui.h"
#include "crypto/ed25519.h"

extern WiFiClientSecure tlsClient;
extern uint8_t ed25519_sk[32];
extern uint8_t ed25519_pk[32];

inline void sendError(const char* code) {
  StaticJsonDocument<256> doc;
  doc["status"] = "error";
  doc["code"] = code;
  String out; serializeJson(doc, out); out += "\n";
  tlsClient.print(out);
}

inline void sendOkWithSignature(const String& sigHex) {
  StaticJsonDocument<256> doc;
  doc["status"] = "ok";
  doc["signature_hex"] = sigHex;
  String out; serializeJson(doc, out); out += "\n";
  tlsClient.print(out);
}

inline String bytesToHex(const uint8_t* data, size_t len) {
  const char* hex = "0123456789abcdef";
  String s; s.reserve(len*2);
  for (size_t i=0;i<len;++i){ s += hex[(data[i]>>4)&0xF]; s += hex[data[i]&0xF]; }
  return s;
}

inline bool signAndRespond(const char* msg_b64) {
  String b64 = String(msg_b64);
  int outLen = base64_dec_len(b64.c_str(), b64.length());
  std::unique_ptr<uint8_t[]> msg(new uint8_t[outLen]);
  base64_decode((char*)msg.get(), b64.c_str(), b64.length());
  uint8_t sig[64];
  ed25519_sign(msg.get(), outLen, ed25519_sk, ed25519_pk, sig);
  sendOkWithSignature(bytesToHex(sig, 64));
  return true;
}
