#pragma once
#include <Arduino.h>
#include <Ed25519.h>
#include <Preferences.h>
#include "secure_channel.h"

Preferences walletPrefs;
uint8_t priv[32], pub[32];

void walletInit() {
  walletPrefs.begin("wallet", false);
  if (walletPrefs.getBytesLength("priv") == 32) {
    walletPrefs.getBytes("priv", priv, 32);
    Ed25519::derivePublicKey(pub, priv);
  } else {
    Ed25519::generatePrivateKey(priv);
    Ed25519::derivePublicKey(pub, priv);
    walletPrefs.putBytes("priv", priv, 32);
  }
  walletPrefs.end();
}

String b58(const uint8_t *data, size_t len) {
  static const char *ALPHA = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz";
  int zeroes = 0;
  while (zeroes < (int)len && data[zeroes] == 0) zeroes++;

  uint8_t buf[len * 2];
  memcpy(buf, data, len);
  size_t start = zeroes;
  char temp[len * 2];
  int tl = 0;

  while (start < len) {
    int carry = 0;
    for (size_t i = start; i < len; i++) {
      int val = buf[i];
      int x = (carry << 8) + val;
      buf[i] = x / 58;
      carry = x % 58;
    }
    if (buf[start] == 0) start++;
    temp[tl++] = ALPHA[carry];
  }

  String out;
  for (int i = 0; i < zeroes; i++) out += '1';
  for (int i = tl - 1; i >= 0; i--) out += temp[i];
  return out;
}

// Unified wallet request handler for both USB (AES-GCM) and WiFi (TLS plaintext).
// main.ino passes either a SecureChannel or PlainChannel as IChannel.
void walletServe(IChannel &ch) {
  walletInit();

  for (;;) {
    String req;
    if (!ch.recvJSON(req, 10000)) {
      // timeout, just continue waiting
      continue;
    }
    req.trim();
    if (req.length() == 0) {
      continue;
    }

    if (req.indexOf("\"cmd\":\"PUBKEY\"") >= 0) {
      String pk = b58(pub, 32);
      ch.sendJSON(String("{\"ok\":true,\"pubkey\":\"") + pk + "\"}");
    } else if (req.indexOf("\"cmd\":\"SIGN\"") >= 0) {
      int mpos = req.indexOf("\"msg\":\"");
      int mend = (mpos >= 0) ? req.indexOf("\"", mpos + 7) : -1;
      if (mpos >= 0 && mend > mpos) {
        String hex = req.substring(mpos + 7, mend);
        size_t l = hex.length() / 2;
        uint8_t msg[l];
        for (size_t i = 0; i < l; i++) {
          msg[i] = (uint8_t)strtoul(hex.substring(i * 2, i * 2 + 2).c_str(), nullptr, 16);
        }
        uint8_t sig[64];
        Ed25519::sign(sig, priv, pub, msg, l);
        String s58 = b58(sig, 64);
        ch.sendJSON(String("{\"ok\":true,\"sig_b58\":\"") + s58 + "\"}");
      }
    }
  }
}
