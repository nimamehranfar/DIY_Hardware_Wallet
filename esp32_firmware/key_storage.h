#pragma once
#include <Preferences.h>
#include <Arduino.h>
#include "crypto/ed25519.h"

inline bool loadOrGenerateKey(Preferences& prefs, uint8_t sk[32], uint8_t pk[32]) {
  if (prefs.isKey("sk")) {
    size_t n = prefs.getBytes("sk", sk, 32);
    if (n != 32) return false;
    ed25519_publickey(sk, pk);
    return true;
  }
  for (int i=0;i<32;++i) sk[i] = (uint8_t)random(0,256);
  prefs.putBytes("sk", sk, 32);
  ed25519_publickey(sk, pk);
  return true;
}
