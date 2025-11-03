#pragma once
#include <Arduino.h>
#include <Preferences.h>

// ===== Trezor Crypto Includes =====
extern "C" {
  #include "crypto/bip39.h"
  #include "crypto/sha2.h"
  #include "crypto/pbkdf2.h"
  #include "crypto/ed25519.h"
  #include "crypto/curves.h"
  #include "crypto/hmac.h"
  #include "crypto/slip10.h"
}

// ===== Constants =====
#define MNEMONIC_WORDS 12
#define BIP39_PASSPHRASE ""  // no passphrase for now
#define SOLANA_PATH "m/44'/501'/0'/0'"

// ===== Globals =====
Preferences prefs;

static String globalMnemonic = "";
static uint8_t privateKey[32];
static uint8_t publicKey[32];

// ===== Generate Random Mnemonic =====
String generate_mnemonic() {
  uint8_t entropy[16]; // 128 bits → 12 words
  for(int i = 0; i < 16; i++) {
    entropy[i] = (uint8_t)esp_random();
  }
  const char* words = mnemonic_from_data(entropy, 16);
  return String(words);
}

// ===== Derive Seed from Mnemonic (BIP39 → PBKDF2-HMAC-SHA512) =====
void mnemonic_to_seed(const String& mnemonic, uint8_t seed[64]) {
  mnemonic_to_seed(mnemonic.c_str(), BIP39_PASSPHRASE, seed, NULL);
}

// ===== Derive Solana Key from BIP39 Seed (ed25519 SLIP-0010) =====
void derive_solana_key(const uint8_t seed[64]) {
  HDNode node;
  hdnode_from_seed(seed, 64, SECP256K1_NAME, &node);

  // Derive path: m/44'/501'/0'/0'
  hdnode_private_ckd_prime(&node, 44);
  hdnode_private_ckd_prime(&node, 501);
  hdnode_private_ckd_prime(&node, 0);
  hdnode_private_ckd_prime(&node, 0);

  memcpy(privateKey, node.private_key, 32);
  ed25519_publickey(node.private_key, publicKey);
}

// ===== Save Private Key & Mnemonic in NVS =====
void save_wallet_to_nvs() {
  prefs.begin("solwallet", false);
  prefs.putString("mnemonic", globalMnemonic);
  prefs.putBytes("privkey", privateKey, 32);
  prefs.putBytes("pubkey", publicKey, 32);
  prefs.end();
}

// ===== Load Wallet if Exists =====
bool load_wallet_from_nvs() {
  prefs.begin("solwallet", true);
  if (!prefs.isKey("mnemonic")) {
    prefs.end();
    return false;
  }
  globalMnemonic = prefs.getString("mnemonic");
  prefs.getBytes("privkey", privateKey, 32);
  prefs.getBytes("pubkey", publicKey, 32);
  prefs.end();
  return true;
}

// ===== Initialize New Wallet (Full Flow) =====
void create_new_wallet() {
  // 1. Generate Mnemonic
  globalMnemonic = generate_mnemonic();

  // 2. Derive Seed
  uint8_t seed[64];
  mnemonic_to_seed(globalMnemonic, seed);

  // 3. Create Solana Ed25519 Keypair
  derive_solana_key(seed);

  // 4. Save to NVS
  save_wallet_to_nvs();
}

// ===== Getters =====
String get_mnemonic() {
  return globalMnemonic;
}

const uint8_t* get_private_key() {
  return privateKey;
}

const uint8_t* get_public_key() {
  return publicKey;
}
