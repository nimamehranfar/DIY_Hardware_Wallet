#pragma once
#include <Preferences.h>
#include <Arduino.h>
#include "crypto/ed25519.h"
#include "crypto/mnemonic.h"
#include "mbedtls/sha256.h"
#include "mbedtls/gcm.h"

// Check if wallet has encrypted keys stored
inline bool hasEncryptedKey(Preferences& prefs) {
  return prefs.isKey("enc_sk") && prefs.isKey("sk_iv") && prefs.isKey("pin_salt");
}

// Check if wallet has plain (legacy) key stored
inline bool hasPlainKey(Preferences& prefs) {
  return prefs.isKey("sk") && !prefs.isKey("enc_sk");
}

// Load encrypted key and decrypt with PIN
inline bool loadEncryptedKey(Preferences& prefs, const uint8_t pinKey[16], 
                             uint8_t sk[32], uint8_t pk[32]) {
  uint8_t encrypted[48];
  uint8_t iv[12];
  
  if (prefs.getBytes("enc_sk", encrypted, 48) != 48) return false;
  if (prefs.getBytes("sk_iv", iv, 12) != 12) return false;
  
  // Decrypt with AES-GCM
  mbedtls_gcm_context gcm;
  mbedtls_gcm_init(&gcm);
  mbedtls_gcm_setkey(&gcm, MBEDTLS_CIPHER_ID_AES, pinKey, 128);
  
  uint8_t tag[16];
  memcpy(tag, encrypted + 32, 16);
  
  int ret = mbedtls_gcm_auth_decrypt(&gcm, 32, iv, 12,
                                      NULL, 0, tag, 16,
                                      encrypted, sk);
  mbedtls_gcm_free(&gcm);
  
  if (ret != 0) return false;  // Wrong PIN
  
  // Derive public key
  ed25519_publickey(sk, pk);
  return true;
}

// Generate new key, encrypt with PIN, and store
inline bool generateAndStoreEncryptedKey(Preferences& prefs, const uint8_t pinKey[16],
                                          const uint8_t salt[16],
                                          uint8_t sk[32], uint8_t pk[32], 
                                          String mnemonic[12]) {
  // Generate 128-bit entropy for BIP39 (16 bytes)
  uint8_t entropy[16];
  esp_fill_random(entropy, 16);
  
  // Generate BIP39 mnemonic
  generateMnemonic(entropy, mnemonic);
  
  // Derive key using BIP39 + SLIP-0010 (Solana path m/44'/501'/0'/0')
  uint8_t bip39Seed[64];
  if (tryRecoverBIP39(mnemonic, bip39Seed)) {
    bip39ToKey(bip39Seed, sk);
  } else {
    // Fallback - shouldn't happen with freshly generated BIP39 mnemonic
    return false;
  }
  
  ed25519_publickey(sk, pk);
  
  // Encrypt private key
  uint8_t encrypted[48];
  uint8_t iv[12];
  esp_fill_random(iv, 12);
  
  mbedtls_gcm_context gcm;
  mbedtls_gcm_init(&gcm);
  mbedtls_gcm_setkey(&gcm, MBEDTLS_CIPHER_ID_AES, pinKey, 128);
  
  uint8_t tag[16];
  int ret = mbedtls_gcm_crypt_and_tag(&gcm, MBEDTLS_GCM_ENCRYPT, 32,
                                       iv, 12, NULL, 0, sk, encrypted, 16, tag);
  mbedtls_gcm_free(&gcm);
  
  if (ret != 0) return false;
  
  memcpy(encrypted + 32, tag, 16);
  
  // Store encrypted key, IV, and salt
  prefs.putBytes("enc_sk", encrypted, 48);
  prefs.putBytes("sk_iv", iv, 12);
  prefs.putBytes("pin_salt", salt, 16);
  
  // Encrypt and store mnemonic
  String mnemonicStr = "";
  for (int i = 0; i < 12; i++) {
    if (i > 0) mnemonicStr += " ";
    mnemonicStr += mnemonic[i];
  }
  
  // Encrypt mnemonic with same key
  uint8_t mnem_iv[12];
  esp_fill_random(mnem_iv, 12);
  
  uint8_t mnem_ct[256];
  uint8_t mnem_tag[16];
  
  mbedtls_gcm_context gcm2;
  mbedtls_gcm_init(&gcm2);
  mbedtls_gcm_setkey(&gcm2, MBEDTLS_CIPHER_ID_AES, pinKey, 128);
  mbedtls_gcm_crypt_and_tag(&gcm2, MBEDTLS_GCM_ENCRYPT, mnemonicStr.length(),
                             mnem_iv, 12, NULL, 0,
                             (const uint8_t*)mnemonicStr.c_str(), mnem_ct,
                             16, mnem_tag);
  mbedtls_gcm_free(&gcm2);
  
  prefs.putBytes("enc_mnem", mnem_ct, mnemonicStr.length());
  prefs.putBytes("mnem_iv", mnem_iv, 12);
  prefs.putBytes("mnem_tag", mnem_tag, 16);
  prefs.putInt("mnem_len", mnemonicStr.length());
  
  return true;
}

// Store RECOVERED key with provided sk/pk/mnemonic (no new generation)
inline bool storeRecoveredKey(Preferences& prefs, const uint8_t pinKey[16],
                               const uint8_t salt[16],
                               const uint8_t sk[32], const uint8_t pk[32], 
                               const String mnemonic[12]) {
  // SECURITY: Mnemonic is never logged to Serial
  
  // Encrypt private key with PIN-derived key
  uint8_t encrypted[48];
  uint8_t iv[12];
  esp_fill_random(iv, 12);
  
  mbedtls_gcm_context gcm;
  mbedtls_gcm_init(&gcm);
  mbedtls_gcm_setkey(&gcm, MBEDTLS_CIPHER_ID_AES, pinKey, 128);
  
  uint8_t tag[16];
  int ret = mbedtls_gcm_crypt_and_tag(&gcm, MBEDTLS_GCM_ENCRYPT, 32,
                                       iv, 12, NULL, 0, sk, encrypted, 16, tag);
  mbedtls_gcm_free(&gcm);
  
  if (ret != 0) return false;
  
  memcpy(encrypted + 32, tag, 16);
  
  // Store encrypted key, IV, and salt
  size_t wrote1 = prefs.putBytes("enc_sk", encrypted, 48);
  size_t wrote2 = prefs.putBytes("sk_iv", iv, 12);
  size_t wrote3 = prefs.putBytes("pin_salt", salt, 16);
  
  Serial.printf("[RECOVERY] Stored enc_sk=%d, sk_iv=%d, pin_salt=%d bytes\n", wrote1, wrote2, wrote3);
  
  // Encrypt and store mnemonic
  String mnemonicStr = "";
  for (int i = 0; i < 12; i++) {
    if (i > 0) mnemonicStr += " ";
    mnemonicStr += mnemonic[i];
  }
  
  // Encrypt mnemonic with same key
  uint8_t mnem_iv[12];
  esp_fill_random(mnem_iv, 12);
  
  uint8_t mnem_ct[256];
  uint8_t mnem_tag[16];
  
  mbedtls_gcm_context gcm2;
  mbedtls_gcm_init(&gcm2);
  mbedtls_gcm_setkey(&gcm2, MBEDTLS_CIPHER_ID_AES, pinKey, 128);
  mbedtls_gcm_crypt_and_tag(&gcm2, MBEDTLS_GCM_ENCRYPT, mnemonicStr.length(),
                             mnem_iv, 12, NULL, 0,
                             (const uint8_t*)mnemonicStr.c_str(), mnem_ct,
                             16, mnem_tag);
  mbedtls_gcm_free(&gcm2);
  
  prefs.putBytes("enc_mnem", mnem_ct, mnemonicStr.length());
  prefs.putBytes("mnem_iv", mnem_iv, 12);
  prefs.putBytes("mnem_tag", mnem_tag, 16);
  prefs.putInt("mnem_len", mnemonicStr.length());
  
  Serial.println("[RECOVERY] storeRecoveredKey COMPLETE - returning true");
  return true;
}

// Migrate legacy plain key to encrypted storage
inline bool migratePlainKeyToEncrypted(Preferences& prefs, const uint8_t pinKey[16],
                                        const uint8_t salt[16],
                                        uint8_t sk[32], uint8_t pk[32]) {
  // Load existing plain key
  if (prefs.getBytes("sk", sk, 32) != 32) return false;
  ed25519_publickey(sk, pk);
  
  // Encrypt it
  uint8_t encrypted[48];
  uint8_t iv[12];
  esp_fill_random(iv, 12);
  
  mbedtls_gcm_context gcm;
  mbedtls_gcm_init(&gcm);
  mbedtls_gcm_setkey(&gcm, MBEDTLS_CIPHER_ID_AES, pinKey, 128);
  
  uint8_t tag[16];
  int ret = mbedtls_gcm_crypt_and_tag(&gcm, MBEDTLS_GCM_ENCRYPT, 32,
                                       iv, 12, NULL, 0, sk, encrypted, 16, tag);
  mbedtls_gcm_free(&gcm);
  
  if (ret != 0) return false;
  
  memcpy(encrypted + 32, tag, 16);
  
  // Store encrypted version
  prefs.putBytes("enc_sk", encrypted, 48);
  prefs.putBytes("sk_iv", iv, 12);
  prefs.putBytes("pin_salt", salt, 16);
  
  // Remove plain key
  prefs.remove("sk");
  
  return true;
}

// Load PIN salt
inline bool loadPINSalt(Preferences& prefs, uint8_t salt[16]) {
  return prefs.getBytes("pin_salt", salt, 16) == 16;
}

// Legacy function for backward compatibility
inline bool loadOrGenerateKey(Preferences& prefs, uint8_t sk[32], uint8_t pk[32], String mnemonic[12]) {
  // This is now a stub - PIN-based loading is handled in setup()
  if (prefs.isKey("sk")) {
    size_t n = prefs.getBytes("sk", sk, 32);
    if (n != 32) return false;
    ed25519_publickey(sk, pk);
    
    // Load mnemonic if exists
    if (prefs.isKey("mnemonic")) {
      String mnemonicStr = prefs.getString("mnemonic", "");
      int wordIndex = 0;
      int start = 0;
      for (int i = 0; i <= mnemonicStr.length(); i++) {
        if (i == mnemonicStr.length() || mnemonicStr[i] == ' ') {
          if (wordIndex < 12) {
            mnemonic[wordIndex++] = mnemonicStr.substring(start, i);
          }
          start = i + 1;
        }
      }
    }
    return true;
  }
  return false;
}

// Recover wallet from mnemonic phrase (using BIP39)
inline bool recoverFromMnemonic(Preferences& prefs, String words[12], 
                                 uint8_t sk[32], uint8_t pk[32]) {
  // Use BIP39 recovery
  uint8_t seed[64];
  if (!recoverBIP39(words, seed)) {
    return false;  // Invalid mnemonic
  }
  
  // Derive key using SLIP-0010
  bip39ToKey(seed, sk);
  ed25519_publickey(sk, pk);
  
  // Store as plain key (will be encrypted on next boot with PIN migration)
  prefs.putBytes("sk", sk, 32);
  
  // Store mnemonic
  String mnemonicStr = "";
  for (int i = 0; i < 12; i++) {
    if (i > 0) mnemonicStr += " ";
    mnemonicStr += words[i];
  }
  prefs.putString("mnemonic", mnemonicStr);
  
  // Remove any encrypted key to force re-encryption on next boot
  prefs.remove("enc_sk");
  prefs.remove("sk_iv");
  prefs.remove("pin_salt");
  
  return true;
}
