#pragma once
/*
 * BIP39 Mnemonic System for ESP32 Hardware Wallet
 * 
 * Standard BIP39: 12 words -> 2048-word list -> PBKDF2 -> Seed -> SLIP-0010 -> Ed25519
 * Compatible with Phantom, Solflare, Ledger, and all standard Solana wallets.
 */

#include <Arduino.h>
#include "mbedtls/sha256.h"
#include "mbedtls/sha512.h"
#include "mbedtls/md.h"
#include "mbedtls/pkcs5.h"
#include "bip39_words.h"

// --- BIP39 Mnemonic Generation ---

// Generate 12-word BIP39 mnemonic from 128 bits (16 bytes) of entropy
// This creates standard-compatible mnemonics that work with Phantom/Solflare
inline void generateBIP39Mnemonic(const uint8_t entropy[16], String words[12]) {
  // Calculate checksum: first 4 bits of SHA256(entropy)
  uint8_t hash[32];
  mbedtls_sha256(entropy, 16, hash, 0);
  uint8_t checksumBits = hash[0] >> 4; // First 4 bits
  
  uint16_t indices[12];
  
  // Process bit by bit to extract 11-bit chunks
  // Total: 132 bits = 12 words * 11 bits
  for (int wordIdx = 0; wordIdx < 12; wordIdx++) {
    int startBit = wordIdx * 11;
    uint16_t index = 0;
    
    for (int bit = 0; bit < 11; bit++) {
      int bitPos = startBit + bit;
      bool bitVal;
      
      if (bitPos < 128) {
        // Get bit from entropy
        int byteIdx = bitPos / 8;
        int bitInByte = 7 - (bitPos % 8);
        bitVal = (entropy[byteIdx] >> bitInByte) & 1;
      } else {
        // Get bit from checksum (bits 128-131)
        int checksumBit = bitPos - 128;
        bitVal = (checksumBits >> (3 - checksumBit)) & 1;
      }
      
      index = (index << 1) | bitVal;
    }
    
    indices[wordIdx] = index;
  }
  
  // Convert indices to words
  for (int i = 0; i < 12; i++) {
    words[i] = String(BIP39_WORDS[indices[i]]);
  }
}

// Wrapper function for compatibility
inline void generateMnemonic(const uint8_t entropy[16], String words[12]) {
  generateBIP39Mnemonic(entropy, words);
}

// --- BIP39 Recovery ---

// Find index of word in 2048-word list
inline int getBIP39Index(String word) {
  for (int i = 0; i < 2048; i++) {
    if (word.equals(BIP39_WORDS[i])) return i;
  }
  return -1;
}

// Recover using standard BIP39 (returns true if valid checksum)
// Outputs 64-byte seed
inline bool recoverBIP39(const String words[12], uint8_t seed[64]) {
  uint16_t indices[12];
  
  // 1. Look up words
  for (int i = 0; i < 12; i++) {
    int idx = getBIP39Index(words[i]);
    if (idx < 0) return false; // Word not in BIP39 list
    indices[i] = (uint16_t)idx;
  }
  
  // 2. Convert 12 x 11-bit indices to entropy + checksum
  uint8_t entropy[16];
  memset(entropy, 0, 16);
  
  int bitIndex = 0;
  for (int i = 0; i < 12; i++) {
    for (int j = 10; j >= 0; j--) {
      bool bit = (indices[i] >> j) & 1;
      if (bitIndex < 128) {
        if (bit) {
          entropy[bitIndex / 8] |= (1 << (7 - (bitIndex % 8)));
        }
      }
      bitIndex++;
    }
  }
  
  // 3. Verify Checksum
  uint8_t received_checksum = indices[11] & 0x0F;
  uint8_t hash[32];
  mbedtls_sha256(entropy, 16, hash, 0);
  uint8_t calculated_checksum = hash[0] >> 4;
  
  if (received_checksum != calculated_checksum) {
    return false;
  }
  
  // 4. Derive Seed (PBKDF2)
  String mnemonicStr = "";
  for (int i = 0; i < 12; i++) {
    mnemonicStr += words[i];
    if (i < 11) mnemonicStr += " ";
  }
  
  const char* pass = mnemonicStr.c_str();
  const char* salt = "mnemonic";
  
  int ret = mbedtls_pkcs5_pbkdf2_hmac_ext(
                            MBEDTLS_MD_SHA512,
                            (const unsigned char *)pass, strlen(pass),
                            (const unsigned char *)salt, strlen(salt),
                            2048, 64, seed);
  
  return (ret == 0);
}

// Alias for compatibility
inline bool tryRecoverBIP39(const String words[12], uint8_t seed[64]) {
  return recoverBIP39(words, seed);
}

// --- SLIP-0010 Ed25519 Key Derivation ---

// HMAC-SHA512 helper
inline void hmacSha512(const uint8_t* key, size_t keyLen, 
                       const uint8_t* data, size_t dataLen, 
                       uint8_t out[64]) {
  mbedtls_md_context_t ctx;
  const mbedtls_md_info_t* info = mbedtls_md_info_from_type(MBEDTLS_MD_SHA512);
  
  mbedtls_md_init(&ctx);
  mbedtls_md_setup(&ctx, info, 1);
  mbedtls_md_hmac_starts(&ctx, key, keyLen);
  mbedtls_md_hmac_update(&ctx, data, dataLen);
  mbedtls_md_hmac_finish(&ctx, out);
  mbedtls_md_free(&ctx);
}

// Derive master key from BIP39 seed using SLIP-0010
inline void slip10MasterKey(const uint8_t seed[64], uint8_t masterKey[32], uint8_t chainCode[32]) {
  const char* curveKey = "ed25519 seed";
  uint8_t I[64];
  
  hmacSha512((const uint8_t*)curveKey, strlen(curveKey), seed, 64, I);
  
  memcpy(masterKey, I, 32);
  memcpy(chainCode, I + 32, 32);
}

// Derive child key (hardened only for Ed25519)
inline void slip10DeriveChild(const uint8_t parentKey[32], const uint8_t parentChainCode[32],
                               uint32_t index,
                               uint8_t childKey[32], uint8_t childChainCode[32]) {
  uint8_t data[37];
  data[0] = 0x00;
  memcpy(data + 1, parentKey, 32);
  data[33] = (index >> 24) & 0xFF;
  data[34] = (index >> 16) & 0xFF;
  data[35] = (index >> 8) & 0xFF;
  data[36] = index & 0xFF;
  
  uint8_t I[64];
  hmacSha512(parentChainCode, 32, data, 37, I);
  
  memcpy(childKey, I, 32);
  memcpy(childChainCode, I + 32, 32);
}

// Full BIP44 derivation for Solana: m/44'/501'/0'/0'
inline void deriveSolanaKey(const uint8_t seed[64], uint8_t sk[32]) {
  uint8_t key[32], chainCode[32];
  uint8_t childKey[32], childChainCode[32];
  
  slip10MasterKey(seed, key, chainCode);
  
  // m/44'
  slip10DeriveChild(key, chainCode, 0x8000002C, childKey, childChainCode);
  memcpy(key, childKey, 32);
  memcpy(chainCode, childChainCode, 32);
  
  // m/44'/501'
  slip10DeriveChild(key, chainCode, 0x800001F5, childKey, childChainCode);
  memcpy(key, childKey, 32);
  memcpy(chainCode, childChainCode, 32);
  
  // m/44'/501'/0'
  slip10DeriveChild(key, chainCode, 0x80000000, childKey, childChainCode);
  memcpy(key, childKey, 32);
  memcpy(chainCode, childChainCode, 32);
  
  // m/44'/501'/0'/0'
  slip10DeriveChild(key, chainCode, 0x80000000, childKey, childChainCode);
  
  memcpy(sk, childKey, 32);
}

// Convert 64-byte BIP39 seed to 32-byte Ed25519 private key
// Uses SLIP-0010 derivation with Solana BIP44 path
inline void bip39ToKey(const uint8_t seed[64], uint8_t sk[32]) {
  deriveSolanaKey(seed, sk);
}
