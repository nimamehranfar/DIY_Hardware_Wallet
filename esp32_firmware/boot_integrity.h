#pragma once
/**
 * boot_integrity.h - Boot-time Integrity Check for ESP32 Hardware Wallet
 * 
 * On first boot: Calculates and stores firmware hash
 * On subsequent boots: Verifies hash matches
 * Alerts user if firmware has been modified
 */

#include <Arduino.h>
#include <Preferences.h>
#include "mbedtls/sha256.h"
#include <esp_partition.h>

// Configuration
#define INTEGRITY_CHECK_ENABLED 1

// Calculate hash of running firmware
inline bool calculateFirmwareHash(uint8_t hash[32]) {
  const esp_partition_t* running = esp_ota_get_running_partition();
  if (!running) {
    Serial.println("[BOOT] Failed to get running partition");
    return false;
  }
  
  // Read firmware in chunks and hash
  mbedtls_sha256_context ctx;
  mbedtls_sha256_init(&ctx);
  mbedtls_sha256_starts(&ctx, 0);
  
  const size_t chunkSize = 4096;
  uint8_t* chunk = new uint8_t[chunkSize];
  
  if (!chunk) {
    mbedtls_sha256_free(&ctx);
    return false;
  }
  
  size_t bytesToRead = running->size;
  size_t offset = 0;
  
  while (bytesToRead > 0) {
    size_t readSize = (bytesToRead > chunkSize) ? chunkSize : bytesToRead;
    
    if (esp_partition_read(running, offset, chunk, readSize) != ESP_OK) {
      delete[] chunk;
      mbedtls_sha256_free(&ctx);
      return false;
    }
    
    mbedtls_sha256_update(&ctx, chunk, readSize);
    offset += readSize;
    bytesToRead -= readSize;
  }
  
  delete[] chunk;
  mbedtls_sha256_finish(&ctx, hash);
  mbedtls_sha256_free(&ctx);
  
  return true;
}

// Check boot integrity
// Returns: 0 = OK, 1 = First boot (hash stored), -1 = Hash mismatch (ALERT!)
inline int checkBootIntegrity() {
#if !INTEGRITY_CHECK_ENABLED
  return 0;  // Skip if disabled
#endif

  Preferences intPrefs;
  intPrefs.begin("integrity", false);
  
  uint8_t currentHash[32];
  if (!calculateFirmwareHash(currentHash)) {
    Serial.println("[BOOT] Failed to calculate firmware hash");
    intPrefs.end();
    return 0;  // Allow boot but log warning
  }
  
  // Print hash for debugging
  Serial.print("[BOOT] Firmware hash: ");
  for (int i = 0; i < 8; i++) Serial.printf("%02X", currentHash[i]);
  Serial.println("...");
  
  // Check if we have a stored hash
  if (!intPrefs.isKey("fw_hash")) {
    // First boot - store the hash
    intPrefs.putBytes("fw_hash", currentHash, 32);
    Serial.println("[BOOT] First boot - stored firmware hash");
    intPrefs.end();
    return 1;
  }
  
  // Compare with stored hash
  uint8_t storedHash[32];
  intPrefs.getBytes("fw_hash", storedHash, 32);
  intPrefs.end();
  
  if (memcmp(currentHash, storedHash, 32) != 0) {
    Serial.println("[BOOT] WARNING: Firmware hash mismatch!");
    Serial.println("[BOOT] This could indicate tampering or a legitimate update.");
    return -1;  // Alert!
  }
  
  Serial.println("[BOOT] Firmware integrity verified");
  return 0;
}

// Update stored hash (call after intentional firmware update)
inline void updateStoredFirmwareHash() {
  Preferences intPrefs;
  intPrefs.begin("integrity", false);
  
  uint8_t hash[32];
  if (calculateFirmwareHash(hash)) {
    intPrefs.putBytes("fw_hash", hash, 32);
    Serial.println("[BOOT] Updated stored firmware hash");
  }
  
  intPrefs.end();
}

// Clear integrity check (for development)
inline void clearIntegrityCheck() {
  Preferences intPrefs;
  intPrefs.begin("integrity", false);
  intPrefs.remove("fw_hash");
  intPrefs.end();
  Serial.println("[BOOT] Cleared integrity check");
}
