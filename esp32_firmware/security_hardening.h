#pragma once
/**
 * security_hardening.h - Security features for ESP32 Hardware Wallet
 * 
 * Features:
 * 1. PIN Brute Force Protection - exponential backoff, wipe after 10 attempts
 * 2. Session Timeout - auto-lock after 5 minutes inactivity
 * 3. Sign Rate Limiting - max 5 signatures per minute
 */

#include <Preferences.h>
#include <Arduino.h>

// ===== CONFIGURATION =====
#define MAX_PIN_ATTEMPTS 10           // Wipe device after this many failures
#define PIN_LOCKOUT_WARNING 5         // Show warning after this many failures
#define SESSION_TIMEOUT_MS 300000     // 5 minutes = 300000ms
#define SIGN_RATE_LIMIT 5             // Max signatures per minute
#define SIGN_RATE_WINDOW_MS 60000     // 60 seconds window

// ===== PIN BRUTE FORCE PROTECTION =====

// Load failed attempt count from NVS
inline uint8_t loadFailedPinAttempts(Preferences& prefs) {
  return prefs.getUChar("pin_failures", 0);
}

// Save failed attempt count to NVS
inline void saveFailedPinAttempts(Preferences& prefs, uint8_t count) {
  prefs.putUChar("pin_failures", count);
}

// Clear failed attempts (called on successful PIN)
inline void clearFailedPinAttempts(Preferences& prefs) {
  prefs.putUChar("pin_failures", 0);
}

// Calculate delay based on failed attempt count (exponential backoff)
// Returns delay in milliseconds: 0, 1s, 2s, 4s, 8s, 16s, 32s, 64s, 128s, 256s
inline unsigned long getPinLockoutDelay(uint8_t failedAttempts) {
  if (failedAttempts == 0) return 0;
  if (failedAttempts > 10) failedAttempts = 10;
  return (1UL << (failedAttempts - 1)) * 1000; // 2^(n-1) seconds
}

// Check if device should be wiped (too many failed attempts)
inline bool shouldWipeDevice(uint8_t failedAttempts) {
  return failedAttempts >= MAX_PIN_ATTEMPTS;
}

// Wipe all sensitive data from NVS (factory reset)
inline void wipeDevice(Preferences& prefs) {
  // Clear all wallet data
  prefs.remove("encrypted_sk");
  prefs.remove("encrypted_iv");
  prefs.remove("encrypted_tag");
  prefs.remove("pk");
  prefs.remove("pin_salt");
  prefs.remove("mnemonic");
  prefs.remove("enc_mnemonic");
  prefs.remove("mnemonic_iv");
  prefs.remove("mnemonic_tag");
  prefs.remove("pin_failures");
  
  // Also clear wifi creds for full reset
  Preferences wifiPrefs;
  wifiPrefs.begin("wifi", false);
  wifiPrefs.clear();
  wifiPrefs.end();
  
  // Also clear TLS certs
  Preferences tlsPrefs;
  tlsPrefs.begin("tls", false);
  tlsPrefs.clear();
  tlsPrefs.end();
}

// Handle failed PIN attempt - returns remaining attempts or 0 if wiped
// Also returns lockout delay via reference
inline uint8_t handleFailedPinAttempt(Preferences& prefs, unsigned long& lockoutDelay) {
  uint8_t failures = loadFailedPinAttempts(prefs);
  failures++;
  saveFailedPinAttempts(prefs, failures);
  
  if (shouldWipeDevice(failures)) {
    wipeDevice(prefs);
    lockoutDelay = 0;
    return 0;
  }
  
  lockoutDelay = getPinLockoutDelay(failures);
  return MAX_PIN_ATTEMPTS - failures;
}

// ===== SESSION TIMEOUT =====

// Global session state - must be extern in header, defined in .ino
extern unsigned long lastActivityTime;
extern bool sessionActive;

// Check if session has timed out
inline bool isSessionTimedOut() {
  if (!sessionActive) return false;
  return (millis() - lastActivityTime) > SESSION_TIMEOUT_MS;
}

// Reset activity timer (call on any user action)
inline void resetActivityTimer() {
  lastActivityTime = millis();
}

// End session (require PIN re-entry)
inline void lockSession() {
  sessionActive = false;
}

// ===== SIGN RATE LIMITING =====

// Track recent sign timestamps (circular buffer)
#define SIGN_HISTORY_SIZE 10
extern unsigned long signTimestamps[SIGN_HISTORY_SIZE];
extern uint8_t signTimestampIndex;

// Record a signature
inline void recordSignature() {
  signTimestamps[signTimestampIndex] = millis();
  signTimestampIndex = (signTimestampIndex + 1) % SIGN_HISTORY_SIZE;
}

// Count signatures in the rate window
inline uint8_t countRecentSignatures() {
  unsigned long now = millis();
  uint8_t count = 0;
  for (int i = 0; i < SIGN_HISTORY_SIZE; i++) {
    if (signTimestamps[i] > 0 && (now - signTimestamps[i]) < SIGN_RATE_WINDOW_MS) {
      count++;
    }
  }
  return count;
}

// Check if signing should be rate limited
inline bool isSignRateLimited() {
  return countRecentSignatures() >= SIGN_RATE_LIMIT;
}

// Get remaining time until rate limit expires (ms)
inline unsigned long getRateLimitRemainingMs() {
  if (!isSignRateLimited()) return 0;
  
  // Find oldest signature in window
  unsigned long now = millis();
  unsigned long oldest = 0;
  
  for (int i = 0; i < SIGN_HISTORY_SIZE; i++) {
    if (signTimestamps[i] > 0 && (now - signTimestamps[i]) < SIGN_RATE_WINDOW_MS) {
      if (oldest == 0 || signTimestamps[i] < oldest) {
        oldest = signTimestamps[i];
      }
    }
  }
  
  if (oldest == 0) return 0;
  return SIGN_RATE_WINDOW_MS - (now - oldest);
}
