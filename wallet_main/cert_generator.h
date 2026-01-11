#pragma once
/*
 * Per-Device TLS Certificate Generator for ESP32
 * 
 * Generates unique RSA 2048-bit key and self-signed X.509 certificate
 * on first boot. Stores in NVS for persistence.
 * 
 * This ensures each device has unique TLS identity - no secrets in source code.
 */

#include <Preferences.h>
#include "mbedtls/pk.h"
#include "mbedtls/rsa.h"
#include "mbedtls/x509_crt.h"
#include "mbedtls/entropy.h"
#include "mbedtls/ctr_drbg.h"
#include "mbedtls/error.h"
#include "esp_random.h"

// PEM buffer sizes
#define CERT_PEM_SIZE 2048
#define KEY_PEM_SIZE 2048

// Storage for generated certificate and key
static char generated_cert_pem[CERT_PEM_SIZE];
static char generated_key_pem[KEY_PEM_SIZE];
static bool certs_loaded = false;

// Custom entropy callback using ESP32's hardware RNG
static int esp32_hardware_rng(void* data, unsigned char* output, size_t len) {
  (void)data;
  esp_fill_random(output, len);
  return 0;
}

// Generate self-signed RSA certificate
// Returns true on success
inline bool generateSelfSignedCert() {
  Serial.println("[CERT] Generating RSA 2048-bit key pair...");
  Serial.println("[CERT] This takes about 30-60 seconds, please wait...");
  
  int ret = 0;
  mbedtls_pk_context key;
  mbedtls_x509write_cert crt;
  mbedtls_mpi serial;
  mbedtls_entropy_context entropy;
  mbedtls_ctr_drbg_context ctr_drbg;
  
  // Declare serial_num before any gotos
  uint32_t serial_num = 0;
  
  // Initialize
  mbedtls_pk_init(&key);
  mbedtls_x509write_crt_init(&crt);
  mbedtls_mpi_init(&serial);
  mbedtls_entropy_init(&entropy);
  mbedtls_ctr_drbg_init(&ctr_drbg);
  
  const char* pers = "espresSol_wallet";
  
  // Seed DRBG with hardware RNG
  ret = mbedtls_ctr_drbg_seed(&ctr_drbg, esp32_hardware_rng, &entropy, 
                              (const unsigned char*)pers, strlen(pers));
  if (ret != 0) {
    Serial.printf("[CERT] DRBG seed failed: %d\n", ret);
    goto cleanup;
  }
  
  // Generate RSA 2048-bit key
  ret = mbedtls_pk_setup(&key, mbedtls_pk_info_from_type(MBEDTLS_PK_RSA));
  if (ret != 0) {
    Serial.printf("[CERT] PK setup failed: %d\n", ret);
    goto cleanup;
  }
  
  ret = mbedtls_rsa_gen_key(mbedtls_pk_rsa(key), mbedtls_ctr_drbg_random, &ctr_drbg, 2048, 65537);
  if (ret != 0) {
    Serial.printf("[CERT] RSA keygen failed: %d\n", ret);
    goto cleanup;
  }
  
  Serial.println("[CERT] Key pair generated, creating certificate...");
  
  // Set up certificate
  mbedtls_x509write_crt_set_subject_key(&crt, &key);
  mbedtls_x509write_crt_set_issuer_key(&crt, &key); // Self-signed
  
  // Subject and issuer name
  ret = mbedtls_x509write_crt_set_subject_name(&crt, "CN=espresSol-HardwareWallet,O=DIY,C=XX");
  if (ret != 0) {
    Serial.printf("[CERT] Set subject failed: %d\n", ret);
    goto cleanup;
  }
  
  ret = mbedtls_x509write_crt_set_issuer_name(&crt, "CN=espresSol-HardwareWallet,O=DIY,C=XX");
  if (ret != 0) {
    Serial.printf("[CERT] Set issuer failed: %d\n", ret);
    goto cleanup;
  }
  
  // Random serial number using MPI
  serial_num = esp_random();
  ret = mbedtls_mpi_lset(&serial, serial_num);
  if (ret != 0) {
    Serial.printf("[CERT] Set serial failed: %d\n", ret);
    goto cleanup;
  }
  mbedtls_x509write_crt_set_serial_raw(&crt, (unsigned char*)&serial_num, sizeof(serial_num));
  
  // Validity: 10 years
  mbedtls_x509write_crt_set_validity(&crt, "20250101000000", "20350101000000");
  
  // Signature algorithm
  mbedtls_x509write_crt_set_md_alg(&crt, MBEDTLS_MD_SHA256);
  
  // Basic constraints (CA:TRUE for self-signed)
  mbedtls_x509write_crt_set_basic_constraints(&crt, 1, -1);
  
  // Write certificate to PEM
  ret = mbedtls_x509write_crt_pem(&crt, (unsigned char*)generated_cert_pem, 
                                  CERT_PEM_SIZE, mbedtls_ctr_drbg_random, &ctr_drbg);
  if (ret != 0) {
    Serial.printf("[CERT] Write cert PEM failed: %d\n", ret);
    goto cleanup;
  }
  
  // Write private key to PEM
  ret = mbedtls_pk_write_key_pem(&key, (unsigned char*)generated_key_pem, KEY_PEM_SIZE);
  if (ret != 0) {
    Serial.printf("[CERT] Write key PEM failed: %d\n", ret);
    goto cleanup;
  }
  
  Serial.println("[CERT] Certificate generated successfully!");
  
cleanup:
  mbedtls_pk_free(&key);
  mbedtls_x509write_crt_free(&crt);
  mbedtls_mpi_free(&serial);
  mbedtls_entropy_free(&entropy);
  mbedtls_ctr_drbg_free(&ctr_drbg);
  
  return (ret == 0);
}

// Store certificate and key in NVS
inline bool storeCertsToNVS() {
  Preferences prefs;
  prefs.begin("tls_certs", false); // read-write
  
  size_t certLen = strlen(generated_cert_pem);
  size_t keyLen = strlen(generated_key_pem);
  
  prefs.putBytes("cert_pem", generated_cert_pem, certLen + 1);
  prefs.putBytes("key_pem", generated_key_pem, keyLen + 1);
  prefs.putBool("has_certs", true);
  
  prefs.end();
  
  Serial.printf("[CERT] Stored cert (%d bytes) and key (%d bytes) to NVS\n", certLen, keyLen);
  return true;
}

// Load certificate and key from NVS
inline bool loadCertsFromNVS() {
  Preferences prefs;
  prefs.begin("tls_certs", true); // read-only
  
  if (!prefs.getBool("has_certs", false)) {
    prefs.end();
    return false;
  }
  
  size_t certLen = prefs.getBytes("cert_pem", generated_cert_pem, CERT_PEM_SIZE);
  size_t keyLen = prefs.getBytes("key_pem", generated_key_pem, KEY_PEM_SIZE);
  
  prefs.end();
  
  if (certLen > 0 && keyLen > 0) {
    Serial.printf("[CERT] Loaded cert (%d bytes) and key (%d bytes) from NVS\n", certLen, keyLen);
    certs_loaded = true;
    return true;
  }
  
  return false;
}

// Main initialization function - call at startup
// Returns pointers to cert and key PEM strings
inline bool initDeviceCerts(const char** cert_out, const char** key_out) {
  // Try loading from NVS first
  if (loadCertsFromNVS()) {
    *cert_out = generated_cert_pem;
    *key_out = generated_key_pem;
    return true;
  }
  
  // Generate new certificate
  Serial.println("[CERT] No certificate found, generating new one...");
  
  if (!generateSelfSignedCert()) {
    Serial.println("[CERT] Certificate generation failed!");
    return false;
  }
  
  // Store for future boots
  storeCertsToNVS();
  
  *cert_out = generated_cert_pem;
  *key_out = generated_key_pem;
  certs_loaded = true;
  
  return true;
}

// Check if certs are available
inline bool hasCerts() {
  return certs_loaded;
}

// Get certificate fingerprint for app verification
inline void getCertFingerprint(uint8_t fingerprint[32]) {
  mbedtls_sha256((const unsigned char*)generated_cert_pem, 
                 strlen(generated_cert_pem), fingerprint, 0);
}
