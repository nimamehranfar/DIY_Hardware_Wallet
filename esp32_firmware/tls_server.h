#pragma once
/*
 * TLS Server Implementation using ESP32's built-in mbedTLS
 * Provides TLS-wrapped TCP server functionality
 * 
 * Uses per-device generated certificates - no secrets in source code!
 * Certificate is generated at first boot and stored in NVS.
 */

#include <WiFi.h>
#include <WiFiClient.h>
#include "mbedtls/ssl.h"
#include "mbedtls/entropy.h"
#include "mbedtls/ctr_drbg.h"
#include "mbedtls/error.h"
#include "mbedtls/net_sockets.h"
#include "mbedtls/pk.h"
#include "mbedtls/x509_crt.h"
#include "cert_generator.h"

// Pointers to dynamically generated certs
static const char* tls_cert_pem = nullptr;
static const char* tls_key_pem = nullptr;

// Initialize TLS certificates (call once at startup)
inline bool initTLSCerts() {
  return initDeviceCerts(&tls_cert_pem, &tls_key_pem);
}

// TLS-wrapped client connection with Arduino-style interface
class TLSClient {
private:
  WiFiClient* tcpClient;
  mbedtls_ssl_context ssl;
  mbedtls_ssl_config conf;
  mbedtls_x509_crt srvcert;
  mbedtls_pk_context pkey;
  mbedtls_entropy_context entropy;
  mbedtls_ctr_drbg_context ctr_drbg;
  bool handshakeComplete;
  String readBuffer;
  
  // BIO callbacks for mbedtls
  static int bioSend(void* ctx, const unsigned char* buf, size_t len) {
    WiFiClient* client = (WiFiClient*)ctx;
    if (!client->connected()) return MBEDTLS_ERR_NET_CONN_RESET;
    return client->write(buf, len);
  }
  
  static int bioRecv(void* ctx, unsigned char* buf, size_t len) {
    WiFiClient* client = (WiFiClient*)ctx;
    if (!client->connected()) return MBEDTLS_ERR_NET_CONN_RESET;
    if (!client->available()) return MBEDTLS_ERR_SSL_WANT_READ;
    return client->read(buf, len);
  }
  
public:
  TLSClient() : tcpClient(nullptr), handshakeComplete(false), readBuffer("") {}
  
  bool begin(WiFiClient* client) {
    if (!tls_cert_pem || !tls_key_pem) {
      Serial.println("[TLS] Certificates not initialized!");
      return false;
    }
    
    tcpClient = client;
    
    // Initialize mbedtls
    mbedtls_ssl_init(&ssl);
    mbedtls_ssl_config_init(&conf);
    mbedtls_x509_crt_init(&srvcert);
    mbedtls_pk_init(&pkey);
    mbedtls_entropy_init(&entropy);
    mbedtls_ctr_drbg_init(&ctr_drbg);
    
    // Seed RNG
    int ret = mbedtls_ctr_drbg_seed(&ctr_drbg, mbedtls_entropy_func, &entropy,
                                     (const unsigned char*)"tls_server", 10);
    if (ret != 0) {
      Serial.printf("[TLS] RNG seed failed: -0x%x\n", -ret);
      return false;
    }
    
    // Parse certificate (using dynamically generated cert)
    ret = mbedtls_x509_crt_parse(&srvcert, (const unsigned char*)tls_cert_pem,
                                  strlen(tls_cert_pem) + 1);
    if (ret != 0) {
      Serial.printf("[TLS] Cert parse failed: -0x%x\n", -ret);
      return false;
    }
    
    // Parse private key (using dynamically generated key)
    ret = mbedtls_pk_parse_key(&pkey, (const unsigned char*)tls_key_pem,
                                strlen(tls_key_pem) + 1, NULL, 0,
                                mbedtls_ctr_drbg_random, &ctr_drbg);
    if (ret != 0) {
      Serial.printf("[TLS] Key parse failed: -0x%x\n", -ret);
      return false;
    }
    
    // Configure SSL
    ret = mbedtls_ssl_config_defaults(&conf, MBEDTLS_SSL_IS_SERVER,
                                       MBEDTLS_SSL_TRANSPORT_STREAM,
                                       MBEDTLS_SSL_PRESET_DEFAULT);
    if (ret != 0) {
      Serial.printf("[TLS] Config failed: -0x%x\n", -ret);
      return false;
    }
    
    mbedtls_ssl_conf_rng(&conf, mbedtls_ctr_drbg_random, &ctr_drbg);
    mbedtls_ssl_conf_authmode(&conf, MBEDTLS_SSL_VERIFY_NONE);
    
    ret = mbedtls_ssl_conf_own_cert(&conf, &srvcert, &pkey);
    if (ret != 0) {
      Serial.printf("[TLS] Own cert config failed: -0x%x\n", -ret);
      return false;
    }
    
    ret = mbedtls_ssl_setup(&ssl, &conf);
    if (ret != 0) {
      Serial.printf("[TLS] SSL setup failed: -0x%x\n", -ret);
      return false;
    }
    
    // Set BIO callbacks
    mbedtls_ssl_set_bio(&ssl, tcpClient, bioSend, bioRecv, NULL);
    
    // Perform handshake
    Serial.println("[TLS] Starting handshake...");
    while ((ret = mbedtls_ssl_handshake(&ssl)) != 0) {
      if (ret != MBEDTLS_ERR_SSL_WANT_READ && ret != MBEDTLS_ERR_SSL_WANT_WRITE) {
        Serial.printf("[TLS] Handshake failed: -0x%x\n", -ret);
        return false;
      }
      delay(10);
    }
    
    handshakeComplete = true;
    Serial.println("[TLS] Handshake complete!");
    return true;
  }
  
  bool connected() {
    return tcpClient && tcpClient->connected() && handshakeComplete;
  }
  
  // Check if data is available
  int available() {
    if (!handshakeComplete) return 0;
    
    // Check if we have buffered data
    if (readBuffer.length() > 0) return readBuffer.length();
    
    // Check underlying connection
    if (!tcpClient || !tcpClient->available()) return 0;
    
    // Try to read some data into buffer
    uint8_t buf[256];
    int ret = mbedtls_ssl_read(&ssl, buf, sizeof(buf) - 1);
    if (ret > 0) {
      buf[ret] = 0;
      readBuffer += String((char*)buf);
      return readBuffer.length();
    }
    return 0;
  }
  
  // Read until delimiter
  String readStringUntil(char delimiter) {
    unsigned long start = millis();
    while (millis() - start < 5000) {  // 5 second timeout
      // Check buffer for delimiter
      int pos = readBuffer.indexOf(delimiter);
      if (pos >= 0) {
        String result = readBuffer.substring(0, pos);
        readBuffer = readBuffer.substring(pos + 1);
        return result;
      }
      
      // Try to read more data
      if (tcpClient && tcpClient->available()) {
        uint8_t buf[256];
        int ret = mbedtls_ssl_read(&ssl, buf, sizeof(buf) - 1);
        if (ret > 0) {
          buf[ret] = 0;
          readBuffer += String((char*)buf);
        } else if (ret != MBEDTLS_ERR_SSL_WANT_READ) {
          break;  // Error or disconnected
        }
      }
      delay(10);
    }
    
    // Timeout - return what we have
    String result = readBuffer;
    readBuffer = "";
    return result;
  }
  
  // Print string with newline
  void println(const String& str) {
    print(str + "\n");
  }
  
  void println(const char* str) {
    println(String(str));
  }
  
  // Print string without newline
  void print(const String& str) {
    if (!handshakeComplete) return;
    const char* data = str.c_str();
    size_t len = str.length();
    size_t written = 0;
    while (written < len) {
      int ret = mbedtls_ssl_write(&ssl, (const unsigned char*)(data + written), len - written);
      if (ret > 0) {
        written += ret;
      } else if (ret != MBEDTLS_ERR_SSL_WANT_WRITE) {
        break;  // Error
      }
      delay(1);
    }
  }
  
  // Read raw bytes
  int read(uint8_t* buf, size_t len) {
    if (!handshakeComplete) return -1;
    int ret = mbedtls_ssl_read(&ssl, buf, len);
    if (ret == MBEDTLS_ERR_SSL_WANT_READ) return 0;
    return ret;
  }
  
  // Write raw bytes
  int write(const uint8_t* buf, size_t len) {
    if (!handshakeComplete) return -1;
    return mbedtls_ssl_write(&ssl, buf, len);
  }
  
  void stop() {
    if (handshakeComplete) {
      mbedtls_ssl_close_notify(&ssl);
    }
    mbedtls_ssl_free(&ssl);
    mbedtls_ssl_config_free(&conf);
    mbedtls_x509_crt_free(&srvcert);
    mbedtls_pk_free(&pkey);
    mbedtls_entropy_free(&entropy);
    mbedtls_ctr_drbg_free(&ctr_drbg);
    
    if (tcpClient) {
      tcpClient->stop();
    }
    handshakeComplete = false;
    readBuffer = "";
  }
  
  ~TLSClient() {
    stop();
  }
};

// Simple TLS Server
class TLSServer {
private:
  WiFiServer tcpServer;
  uint16_t port;
  
public:
  TLSServer(uint16_t p = 8443) : tcpServer(p), port(p) {}
  
  void begin() {
    tcpServer.begin();
    Serial.printf("[TLS] Server started on port %d\n", port);
  }
  
  bool hasClient() {
    return tcpServer.hasClient();
  }
  
  WiFiClient available() {
    return tcpServer.available();
  }
};

// Global TLS server instance
static TLSServer tlsServer(8443);
