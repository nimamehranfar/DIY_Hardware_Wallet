#include <WiFi.h>
#include <WiFiClientSecure.h>
#include <Preferences.h>
#include <ArduinoJson.h>
#include <U8g2lib.h>
#include "key_storage.h"
#include "transaction_handler.h"
#include "display_ui.h"

const char* WIFI_SSID = "YOUR_WIFI_SSID";
const char* WIFI_PASSWORD = "YOUR_WIFI_PASSWORD";
const char* SERVER_HOST = "192.168.1.10";
const uint16_t SERVER_PORT = 8443;

const char* SERVER_CERT_PEM = R"PEM(
-----BEGIN CERTIFICATE-----
MIIDAzCCAeugAwIBAgIUexbzejJ06r5tXQ8YF+tmcQ5NqGEwDQYJKoZIhvcNAQEL
BQAwFTETMBEGA1UEAwwKUGNUU0wgU2VydjAeFw0yNTEwMjIxOTU3MTFaFw0zNTEw
MTkxOTU3MTFaMBUxEzARBgNVBAMMClBjVFNMIFNlcnYwggEiMA0GCSqGSIb3DQEB
AQUAA4IBDwAwggEKAoIBAQCfD8BbQ8adSTCqkZkmbYH+H2zBcS1L0svqgZr2aYhU
X5BKS3J1kGZs97bW3rV3b5yTqW5vVmUg0y0j7w9yzM2v6Yp9sA6VnYlKc3o9r+4t
5V7ap6YJ99Y2m6mUOZcUQkBv9s7p7E1nS63H4a8nW9KkIHGqj3tM7vCw3dYQ5nnd
s6g8oRz0rN2wqvBzJwOJo1Qz2+2l7q3lDkO6P5a5U1LwVgQH9nK3wz0cJXvX3fXo
gGQJ4yL1pD7+gWw9p6pU4nqHfYp0V9+2R0p0h0m9k3X2J8a9o2Qk6xg5QwQdXc5o
F7M1S6s0dsy9b8J+1FfU7iZrC4qPzj0XrJ3p1Oiz8QXH1uCpi8Jk8o8lq2zRAgMB
AAGjUzBRMB0GA1UdDgQWBBR0/jq0DHRXyQ9c9D/HgU0nC3cRzDAfBgNVHSMEGDAW
gBR0/jq0DHRXyQ9c9D/HgU0nC3cRzDAPBgNVHRMBAf8EBTADAQH/MA0GCSqGSIb3
DQEBCwUAA4IBAQCGy0b1N5m1wU1o0rJm0N1K3m6d6dOQyTq2b8zq9r7dYwS7c3yA
k0dD0Z0Yv1gKkXwI1xYq6pFQm7fKp1H6m2/5c8l6v5m3K+OaP7XwVf3u5l3HkZ8s
1kO7QdJf6P4r2x2q7o5d9Wc2m6dKjY2yDk3QWm5eZkLZ0g1xk0m2b1n2p3q4r5s6
7t8u9v0w1x2y3z4A5B6C7D8E9F0G1H2I3J4K5L6M7N8O9P0Q1R2S3T4U5V6W7X8Y
Z1a2b3c4d5e6f7g8h9i0jA==
-----END CERTIFICATE-----
)PEM";

const int BTN_UP = 12;
const int BTN_DOWN = 13;
const int BTN_OK = 14;

U8G2_SSD1306_128X64_NONAME_F_HW_I2C u8g2(U8G2_R0, U8X8_PIN_NONE);
WiFiClientSecure tlsClient;
Preferences prefs;

uint8_t ed25519_sk[32];
uint8_t ed25519_pk[32];

void connectWiFi() {
  WiFi.mode(WIFI_STA);
  WiFi.begin(WIFI_SSID, WIFI_PASSWORD);
  drawCentered("WiFi connecting...", 0);
  while (WiFi.status() != WL_CONNECTED) { delay(400); }
  drawCentered("WiFi connected", 0);
}

void serveOneRequest() {
  tlsClient.setCACert(SERVER_CERT_PEM);
  if (!tlsClient.connect(SERVER_HOST, SERVER_PORT)) { drawCentered("TLS connect failed", 0); delay(800); return; }
  drawCentered("TLS connected", 0);

  String line = tlsClient.readStringUntil('\n');
  if (line.length() == 0) { tlsClient.stop(); return; }

  StaticJsonDocument<3072> doc;
  auto err = deserializeJson(doc, line);
  if (err) { sendError("invalid_json"); tlsClient.stop(); return; }

  const char* action = doc["action"] | "";
  if (strcmp(action, "sign_solana_message")) { sendError("unknown_action"); tlsClient.stop(); return; }

  const char* msg_b64 = doc["message_b64"];
  const char* sender_pk = doc["sender_pubkey"];
  const char* recipient = doc["recipient"];
  long amount = doc["amount"] | 0;

  String header = "Review TX";
  String body = "From:\n" + String(sender_pk) + "\nTo:\n" + String(recipient) + "\nAmt: " + String(amount) + "\nOK=Sign Down=No";
  drawScrollable(header, body);

  int decision = waitForDecision();
  if (decision != 1) { sendError(decision == -1 ? "user_rejected" : "timeout"); tlsClient.stop(); return; }

  if (!signAndRespond(msg_b64)) { sendError("sign_failed"); }
  tlsClient.stop();
}

void setup() {
  pinMode(BTN_UP, INPUT_PULLUP);
  pinMode(BTN_DOWN, INPUT_PULLUP);
  pinMode(BTN_OK, INPUT_PULLUP);
  u8g2.begin();
  drawCentered("Booting wallet...", 0);
  prefs.begin("wallet", false);
  if (!loadOrGenerateKey(prefs, ed25519_sk, ed25519_pk)) { drawCentered("Key error",0); while(true) delay(1000); }
  connectWiFi();
}

void loop() {
  serveOneRequest();
  delay(200);
}
