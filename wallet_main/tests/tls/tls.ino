#include <WiFi.h>
#include <WiFiClientSecure.h>
#include "rootCA.h"

const char* WIFI_SSID = "iPhone";     // Rename hotspot to remove apostrophe
const char* WIFI_PASS = "Ahmad123";

const char* SERVER_HOST = "172.20.10.10";  // PC default IP
const uint16_t SERVER_PORT = 8443;

WiFiClientSecure client;

void setup() {
  Serial.begin(9600);
  delay(1000);
  Serial.println("\nBooting...");

  Serial.print("Connecting to WiFi: ");
  Serial.println(WIFI_SSID);
  WiFi.begin(WIFI_SSID, WIFI_PASS);

  int retries = 0;
  while (WiFi.status() != WL_CONNECTED && retries < 20) {
    Serial.print(".");
    delay(500);
    retries++;
  }
  if (WiFi.status() != WL_CONNECTED) {
    Serial.println("\n❌ WiFi Failed!");
    return;
  }

  Serial.println("\n✅ WiFi Connected!");
  Serial.print("IP Address: ");
  Serial.println(WiFi.localIP());
  Serial.println(WiFi.gatewayIP());
  Serial.println(WiFi.subnetMask());
  IPAddress serverIP;
  if (WiFi.hostByName("NM.local", serverIP)) {
    Serial.print("Resolved NM.local to: ");
    Serial.println(serverIP);
  } else {
    Serial.println("Failed to resolve NM.local");
  }

  // ✅ Use Root CA from file
  client.setCACert(ROOT_CA);

  Serial.println("Connecting via TLS...");
  if (!client.connect(SERVER_HOST, SERVER_PORT)) {
    Serial.println("❌ TLS Connection Failed!");
    return;
  }

  Serial.println("✅ TLS Connection Success!");
  client.println("hello");

  Serial.println("Waiting for server response...");
  unsigned long start = millis();
  while (!client.available() && millis() - start < 3000) {  // wait up to 3 seconds
    delay(10);
  }

  if (client.available()) {
    String line = client.readStringUntil('\n');
    Serial.print("Server says: ");
    Serial.println(line);
  } else {
    Serial.println("⚠ No response from server.");
  }
}

void loop() {}