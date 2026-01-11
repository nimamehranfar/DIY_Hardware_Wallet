#ifndef TLS_CLIENT_H
#define TLS_CLIENT_H

#include <WiFi.h>
#include <WiFiClientSecure.h>
#include "rootCA.h"
#include <Adafruit_SSD1306.h>

// const char* WIFI_SSID = "Redmi Note 11 Pro 5G";
// const char* WIFI_PASS = "NM25ya26";
// const char* SERVER_HOST = "10.155.149.133";
const char* WIFI_SSID = "iPhone";
const char* WIFI_PASS = "Ahmad123";
const char* SERVER_HOST = "172.20.10.10";
const uint16_t SERVER_PORT = 8443;

WiFiClientSecure client;

void waitForWiFi(Adafruit_SSD1306 &display) {
  showOLED(display, "Connecting", "WiFi...");
  WiFi.begin(WIFI_SSID, WIFI_PASS);
  while (WiFi.status() != WL_CONNECTED) {
    delay(500);
  }
  showOLED(display, "WiFi OK!", WiFi.localIP().toString());
}

WiFiClientSecure* connectTLS(Adafruit_SSD1306 &display) {
  WiFi.mode(WIFI_STA);
  WiFi.begin(WIFI_SSID, WIFI_PASS);

  showOLED(display, "Connecting", "WiFi...");
  int tries = 0;
  while (WiFi.status() != WL_CONNECTED && tries < 40) {
    delay(500);
    tries++;
  }
  if (WiFi.status() != WL_CONNECTED) {
    showOLED(display, "WiFi Failed!");
    return nullptr;
  }

  showOLED(display, "WiFi OK!", WiFi.localIP().toString());
  delay(500);


  // Serial.println(WiFi.localIP());
  // Serial.printf("Testing raw TCP to %s:%d\n", SERVER_HOST, SERVER_PORT);
  // WiFiClient test;
  // if (!test.connect(SERVER_HOST, SERVER_PORT, 3000)) {
  //   Serial.println("❌ TCP connect failed (no route or blocked port)");
  //   showOLED(display, "TCP blocked!");
  //   return false;
  // }
  // Serial.println("✅ TCP reachable, continuing...");
  // test.stop();



  client.setCACert(ROOT_CA);

  for (int attempt = 0; attempt < 15; attempt++) {
    showOLED(display, "TLS connect", SERVER_HOST);
    if (!client.connect(SERVER_HOST, SERVER_PORT)) {
      showOLED(display, "TLS Failed!", "Retry...");
      delay(2000);
      continue;
    }

    // --- handshake ---
    client.println("{\"action\":\"ping\"}");
    unsigned long start = millis();
    while (!client.available() && millis() - start < 3000) delay(10);

    if (!client.available()) {
      showOLED(display, "No pong", "Retry...");
      client.stop();
      delay(1500);
      continue;
    }

    String reply = client.readStringUntil('\n');
    if (reply.indexOf("pong") == -1) {
      showOLED(display, "Bad pong", reply);
      client.stop();
      delay(1500);
      continue;
    }

    showOLED(display, "Handshake OK");
    delay(500);

    // --- transmit data (example: pubkey) ---
    String jsonMsg = "{\"action\":\"pubkey\",\"pubkey\":\"A1B2C3D4E5F6G7H8\"}";
    client.println(jsonMsg);
    client.flush();   // force bytes out
    showOLED(display, "Sent pubkey...");
    delay(200);       // give TCP buffer time before reading

    // wait for response
    unsigned long t0 = millis();
    while (!client.available() && millis() - t0 < 4000) delay(10);

    if (client.available()) {
      String resp = client.readStringUntil('\n');
      showOLED(display, "Server:", resp);
      delay(2000);
      client.stop();
      return &client;
    } else {
      showOLED(display, "No reply", "Retry...");
      client.stop();
      delay(3000);
    }
  }

  showOLED(display, "TLS Failed", "Aborting");
  return nullptr;
}



#endif
