#pragma once
#include <U8g2lib.h>
#include <Arduino.h>
#include "qrcode.h"
extern U8G2_SSD1306_128X64_NONAME_F_HW_I2C u8g2;
extern const int BTN_OK;
extern const int BTN_DOWN;

// Display splash screen with logo matching mobile app
inline void showSplashScreen(int durationMs = 2000) {
  u8g2.clearBuffer();
  
  // Logo based on mobile app SVG (scaled for 128x64 OLED)
  // Original viewBox: 0 0 512 512, scale factor ~0.1
  int ox = 20;  // x offset to center logo on left side
  int oy = -2;  // y offset
  
  // Steam lines (2 wavy curves above cup)
  // Steam 1: M270 20 -> curves up
  u8g2.drawLine(ox + 27, oy + 2, ox + 26, oy + 5);
  u8g2.drawLine(ox + 26, oy + 5, ox + 28, oy + 8);
  u8g2.drawLine(ox + 28, oy + 8, ox + 27, oy + 11);
  
  // Steam 2: M230 40 -> curves up  
  u8g2.drawLine(ox + 23, oy + 4, ox + 22, oy + 7);
  u8g2.drawLine(ox + 22, oy + 7, ox + 24, oy + 10);
  u8g2.drawLine(ox + 24, oy + 10, ox + 23, oy + 13);
  
  // Cup body (rectangle with rounded bottom)
  // M160 210 L352 210 -> top edge at y=21
  u8g2.drawHLine(ox + 16, oy + 21, 20);  // Top rim
  // Sides and rounded bottom
  u8g2.drawVLine(ox + 16, oy + 21, 15);  // Left side
  u8g2.drawVLine(ox + 35, oy + 21, 15);  // Right side
  // Bottom curve
  u8g2.drawLine(ox + 16, oy + 36, ox + 20, oy + 40);
  u8g2.drawHLine(ox + 20, oy + 40, 12);
  u8g2.drawLine(ox + 32, oy + 40, ox + 35, oy + 36);
  
  // Handle (arc on right side)
  // M352 240 C400 240 420 260 420 290 C420 320 400 340 352 340
  u8g2.drawCircle(ox + 40, oy + 29, 6, U8G2_DRAW_UPPER_RIGHT | U8G2_DRAW_LOWER_RIGHT);
  
  // Saucer (curved line below cup)
  // M120 410 Q256 470 392 410
  u8g2.drawLine(ox + 10, oy + 44, ox + 18, oy + 48);
  u8g2.drawHLine(ox + 18, oy + 48, 16);
  u8g2.drawLine(ox + 34, oy + 48, ox + 42, oy + 44);
  
  // Shadow curve (lighter, smaller arc below saucer)
  u8g2.drawLine(ox + 14, oy + 50, ox + 20, oy + 52);
  u8g2.drawHLine(ox + 20, oy + 52, 12);
  u8g2.drawLine(ox + 32, oy + 52, ox + 38, oy + 50);
  
  // Brand name "espresSol" on right side
  u8g2.setFont(u8g2_font_9x15B_tf);
  u8g2.drawStr(58, 35, "espres");
  u8g2.drawStr(58, 52, "Sol");
  
  u8g2.sendBuffer();
  delay(durationMs);
}

// Display a QR code on the OLED (version 3 = 29x29 modules)
inline void drawQRCode(const char* data) {
  QRCode qrcode;
  uint8_t qrcodeData[qrcode_getBufferSize(3)];
  qrcode_initText(&qrcode, qrcodeData, 3, ECC_LOW, data);
  
  u8g2.clearBuffer();
  
  // Scale = 2 pixels per module, QR size = 29*2 = 58 pixels
  // Center on 128x64 display: x offset = (128-58)/2 = 35, y offset = (64-58)/2 = 3
  int scale = 2;
  int qrSize = qrcode.size * scale;
  int xOffset = (128 - qrSize) / 2;
  int yOffset = (64 - qrSize) / 2;
  
  for (int y = 0; y < qrcode.size; y++) {
    for (int x = 0; x < qrcode.size; x++) {
      if (qrcode_getModule(&qrcode, x, y)) {
        u8g2.drawBox(xOffset + x * scale, yOffset + y * scale, scale, scale);
      }
    }
  }
  u8g2.sendBuffer();
}

// Display QR code for IP:port pairing
inline void displayIPQRCode(const String& ipWithPort) {
  drawQRCode(ipWithPort.c_str());
}

inline void drawCentered(const char* msg, int yOffset) {
  u8g2.clearBuffer();
  u8g2.setFont(u8g2_font_9x15_tf);
  int width = u8g2.getUTF8Width(msg);
  int x = (128 - width) / 2;
  int y = (64 - 15) / 2 + yOffset;
  if (x < 0) x = 0;
  u8g2.drawUTF8(x, y, msg);
  u8g2.sendBuffer();
}

inline void drawScrollable(const String& title, const String& body) {
  u8g2.clearBuffer();
  u8g2.setFont(u8g2_font_9x15_tf);
  const int lineH = 16;
  String lines[64];
  int L=0;
  String cur;
  for (size_t k=0;k<body.length();++k) {
    char c = body[k];
    if (c=='\n' || cur.length()>=20) {
      lines[L++] = cur; cur="";
      if (c=='\n') continue;
    }
    cur += c;
  }
  if (cur.length()) lines[L++] = cur;
  int idx=0;
  while (idx < L) {
    u8g2.clearBuffer();
    u8g2.drawUTF8(0,0,title.c_str());
    int y=lineH;
    for (int j=0;j<3 && (idx+j)<L;++j) {
      u8g2.drawUTF8(0,y,lines[idx+j].c_str());
      y+=lineH;
    }
    u8g2.sendBuffer();
    delay(900);
    idx+=3;
  }
}

inline int waitForDecision() {
  Serial.println("[BTN] Waiting for button press (OK=approve, DOWN=reject)...");
  Serial.print("[BTN] GPIO OK="); Serial.print(BTN_OK);
  Serial.print(" DOWN="); Serial.println(BTN_DOWN);
  
  unsigned long t0 = millis(), T=20000;
  int lastPrint = 0;
  while (millis()-t0 < T) {
    int okState = digitalRead(BTN_OK);
    int downState = digitalRead(BTN_DOWN);
    
    // Print button states every 2 seconds
    if ((millis()-t0)/2000 > lastPrint) {
      lastPrint = (millis()-t0)/2000;
      Serial.print("[BTN] OK="); Serial.print(okState);
      Serial.print(" DOWN="); Serial.print(downState);
      Serial.print(" (press LOW to activate, "); 
      Serial.print(20 - (millis()-t0)/1000); Serial.println("s left)");
    }
    
    if (okState == LOW) {
      Serial.println("[BTN] OK pressed - APPROVED!");
      return 1;
    }
    if (downState == LOW) {
      Serial.println("[BTN] DOWN pressed - REJECTED!");
      return -1;
    }
    delay(40);
  }
  Serial.println("[BTN] TIMEOUT - no button pressed in 20 seconds");
  return 0;
}
