#pragma once
#include <U8g2lib.h>
#include <Arduino.h>
extern U8G2_SSD1306_128X64_NONAME_F_HW_I2C u8g2;
extern const int BTN_OK;
extern const int BTN_DOWN;

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
  unsigned long t0 = millis(), T=20000;
  while (millis()-t0 < T) {
    if (digitalRead(BTN_OK)==LOW) return 1;
    if (digitalRead(BTN_DOWN)==LOW) return -1;
    delay(40);
  }
  return 0;
}
