#include <Wire.h>
#include <Adafruit_GFX.h>
#include <Adafruit_SSD1306.h>
#include "PasswordHandler.h"
#include "TLSClient.h"
// #include "USBComm.h"
#include "USBComm_ECDH.h"

#define OLED_ADDR 0x3C
#define SCREEN_WIDTH 128
#define SCREEN_HEIGHT 64

Adafruit_SSD1306 display(SCREEN_WIDTH, SCREEN_HEIGHT, &Wire, -1);

enum Transport { TRANS_USB=0, TRANS_WIFI=1 };

static void oledMenu(Transport choice) {
  display.clearDisplay();
  display.setTextSize(2);
  display.setTextColor(SSD1306_WHITE);
  display.setCursor(0,0);
  display.println("Select I/O:");
  display.setTextSize(2);

  // highlight with '>' on current choice
  display.setCursor(0, 24);
  display.print(choice == TRANS_USB  ? "> USB "  : "  USB ");
  display.setCursor(0, 44);
  display.print(choice == TRANS_WIFI ? "> WiFi"  : "  WiFi");

  display.display();
}

// Uses same buttons as PasswordHandler: Up(18) Down(19) Del(23) Ok(4)
static Transport selectTransport() {
  pinMode(18, INPUT_PULLUP);  // Up = +1 digit in PIN handler
  pinMode(19, INPUT_PULLUP);  // Down = -1 digit
  pinMode(23, INPUT_PULLUP);  // Delete = "deny/cancel"
  pinMode(4 , INPUT_PULLUP);  // Confirm

  Transport choice = TRANS_USB;   // default
  oledMenu(choice);

  int lastUp=HIGH, lastDown=HIGH, lastDel=HIGH, lastOk=HIGH;
  for (;;) {
    int up   = digitalRead(18);
    int down = digitalRead(19);
    int del  = digitalRead(23);
    int ok   = digitalRead(4);

    if (up==LOW && lastUp==HIGH) {
      choice = (choice==TRANS_USB) ? TRANS_WIFI : TRANS_USB;
      oledMenu(choice);
      delay(200);
    }
    if (down==LOW && lastDown==HIGH) {
      choice = (choice==TRANS_USB) ? TRANS_WIFI : TRANS_USB;
      oledMenu(choice);
      delay(200);
    }
    // Delete works as quick-cancel: return USB (you can change if you prefer)
    if (del==LOW && lastDel==HIGH) {
      choice = TRANS_USB;
      oledMenu(choice);
      delay(200);
    }
    if (ok==LOW && lastOk==HIGH) {
      return choice;
    }

    lastUp=up; lastDown=down; lastDel=del; lastOk=ok;
    delay(10);
  }
}

void setup() {
  Serial.begin(115200);              // for USB mode as well
  Wire.begin(21, 22);                // OLED on ESP32 I2C
  display.begin(SSD1306_SWITCHCAPVCC, OLED_ADDR);

  showOLED(display, "System Booting...");
  delay(800);

  // 1) Verify PIN (existing handler)
  bool accessGranted = handlePassword(display);
  if (!accessGranted) {
    showOLED(display, "Access Denied!");
    while (true) delay(1000);
  }

  // 2) Select transport
  showOLED(display, "Choose I/O...");
  delay(500);
  Transport t = selectTransport();

  // 3) Run transport
  if (t==TRANS_WIFI) {
    showOLED(display, "WiFi selected");
    bool ok = connectTLS(display);
    showOLED(display, ok? "TLS OK":"TLS Failed");
  } else {
    showOLED(display, "USB selected");
    bool ok = runUSBECDH(display);   // NEW secure ECDH path
    showOLED(display, ok? "USB OK":"USB error");
  }
}

void loop() {
  // your next application stage can go here after transport setup
}
