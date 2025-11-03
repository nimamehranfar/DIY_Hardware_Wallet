#ifndef PASSWORD_HANDLER_H
#define PASSWORD_HANDLER_H

#include <Adafruit_SSD1306.h>

constexpr int PIN_LENGTH = 4;

// Button pins (ESP32 safe)
const int buttonUpPin = 18;
const int buttonDownPin = 19;
const int buttonDelPin = 23;
const int buttonOkPin = 4;

// Hardcoded correct PIN
const int correctPin[PIN_LENGTH] = {1, 2, 3, 4};

int enteredPin[PIN_LENGTH] = {0};
int enteredDigits = 0;
int currentDigit = 0;

void showOLED(Adafruit_SSD1306 &display, const String &l1, const String &l2 = "", const String &l3 = "") {
  display.clearDisplay();
  display.setTextSize(2);
  display.setTextColor(SSD1306_WHITE);
  display.setCursor(0, 0);
  display.println(l1);
  if (l2.length()) display.println(l2);
  if (l3.length()) display.println(l3);
  display.display();
}

// Compare entered PIN with correct one
bool checkPin() {
  for (int i = 0; i < PIN_LENGTH; i++) {
    if (enteredPin[i] != correctPin[i]) return false;
  }
  return true;
}

// Display masked entry
void showEntry(Adafruit_SSD1306 &display) {
  String masked = "";
  for (int i = 0; i < enteredDigits; i++) masked += "*";
  for (int i = enteredDigits; i < PIN_LENGTH; i++) masked += "_";
  showOLED(display, "Digit:" + String(currentDigit), "PIN:" + masked);
}

// Full password handling loop
bool handlePassword(Adafruit_SSD1306 &display) {
  pinMode(buttonUpPin, INPUT_PULLUP);
  pinMode(buttonDownPin, INPUT_PULLUP);
  pinMode(buttonDelPin, INPUT_PULLUP);
  pinMode(buttonOkPin, INPUT_PULLUP);

  int lastUp = HIGH, lastDown = HIGH, lastDel = HIGH, lastOk = HIGH;
  enteredDigits = 0;
  currentDigit = 0;

  showOLED(display, "Enter PIN:");
  delay(600);
  showEntry(display);

  while (true) {
    int up = digitalRead(buttonUpPin);
    int down = digitalRead(buttonDownPin);
    int del = digitalRead(buttonDelPin);
    int ok = digitalRead(buttonOkPin);

    if (up == LOW && lastUp == HIGH) {
      currentDigit = (currentDigit + 1) % 10;
      showEntry(display);
      delay(200);
    }

    if (down == LOW && lastDown == HIGH) {
      currentDigit = (currentDigit - 1 + 10) % 10;
      showEntry(display);
      delay(200);
    }

    if (del == LOW && lastDel == HIGH) {
      if (enteredDigits > 0) {
        enteredDigits--;
        enteredPin[enteredDigits] = 0;
      }
      showEntry(display);
      delay(200);
    }

    if (ok == LOW && lastOk == HIGH) {
      if (enteredDigits < PIN_LENGTH) {
        enteredPin[enteredDigits] = currentDigit;
        enteredDigits++;
        showEntry(display);
      }

      if (enteredDigits == PIN_LENGTH) {
        bool correct = checkPin();
        if (correct) {
          showOLED(display, "Correct!", "", "");
          delay(1000);
          return true;
        } else {
          showOLED(display, "Wrong PIN!", "Try again");
          delay(1200);
          enteredDigits = 0;
          currentDigit = 0;
          for (int i = 0; i < PIN_LENGTH; i++) enteredPin[i] = 0;
          showEntry(display);
        }
      }
      delay(200);
    }

    lastUp = up;
    lastDown = down;
    lastDel = del;
    lastOk = ok;
  }
}

#endif
