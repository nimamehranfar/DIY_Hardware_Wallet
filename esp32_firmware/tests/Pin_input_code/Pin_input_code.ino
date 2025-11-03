#include <Wire.h>
#include <Adafruit_GFX.h>
#include <Adafruit_SSD1306.h>

// --- OLED Setup ---
#define OLED_ADDR      0x3C
#define SCREEN_WIDTH   128
#define SCREEN_HEIGHT  64
Adafruit_SSD1306 display(SCREEN_WIDTH, SCREEN_HEIGHT, &Wire, -1);

// --- Button Pin Assignments (right side of ESP32 DevKit) ---
const int buttonUpPin = 18;     // +1 digit
const int buttonDownPin = 19;   // -1 digit
const int buttonDelPin = 23;    // delete
const int buttonOkPin = 4;     // confirm

// --- Button State Tracking ---
int lastUp = HIGH, lastDown = HIGH, lastDel = HIGH, lastOk = HIGH;

// --- PIN Configuration ---
const int PIN_LENGTH = 4;
int enteredPin[PIN_LENGTH] = {0};
int enteredDigits = 0;
int currentDigit = 0;
bool pinSaved = false;

// --- Final Saved PIN ---
int savedPin[PIN_LENGTH] = {0};

// --- Utility Function to Show OLED Text ---
void showOLED(const String &l1, const String &l2 = "", const String &l3 = "") {
  display.clearDisplay();
  display.setTextSize(2);
  display.setTextColor(SSD1306_WHITE);
  display.setCursor(0, 0);
  display.println(l1);
  if (l2.length()) display.println(l2);
  if (l3.length()) display.println(l3);
  display.display();
}

// --- Setup ---
void setup() {
  Wire.begin(21, 22); // SDA=21, SCL=22 for OLED
  display.begin(SSD1306_SWITCHCAPVCC, OLED_ADDR);

  pinMode(buttonUpPin, INPUT_PULLUP);
  pinMode(buttonDownPin, INPUT_PULLUP);
  pinMode(buttonDelPin, INPUT_PULLUP);
  pinMode(buttonOkPin, INPUT_PULLUP);

  showOLED("Enter PIN:");
  delay(500);
  showCurrentDigit();
}

// --- Main Loop ---
void loop() {
  handleButtons();
}

// --- Button Handling ---
void handleButtons() {
  int up = digitalRead(buttonUpPin);
  int down = digitalRead(buttonDownPin);
  int del = digitalRead(buttonDelPin);
  int ok = digitalRead(buttonOkPin);

  // Increment digit
  if (up == LOW && lastUp == HIGH) {
    currentDigit = (currentDigit + 1) % 10;
    showCurrentDigit();
    delay(200);
  }

  // Decrement digit
  if (down == LOW && lastDown == HIGH) {
    currentDigit = (currentDigit - 1 + 10) % 10;
    showCurrentDigit();
    delay(200);
  }

  // Delete last digit
  if (del == LOW && lastDel == HIGH) {
    deleteLastDigit();
    delay(200);
  }

  // Confirm (add digit or save)
  if (ok == LOW && lastOk == HIGH) {
    confirmDigit();
    delay(400);
  }

  // Update last states
  lastUp = up;
  lastDown = down;
  lastDel = del;
  lastOk = ok;
}

// --- Show Current State on OLED ---
void showCurrentDigit() {
  String entered = "";
  for (int i = 0; i < enteredDigits; i++) entered += String(enteredPin[i]);
  showOLED("Digit:", String(currentDigit), "PIN:" + entered);
}

// --- Delete Last Digit ---
void deleteLastDigit() {
  if (enteredDigits > 0) {
    enteredDigits--;
    enteredPin[enteredDigits] = 0;
  }
  showCurrentDigit();
}

// --- Confirm/Add Digit or Save PIN ---
void confirmDigit() {
  if (enteredDigits < PIN_LENGTH) {
    enteredPin[enteredDigits] = currentDigit;
    enteredDigits++;
    showCurrentDigit();
  }

  if (enteredDigits == PIN_LENGTH && !pinSaved) {
    // Save the PIN
    for (int i = 0; i < PIN_LENGTH; i++) savedPin[i] = enteredPin[i];
    pinSaved = true;
    showSavedPin();
    delay(2000);
    resetPin();
  }
}

// --- Show Saved PIN ---
void showSavedPin() {
  String pinString = "";
  for (int i = 0; i < PIN_LENGTH; i++) pinString += String(savedPin[i]);
  showOLED("PIN Saved!", "", pinString);
}

// --- Reset Entry ---
void resetPin() {
  for (int i = 0; i < PIN_LENGTH; i++) enteredPin[i] = 0;
  enteredDigits = 0;
  currentDigit = 0;
  showOLED("Enter PIN:");
  delay(500);
  showCurrentDigit();
}
