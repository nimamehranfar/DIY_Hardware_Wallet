const int button1Pin = 15;
const int button2Pin = 16;
const int button3Pin = 17;
const int button4Pin = 18;

// Track previous states (for debouncing)
int lastButton1State = HIGH;
int lastButton2State = HIGH;
int lastButton3State = HIGH;
int lastButton4State = HIGH;

void setup() {
  Serial.begin(115200);

  // Set each button as input with pull-up resistor
  pinMode(button1Pin, INPUT_PULLUP);
  pinMode(button2Pin, INPUT_PULLUP);
  pinMode(button3Pin, INPUT_PULLUP);
  pinMode(button4Pin, INPUT_PULLUP);
}

void loop() {
  // Read states
  int button1State = digitalRead(button1Pin);
  int button2State = digitalRead(button2Pin);
  int button3State = digitalRead(button3Pin);
  int button4State = digitalRead(button4Pin);

  
  if (button1State == LOW && lastButton1State == HIGH) {
    //todo

    Serial.println("Button 1 pressed!");
    delay(200); // debounce
  }

  
  if (button2State == LOW && lastButton2State == HIGH) {
    //todo
    Serial.println("Button 2 pressed!");
    delay(200);
  }

  
  if (button3State == LOW && lastButton3State == HIGH) {
    //todo
    Serial.println("Button 3 pressed!");
    delay(200);
  }

  
  if (button4State == LOW && lastButton4State == HIGH) {
    //todo
    Serial.println("Button 4 pressed!");
    delay(200);
  }

  // Update previous states
  lastButton1State = button1State;
  lastButton2State = button2State;
  lastButton3State = button3State;
  lastButton4State = button4State;
}
