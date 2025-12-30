#define SDA_PIN 21
#define SCL_PIN 22

void setup() {
  Serial.begin(115200);
  delay(1000);
  Serial.println("BOOT OK");
  delay(1000);

  pinMode(SDA_PIN, INPUT_PULLUP);
  pinMode(SCL_PIN, INPUT_PULLUP);
  delay(50);

  Serial.print("SDA level: "); Serial.println(digitalRead(SDA_PIN));
  Serial.print("SCL level: "); Serial.println(digitalRead(SCL_PIN));
}

void loop() {
  }
