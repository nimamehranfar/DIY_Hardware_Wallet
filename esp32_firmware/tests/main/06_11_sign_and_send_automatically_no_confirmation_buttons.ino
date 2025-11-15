#include <Arduino.h>
#include <Ed25519.h>
#include <Preferences.h>

// Base58 alphabet (Solana-compatible)
const char *BASE58_ALPHABET = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz";

Preferences prefs;
uint8_t privateKey[32];
uint8_t publicKey[32];

String base58Encode(const uint8_t *data, size_t len) {
  // Count leading zeroes
  int zeroes = 0;
  while (zeroes < len && data[zeroes] == 0) zeroes++;

  // Copy input into a mutable buffer
  uint8_t buf[len * 2];
  memcpy(buf, data, len);

  int j = 0;
  size_t start = zeroes;
  char temp[len * 2];
  int tempLen = 0;

  while (start < len) {
    int carry = 0;
    for (size_t i = start; i < len; i++) {
      int val = ((int)buf[i] & 0xFF);
      int x = (carry << 8) + val;
      buf[i] = x / 58;
      carry = x % 58;
    }

    if (buf[start] == 0) start++;
    temp[tempLen++] = BASE58_ALPHABET[carry];
  }

  String result = "";
  for (int i = 0; i < zeroes; i++) result += '1';
  for (int i = tempLen - 1; i >= 0; i--) result += temp[i];
  return result;
}

void generateOrLoadKeys() {
  prefs.begin("wallet", false);
  if (prefs.getBytesLength("priv") == 32) {
    prefs.getBytes("priv", privateKey, 32);
    Ed25519::derivePublicKey(publicKey, privateKey);
    Serial.println("[OK] Loaded existing keypair from flash.");
  } else {
    Ed25519::generatePrivateKey(privateKey);
    Ed25519::derivePublicKey(publicKey, privateKey);
    prefs.putBytes("priv", privateKey, 32);
    Serial.println("[OK] Generated and stored new keypair.");
  }
  prefs.end();
}

void handleCommand(String cmd) {
  cmd.trim();
  if (cmd == "PUBKEY") {
    String pk58 = base58Encode(publicKey, 32);
    Serial.println(pk58);
  } else if (cmd.startsWith("SIGN:")) {
    String hexMsg = cmd.substring(5);
    size_t msgLen = hexMsg.length() / 2;
    uint8_t *msg = (uint8_t*)malloc(msgLen);
    for (size_t i = 0; i < msgLen; i++)
      msg[i] = strtoul(hexMsg.substring(i*2, i*2+2).c_str(), nullptr, 16);

    uint8_t sig[64];
    Ed25519::sign(sig, privateKey, publicKey, msg, msgLen);
    String sig58 = base58Encode(sig, 64);
    Serial.println(sig58);
    free(msg);
  } else {
    Serial.println("[ERR] Unknown command");
  }
}

void setup() {
  Serial.begin(115200);
  while (!Serial) delay(10);
  Serial.println("== Solana ESP32 Signer ==");
  generateOrLoadKeys();
  Serial.println("Ready. Commands: PUBKEY / SIGN:<hex>");
}

void loop() {
  if (Serial.available()) {
    String line = Serial.readStringUntil('\n');
    handleCommand(line);
  }
}
