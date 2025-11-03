import os, sys, base64, json, time
import serial
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

# --- Adjust your serial port ---
SERIAL_PORT = "COM5"   # or /dev/ttyUSB0 on Linux
BAUD = 115200
TIMEOUT = 0.2

# PSK must be identical to the one in USBComm.h
PSK = bytes([
    0x41,0x79,0x23,0x77,0xC2,0x56,0x19,0xAD,
    0xBE,0x99,0x10,0x72,0x33,0x45,0xFE,0xA1,
    0x91,0x2B,0xC7,0xDD,0xE8,0x09,0x5A,0x3C,
    0x77,0xAB,0xD4,0xEE,0x19,0x88,0xC0,0x55
])

def b64e(b: bytes) -> str:
    return base64.b64encode(b).decode()

def b64d(s: str) -> bytes:
    return base64.b64decode(s.encode())

def decrypt_frame(frame: str) -> str:
    obj = json.loads(frame)
    nonce = b64d(obj["nonce"])
    ct    = b64d(obj["ct"])
    tag   = b64d(obj["tag"])
    # cryptography AESGCM expects ct+tag concatenated
    data = ct + tag
    aes = AESGCM(PSK)
    pt = aes.decrypt(nonce, data, None)
    return pt.decode()

def encrypt_frame(plaintext: str) -> str:
    aes = AESGCM(PSK)
    nonce = os.urandom(12)
    data = aes.encrypt(nonce, plaintext.encode(), None)  # returns ct+tag
    ct, tag = data[:-16], data[-16:]
    obj = {
        "nonce": b64e(nonce),
        "ct":    b64e(ct),
        "tag":   b64e(tag),
    }
    return json.dumps(obj) + "\n"

def main():
    print(f"[*] USB AES-GCM server on {SERIAL_PORT} @ {BAUD}")
    with serial.Serial(SERIAL_PORT, BAUD, timeout=TIMEOUT) as ser:
        buf = ""
        while True:
            try:
                chunk = ser.read(1024)
                if chunk:
                    buf += chunk.decode(errors="ignore")
                    # process complete lines
                    while "\n" in buf:
                        line, buf = buf.split("\n", 1)
                        line = line.strip()
                        if not line:
                            continue
                        try:
                            msg = decrypt_frame(line)
                            print("[<] ESP:", msg)
                            # Example: respond success
                            if '"action":"pubkey"' in msg:
                                reply = '{"status":"ok","saved":true}'
                            else:
                                reply = '{"status":"pong"}'
                            frame = encrypt_frame(reply)
                            ser.write(frame.encode())
                            ser.flush()
                            print("[>] PC :", reply)
                        except Exception as ex:
                            print("[!] Decrypt/parse error:", ex)
                else:
                    time.sleep(0.02)
            except KeyboardInterrupt:
                print("\n[!] Stopping.")
                break

if __name__ == "__main__":
    main()
