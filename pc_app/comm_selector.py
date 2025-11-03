import os
import sys
import json
import time
import binascii
import hashlib
import hmac
import importlib

from Crypto.Cipher import AES

# -------------------------------------------------------------------
# Helper: shared SHA256 and HMAC
# -------------------------------------------------------------------
def sha256_bytes(data: bytes) -> bytes:
    return hashlib.sha256(data).digest()

def hmac_sha256(key: bytes, msg: bytes) -> bytes:
    return hmac.new(key, msg, hashlib.sha256).digest()

# -------------------------------------------------------------------
#  Wi-Fi (TLS) communication path
# -------------------------------------------------------------------
def run_wifi():
    print("[*] Starting Wi-Fi TLS server ...")
    try:
        mod = importlib.import_module("pc_app.tls.tls_server")
        mod.main()
    except Exception as e:
        print("[!] Wi-Fi server crashed:", e)

# -------------------------------------------------------------------
#  USB communication path
# -------------------------------------------------------------------
def run_usb():
    import serial

    port = input("Enter serial port (e.g., COM5 or /dev/ttyUSB0): ").strip()
    baud = 115200
    pin  = input("Enter device PIN (digits only): ").strip()
    seed = input("Enter any number (seed): ").strip()

    # Derive key = SHA256( "<pin>:<seed>" )
    key = sha256_bytes(f"{pin}:{seed}".encode())

    print(f"[*] Opening serial port {port} ...")
    ser = serial.Serial(port, baudrate=baud, timeout=2)
    # Prevent ESP32 from resetting when port opens
    ser.setDTR(False)
    ser.setRTS(False)
    ser.open()
    time.sleep(2)

    # ----------------------------------------------------------------
    # Step 1: Wait for ESP32 to announce readiness
    # ----------------------------------------------------------------
    print("[*] Waiting for USB_READY from ESP32...")
    ready = False
    start = time.time()
    while time.time() - start < 10:
        line = ser.readline().decode(errors="ignore").strip()
        if not line:
            continue
        print("[ESP]", line)
        if "USB_READY" in line:
            ready = True
            break

    if not ready:
        print("[!] Timeout: ESP32 didn’t send USB_READY.")
        ser.close()
        return

    # ----------------------------------------------------------------
    # Step 2: Send pairing message with HMAC proof
    # ----------------------------------------------------------------
    proof = hmac_sha256(key, b"ESP32_PROOF")
    proof_hex = binascii.hexlify(proof).decode().upper()
    pair_msg = json.dumps({"action": "pair", "seed": seed, "proof": proof_hex})
    ser.write((pair_msg + "\n").encode())
    print("[PC] → Sent pairing request")

    # Wait for pairing response
    resp = ser.readline().decode(errors="ignore").strip()
    print("[ESP]", resp or "<no response>")
    if not resp:
        print("[!] No response from ESP32 during pairing.")
        ser.close()
        return
    try:
        data = json.loads(resp)
    except json.JSONDecodeError:
        print("[!] Invalid JSON from ESP32.")
        ser.close()
        return
    if not (data.get("status") == "ok" and data.get("phase") == "paired"):
        print("[!] Pairing failed:", data)
        ser.close()
        return
    print("[✔] Pairing successful.")

    # ----------------------------------------------------------------
    # Step 3: Send encrypted test message
    # ----------------------------------------------------------------
    iv = os.urandom(16)
    iv_hex = binascii.hexlify(iv).decode().upper()
    plain = "hello over usb"

    enc_msg = json.dumps({
        "action": "enc_test",
        "iv": iv_hex,
        "plain": plain
    })
    ser.write((enc_msg + "\n").encode())
    print("[PC] → Sent enc_test message")

    # Wait for encrypted echo
    resp2 = ser.readline().decode(errors="ignore").strip()
    print("[ESP]", resp2 or "<no response>")
    if not resp2:
        print("[!] No echo from ESP32.")
        ser.close()
        return

    try:
        data2 = json.loads(resp2)
    except json.JSONDecodeError:
        print("[!] Invalid JSON in echo.")
        ser.close()
        return

    if data2.get("status") != "ok" or "echo" not in data2:
        print("[!] Enc test failed:", data2)
        ser.close()
        return

    # ----------------------------------------------------------------
    # Step 4: Decrypt echo and verify
    # ----------------------------------------------------------------
    try:
        cbytes = binascii.unhexlify(data2["echo"])
        cipher = AES.new(key, AES.MODE_CTR, nonce=b"", initial_value=int.from_bytes(iv, "big"))
        dec = cipher.decrypt(cbytes)
        print("[OK] Decrypted echo:", dec.decode(errors="ignore"))
    except Exception as e:
        print("[!] AES decryption failed:", e)
        return

    ser.close()
    print("[✔] USB communication successful.")

# -------------------------------------------------------------------
#  Selector entry point
# -------------------------------------------------------------------
def main():
    print("=== Communication Selector ===")
    method = input("Select communication method [usb / wifi]: ").strip().lower()
    if method == "wifi":
        run_wifi()
    elif method == "usb":
        run_usb()
    else:
        print("Unknown method.")

# -------------------------------------------------------------------
if __name__ == "__main__":
    main()
