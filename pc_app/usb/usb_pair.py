# pc_app/usb/usb_pair.py
import os, sys, time, json, binascii, hashlib, hmac
import serial
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives import hashes


try:
    from Crypto.Cipher import AES
except Exception:
    print("[!] PyCryptodome required for AES (pip install pycryptodome)")
    sys.exit(1)

def sha256(data: bytes) -> bytes:
    return hashlib.sha256(data).digest()

def derive_aes_key(shared: bytes) -> bytes:
    salt = b"USBPAIRv1"
    info = b"AES-256-CTR"
    hkdf = HKDF(algorithm=hashes.SHA256(), length=32, salt=salt, info=info)
    return hkdf.derive(shared)

def open_serial(port: str, baud: int = 115200, timeout: float = 2.0) -> serial.Serial:
    ser = serial.Serial()
    ser.port = port
    ser.baudrate = baud
    ser.timeout = timeout
    ser.dtr = False   # prevent auto-reset before open
    ser.rts = False
    ser.open()
    time.sleep(1.5)
    ser.reset_input_buffer()
    return ser

def read_json_line(ser, timeout=10):
    start = time.time()
    buf = ""
    while time.time() - start < timeout:
        if ser.in_waiting:
            ch = ser.read().decode(errors="ignore")
            if ch == "\n":
                line = buf.strip()
                if line.startswith("{") and line.endswith("}"):
                    return json.loads(line)
                buf = ""
            else:
                buf += ch
        else:
            time.sleep(0.02)
    raise TimeoutError("No JSON response from ESP")


def run():
    port = input("Enter serial port (e.g., COM5 or /dev/ttyUSB0): ").strip()
    ser = open_serial(port)

    print("[*] Generating PC ECDH key (secp256r1)...")
    pc_priv = ec.generate_private_key(ec.SECP256R1())
    pc_pub  = pc_priv.public_key()
    pc_pub_uncompressed = pc_pub.public_bytes(Encoding.X962, PublicFormat.UncompressedPoint)  # 65 bytes
    pc_pub_hex = binascii.hexlify(pc_pub_uncompressed).decode().upper()

    # 1) Wait for USB_READY (no timeout)
    print("[*] Waiting for USB_READY...")
    while True:
        ln = ser.readline().decode(errors="ignore").strip()
        if not ln:
            continue
        print("[ESP]", ln)
        if "USB_READY" in ln:
            break

    # 2) Send PC public key
    send = json.dumps({"action":"pc_pub","pc_pub":pc_pub_hex})
    ser.write((send + "\n").encode())
    print("[PC] → Sent pc_pub")

    # 3) Receive wallet_pub + pairing code
    print("[*] Waiting for wallet_pub JSON from ESP...")
    resp = ""
    start = time.time()
    while time.time() - start < 15:
        line = ser.readline().decode(errors="ignore").strip()
        if not line:
            continue
        print("[ESP]", line)
        if line.startswith("{") and line.endswith("}"):
            resp = line
            break
    else:
        raise TimeoutError("No JSON from ESP after sending pc_pub")

    data = json.loads(resp)

    if data.get("status") != "ok" or "wallet_pub" not in data or "code" not in data:
        print("[!] Unexpected response:", data)
        return
    wallet_pub_hex = data["wallet_pub"]
    esp_code_str   = data["code"]

    # Compute same code on PC
    wallet_pub = binascii.unhexlify(wallet_pub_hex)
    # Shared secret
    peer_pub = ec.EllipticCurvePublicKey.from_encoded_point(ec.SECP256R1(), wallet_pub)
    shared = pc_priv.exchange(ec.ECDH(), peer_pub)  # 32 bytes

    # pair code = SHA256(shared || wallet_pub || pc_pub) % 1_000_000
    m = hashlib.sha256()
    m.update(shared); m.update(wallet_pub); m.update(pc_pub_uncompressed)
    code = int.from_bytes(m.digest()[:4], "big") % 1_000_000
    pc_code_str = f"{code:06d}"
    print(f"[PAIR CODE] ESP: {esp_code_str}  |  PC: {pc_code_str}")

    if pc_code_str != esp_code_str:
        print("[!] Pair codes mismatch. Aborting.")
        return

    print("[*] Waiting for ESP user decision (allow/deny)...")
    # ESP will print a user decision line; we just read the next line
    while True:
        ln = ser.readline().decode(errors="ignore").strip()
        if not ln:
            continue
        print("[ESP]", ln)
        try:
            jd = json.loads(ln)
            if jd.get("action")=="user" and jd.get("decision")=="allow":
                break
            if jd.get("action")=="user" and jd.get("decision") in ("deny","timeout"):
                print("[!] ESP denied/timed out.")
                return
        except Exception:
            continue

    # 4) Derive AES key
    aes_key = derive_aes_key(shared)
    print("[✔] Paired. AES-256 key derived.")

    # 5) Encrypted echo test
    iv = os.urandom(16)
    iv_hex = binascii.hexlify(iv).decode().upper()
    plain = "hello over usb (ECDH)"
    ser.write((json.dumps({"action":"enc_test","iv":iv_hex,"plain":plain})+"\n").encode())
    print("[PC] → Sent enc_test")

    ans = ser.readline().decode(errors="ignore").strip()
    print("[ESP]", ans or "<no response>")
    jd = json.loads(ans)
    if jd.get("status")!="ok" or "echo" not in jd:
        print("[!] Enc test failed:", jd); return

    cbytes = binascii.unhexlify(jd["echo"])
    cipher = AES.new(aes_key, AES.MODE_CTR, nonce=b"", initial_value=int.from_bytes(iv, "big"))
    dec = cipher.decrypt(cbytes)
    print("[OK] Decrypted echo:", dec.decode(errors="ignore"))
    print("[✔] USB ECDH/AES link verified.")

if __name__ == "__main__":
    run()
