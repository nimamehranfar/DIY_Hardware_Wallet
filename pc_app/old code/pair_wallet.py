import os

import serial, time, json, binascii, sys
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives import serialization, hashes

SERIAL_PORT = "COM5"  # change for your system
BAUD_RATE = 115200
CONFIG = "config.json"


def load_old():
    if not os.path.exists(CONFIG):
        return None
    with open(CONFIG) as f:
        return json.load(f)


def read_until(ser, marker):
    while True:
        line = ser.readline().decode(errors='ignore').strip()
        if not line:
            continue
        if line == marker:
            return


def read_line(ser):
    return ser.readline().decode(errors='ignore').strip()


def main(SERIAL_PORT = "COM5",BAUD_RATE = 115200,CONFIG = "config.json"):
    ser = serial.Serial(SERIAL_PORT, BAUD_RATE, timeout=1)
    time.sleep(2)  # allow ESP32 USB reset
    ser.reset_input_buffer()

    # Disable DTR/RTS so ESP32 doesn't auto-reset
    ser.setDTR(False)
    ser.setRTS(False)
    while True:
        cfg = load_old()
        print("Waiting for wallet to connect...")
        # Read wallet public key (64-byte hex, no 0x04)
        read_until(ser, "WALLET_PUB_BEGIN")
        wallet_pub_hex = read_line(ser)
        # next should be WALLET_PUB_END
        _ = read_line(ser)

        wallet_pub_raw = binascii.unhexlify(wallet_pub_hex)
        if len(wallet_pub_raw) != 64:
            print("Invalid wallet public key length")
            # sys.exit(1)
        else:
            # Build uncompressed point: 0x04 || X(32) || Y(32)
            wallet_pub65 = b'\x04' + wallet_pub_raw

            if cfg:
                if cfg["wallet_public_key_uncompressed_hex"] == wallet_pub65.hex().upper():
                    pc_pub_hex=cfg["pc_public_key_uncompressed_hex"]

                    ser.write(b"PC_PUB_BEGIN\r\n")
                    ser.write(pc_pub_hex[2:].encode() + b"\r\n")

                    read_until(ser, "PAIRING_APPROVAL")
                    approval = read_line(ser)
                    read_line(ser)

                    if approval == "PAIRING_APPROVAL_APPROVED":
                        print("Auto-paired OK")
                        return cfg["shared_secret_hex"]
                    else:
                        print("Auto-pair denied")
                        if os.path.exists(CONFIG):
                            os.remove(CONFIG)
                        continue
                else:
                    print(cfg["wallet_public_key_uncompressed_hex"])
                    print("Keys did not match")
                    print(wallet_pub65.hex().upper())
                    if os.path.exists(CONFIG):
                        os.remove(CONFIG)
                    continue
            # Generate PC keypair
            pc_private = ec.generate_private_key(ec.SECP256R1())
            pc_public = pc_private.public_key()
            pc_public_bytes65 = pc_public.public_bytes(
                encoding=serialization.Encoding.X962,
                format=serialization.PublicFormat.UncompressedPoint
            )
            # Send only 64 bytes (skip the first 0x04)
            ser.write(b"PC_PUB_BEGIN\r\n")
            ser.write(binascii.hexlify(pc_public_bytes65[1:]) + b"\r\n")
            ser.flush()

            # Compute shared secret using wallet's public key
            wallet_pub_key = ec.EllipticCurvePublicKey.from_encoded_point(ec.SECP256R1(), wallet_pub65)
            shared_secret = pc_private.exchange(ec.ECDH(), wallet_pub_key)

            # Pairing code = first 3 bytes of SHA-256(shared_secret), upper hex
            digest = hashes.Hash(hashes.SHA256())
            digest.update(shared_secret)
            h = digest.finalize()
            pair_code_pc = h[:3].hex().upper()
            print("PC pairing code:", pair_code_pc)

            # Read ESP32 pairing code
            read_until(ser, "PAIR_CODE_BEGIN")
            esp_code = read_line(ser)
            # next should be PAIR_CODE_END
            _ = read_line(ser)
            print("ESP32 pairing code:", esp_code)

            # Read ESP32 pairing approval
            read_until(ser, "PAIRING_APPROVAL")
            approval = read_line(ser)
            # next should be PAIR_APPROVAL_END
            _ = read_line(ser)

            if approval == "PAIRING_APPROVAL_APPROVED":
                data = {
                    "wallet_public_key_uncompressed_hex": wallet_pub65.hex().upper(),
                    "pc_public_key_uncompressed_hex": pc_public_bytes65.hex().upper(),
                    "shared_secret_hex": shared_secret.hex().upper()
                }
                with open("../config.json", "w") as f:
                    json.dump(data, f, indent=2)
                print("Saved config.json")

                ser.close()
                return shared_secret.hex().upper()
            else:
                print("Pairing denied")


if __name__ == "__main__":
    main(SERIAL_PORT,BAUD_RATE,CONFIG)
