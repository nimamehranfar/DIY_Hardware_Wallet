import time
import binascii
import base58
import serial
import json
from datetime import datetime
from pathlib import Path

# Solders imports
from solders.pubkey import Pubkey
from solders.system_program import transfer, TransferParams
from solders.transaction import Transaction
from solders.message import Message
from solders.signature import Signature

# Solana-py RPC client
from solana.rpc.api import Client as SolanaClient

# Optional: local signature verification
import nacl.signing
import nacl.exceptions

# ---------------- CONFIG ----------------
PORT = "COM5"
BAUD = 115200
RPC_URL = "https://api.devnet.solana.com"
DEFAULT_LAMPORTS = 100_000_000  # 0.1 SOL
AIR_DROP_AMOUNT = 1_000_000_000  # 1 SOL
TX_HISTORY_FILE = Path("tx_history.json")  # persistent transaction history file

# ----------------------------------------


def send_cmd(ser, cmd, delay=0.2):
    ser.write((cmd + "\n").encode())
    time.sleep(delay)
    out = ser.read_all().decode(errors="ignore").strip()
    lines = [line.strip() for line in out.splitlines() if line.strip()]
    return lines[-1] if lines else None


def ensure_airdrop(client: SolanaClient, sender: Pubkey):
    bal = client.get_balance(sender).value
    print(f"[RPC] Current balance: {bal} lamports")
    if bal < 200_000_000:
        print("[RPC] Balance low. Requesting 1 SOL airdrop on Devnet...")
        client.request_airdrop(sender, AIR_DROP_AMOUNT)
        time.sleep(8)
        bal = client.get_balance(sender).value
        print(f"[RPC] New balance: {bal} lamports")
    return bal


def get_pubkey_input(prompt):
    while True:
        s = input(prompt).strip()
        try:
            return Pubkey.from_string(s)
        except ValueError:
            print("❌ Invalid public key. Try again.")


def get_lamports_input(prompt):
    while True:
        s = input(prompt).strip()
        if not s:
            return DEFAULT_LAMPORTS
        try:
            val = int(s)
            if val <= 0:
                raise ValueError
            return val
        except ValueError:
            print("❌ Enter a positive integer amount in lamports.")


def load_tx_history():
    if TX_HISTORY_FILE.exists():
        try:
            with open(TX_HISTORY_FILE, "r") as f:
                return json.load(f)
        except Exception as e:
            # Note: We keep the history empty if it fails to load, but print the error
            print(f"⚠️ Could not load transaction history: {e}")
    return []


def save_tx_history(tx_history):
    try:
        with open(TX_HISTORY_FILE, "w") as f:
            # We use `default=str` to handle any other solders objects that might slip in
            json.dump(tx_history, f, indent=4, default=str)
    except Exception as e:
        print(f"⚠️ Could not save transaction history: {e}")


def send_sol(client: SolanaClient, ser, sender: Pubkey, receiver: Pubkey, lamports: int, tx_history: list):
    instruction = transfer(TransferParams(from_pubkey=sender, to_pubkey=receiver, lamports=lamports))
    blockhash_resp = client.get_latest_blockhash()
    blockhash = blockhash_resp.value.blockhash

    message = Message.new_with_blockhash(
        instructions=[instruction],
        payer=sender,
        blockhash=blockhash
    )
    tx = Transaction.new_unsigned(message)

    message_bytes = bytes(tx.message)
    msg_hex = binascii.hexlify(message_bytes).decode()
    print(f"[→] Sending message ({len(message_bytes)} bytes) to ESP32 for signing...")

    sig_b58 = send_cmd(ser, "SIGN:" + msg_hex)
    if not sig_b58:
        print("❌ No signature returned")
        return

    sig_bytes = base58.b58decode(sig_b58)
    if len(sig_bytes) != 64:
        print(f"❌ Invalid signature length: {len(sig_bytes)} bytes")
        return

    tx.signatures = [Signature(sig_bytes)]

    # Optional local verification
    try:
        verify_key = nacl.signing.VerifyKey(bytes(sender))
        verify_key.verify(message_bytes, sig_bytes)
        print("🧾 Local verification: ✅ VALID")
    except nacl.exceptions.BadSignatureError:
        print("⚠️ Local verification failed!")

    raw_tx = bytes(tx)
    resp = client.send_raw_transaction(raw_tx)

    tx_id = None
    if hasattr(resp, 'value') and resp.value:
        # FIX: Convert the solders Signature object to a string for JSON serialization
        tx_id = str(resp.value)
        print(f"[RPC] Transaction ID: {tx_id}")
    elif hasattr(resp, 'error') and resp.error:
        print(f"[RPC] Failed to send transaction: {resp.error.message}")
    else:
        print(f"[RPC] Unknown response or failed: {resp}")

    if tx_id:
        tx_history.append({
            "timestamp": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
            "receiver": str(receiver),
            "amount": lamports,
            "tx_id": tx_id
        })
        save_tx_history(tx_history)


def show_tx_history(tx_history: list):
    if not tx_history:
        print("No transactions yet.")
        return
    print("\n--- Transaction History ---")
    for i, tx in enumerate(tx_history, 1):
        # Ensure tx_id is treated as a string for display
        tx_id_str = str(tx['tx_id'])
        print(f"{i}. [{tx['timestamp']}] Sent {tx['amount']} lamports to {tx['receiver']}")
        print(f"   Transaction ID: {tx_id_str}")
    print("---------------------------")


def main():
    tx_history = load_tx_history()
    # FIX: Initialize ser to None to ensure it's defined in the main scope
    ser = None
    try:
        client = SolanaClient(RPC_URL)
        print("🔌 Connecting to ESP32...")
        ser = serial.Serial(PORT, BAUD, timeout=1)
        time.sleep(2)

        pubkey_b58 = send_cmd(ser, "PUBKEY")
        if not pubkey_b58:
            print("❌ No PUBKEY returned from ESP32")
            # If ser is open here, it will be closed in finally, but we can exit early.
            # We explicitly don't call ser.close() here as it is handled by the finally block
            return
        sender = Pubkey.from_string(pubkey_b58)
        print("[✓] ESP32 Public Key:", pubkey_b58)

        ensure_airdrop(client, sender)

        while True:
            print("\nSelect an option:")
            print("1. Check balance")
            print("2. Request airdrop")
            print("3. Send SOL")
            print("4. Transaction history")
            print("5. Exit")
            choice = input("Enter choice: ").strip()

            if choice == "1":
                bal = client.get_balance(sender).value
                print(f"[RPC] Current balance: {bal} lamports")
            elif choice == "2":
                ensure_airdrop(client, sender)
            elif choice == "3":
                # For quick testing, you can set the receiver to the sender's pubkey
                # to send the funds back to yourself.
                print("Note: Receiver can be the same as ESP32 public key (8RHtZf...) for testing.")
                receiver = get_pubkey_input("Receiver public key: ")
                lamports = get_lamports_input(f"Amount in lamports (default {DEFAULT_LAMPORTS}): ")
                send_sol(client, ser, sender, receiver, lamports, tx_history)
            elif choice == "4":
                show_tx_history(tx_history)
            elif choice == "5":
                print("Exiting...")
                break
            else:
                print("❌ Invalid choice. Try again.")

    except serial.SerialException as e:
        print(f"\nFATAL ERROR: Could not open serial port {PORT}. Details: {e}")
    except Exception as e:
        print(f"\nAn unexpected error occurred: {e}")
    finally:
        # The 'ser is not None' check replaces the need for 'ser in locals()'
        # and eliminates the warning.
        if ser is not None and ser.is_open:
            ser.close()


if __name__ == "__main__":
    main()