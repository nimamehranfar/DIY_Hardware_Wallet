import time, json, binascii, sys
from solders.pubkey import Pubkey
from solders.system_program import transfer, TransferParams
from solders.transaction import Transaction
from solders.message import Message
from solders.signature import Signature
from solana.rpc.api import Client as SolanaClient
from pc_app.comm_selector import select_comm
from secure_channel import SecureChannel, SerialTransport, SocketTransport
import base58

import importlib

RPC_URL = "https://api.devnet.solana.com"
DEFAULT_LAMPORTS = 100_000_000


# --- unified channel factory ---
def get_channel():
    """
    Calls comm_selector.main() and returns a SecureChannel ready to use,
    along with the original transport object.
    - USB returns (SecureChannel, ser)
    - WiFi/TLS returns (SecureChannel, sock)
    """
    result = select_comm()

    if not result:
        print("[!] No communication channel returned.")
        sys.exit(1)

    # USB path (tuple of (ser, aes_key))
    if isinstance(result, tuple) and len(result) == 2:
        ser, aes_key = result
        print("[*] Using USB AES-GCM secure channel")
        ch = SecureChannel(aes_key, SerialTransport(ser))
        return ch, ser

    # TLS path (single socket object)
    print("[*] Using TLS socket channel (already encrypted)")
    ch = SecureChannel(b"\x00"*16, SocketTransport(result))
    return ch, result


# --- wallet operations ---
def request_pubkey(ch: SecureChannel) -> Pubkey:
    ch.send_json({"cmd": "PUBKEY"})
    resp = ch.recv_json()
    if resp.get("ok") and "pubkey" in resp:
        return Pubkey.from_string(resp["pubkey"])
    raise RuntimeError(f"Bad PUBKEY response: {resp}")


def request_sign(ch: SecureChannel, msg_hex: str) -> bytes:
    ch.send_json({"cmd": "SIGN", "msg": msg_hex})
    resp = ch.recv_json()
    if resp.get("ok") and "sig_b58" in resp:
        return base58.b58decode(resp["sig_b58"])
    raise RuntimeError(f"Bad SIGN response: {resp}")


def main():
    client = SolanaClient(RPC_URL)
    ch, transport = get_channel()

    sender = request_pubkey(ch)
    print("[✓] ESP32 Public Key:", str(sender))

    while True:
        print("\n1) Balance\n2) Airdrop\n3) Send SOL\n4) Exit")
        c = input("> ").strip()

        if c == "1":
            bal = client.get_balance(sender).value
            print(f"[RPC] Balance = {bal} lamports")

        elif c == "2":
            print("[RPC] Requesting 1 SOL airdrop...")
            client.request_airdrop(sender, 1_000_000_000)
            time.sleep(8)
            bal = client.get_balance(sender).value
            print(f"[RPC] New Balance = {bal} lamports")

        elif c == "3":
            to = input("Receiver pubkey: ").strip()
            lam = input(f"Lamports (default {DEFAULT_LAMPORTS}): ").strip()
            lamports = int(lam) if lam else DEFAULT_LAMPORTS

            receiver = Pubkey.from_string(to)
            bh = client.get_latest_blockhash().value.blockhash
            ix = transfer(TransferParams(from_pubkey=sender, to_pubkey=receiver, lamports=lamports))
            msg = Message.new_with_blockhash([ix], payer=sender, blockhash=bh)
            tx = Transaction.new_unsigned(msg)
            msg_hex = binascii.hexlify(bytes(tx.message)).decode()
            sig = request_sign(ch, msg_hex)
            tx.signatures = [Signature(sig)]
            resp = client.send_raw_transaction(bytes(tx))
            print("[RPC] send_raw_transaction =>", getattr(resp, "value", resp))

        elif c == "4":
            print("Exiting wallet...")
            break

        else:
            print("❌ Invalid choice. Try again.")

    # close channel if serial
    if hasattr(transport, "close"):
        try:
            transport.close()
        except Exception:
            pass


if __name__ == "__main__":
    main()
