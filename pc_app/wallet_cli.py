"""
Wallet CLI - Secure Solana Hardware Wallet Interface
Communicates with ESP32 Hardware Wallet using AES-GCM encrypted SecureChannel
"""
import time
import json
import binascii
import sys
import os

from solders.pubkey import Pubkey
from solders.system_program import transfer, TransferParams
from solders.transaction import Transaction
from solders.message import Message
from solders.signature import Signature
from solana.rpc.api import Client as SolanaClient
import base58

# Import local modules
try:
    from pc_app.comm_selector import select_comm, ESP32_HOST, ESP32_PORT
    from pc_app.secure_channel import SecureChannel, SocketTransport, SerialTransport
except ImportError:
    from comm_selector import select_comm
    from secure_channel import SecureChannel, SocketTransport, SerialTransport

# Load config if exists
CONFIG_PATH = os.path.join(os.path.dirname(__file__), "config.json")
if os.path.exists(CONFIG_PATH):
    with open(CONFIG_PATH, 'r') as f:
        config = json.load(f)
    RPC_URL = config.get("rpc_url", "https://api.devnet.solana.com")
    # Update comm_selector with config values
    import comm_selector
    comm_selector.ESP32_HOST = config.get("esp32_ip", "192.168.1.100")
    comm_selector.ESP32_PORT = config.get("port", 8443)
    comm_selector.USE_TLS = config.get("use_tls", False)
else:
    RPC_URL = "https://api.devnet.solana.com"

DEFAULT_LAMPORTS = 100_000_000


def get_channel():
    """
    Get secure communication channel to ESP32.
    Returns (SecureChannel, transport) tuple.
    """
    result = select_comm()
    
    if not result:
        print("[!] No communication channel established.")
        sys.exit(1)
    
    # USB path returns (serial, aes_key) tuple
    if isinstance(result, tuple) and len(result) == 2:
        ser, aes_key = result
        print("[*] Using USB with AES-GCM SecureChannel")
        ch = SecureChannel(aes_key, SerialTransport(ser))
        return ch, ser
    
    # WiFi path returns a socket
    # For WiFi, we use a null key since the ESP32 will handle key exchange
    # The channel still provides message framing
    print("[*] Using WiFi with AES-GCM SecureChannel")
    
    # Generate a session key via key exchange
    # For now, use a derived key based on ECDH (simplified)
    # In production, implement proper key exchange protocol
    aes_key = bytes(16)  # Will be replaced by key exchange
    
    ch = SecureChannel(aes_key, SocketTransport(result))
    return ch, result


def request_pubkey(ch: SecureChannel) -> Pubkey:
    """Request public key from the hardware wallet."""
    print("[*] Requesting public key from ESP32...")
    ch.send_json({"cmd": "PUBKEY"})
    resp = ch.recv_json(timeout=10)
    
    if resp.get("ok") and "pubkey" in resp:
        pubkey_str = resp["pubkey"]
        print(f"[+] Received pubkey: {pubkey_str[:16]}...")
        return Pubkey.from_string(pubkey_str)
    
    raise RuntimeError(f"Failed to get pubkey: {resp}")


def request_sign(ch: SecureChannel, msg_hex: str) -> bytes:
    """
    Request signature from the hardware wallet.
    The user must confirm on the ESP32 device.
    """
    print("[*] Sending sign request to ESP32...")
    print("[!] Please confirm the transaction on your hardware wallet!")
    
    ch.send_json({"cmd": "SIGN", "msg": msg_hex})
    
    # Longer timeout to allow user to review and confirm
    resp = ch.recv_json(timeout=60)
    
    if resp.get("ok") and "sig_b58" in resp:
        sig_bytes = base58.b58decode(resp["sig_b58"])
        print("[+] Signature received!")
        return sig_bytes
    
    error = resp.get("error", "unknown error")
    raise RuntimeError(f"Signing failed: {error}")


def show_mnemonic(ch: SecureChannel):
    """Request ESP32 to display mnemonic on OLED."""
    print("\n[*] Requesting mnemonic display on ESP32...")
    print("[!] Look at your hardware wallet screen!")
    ch.send_json({"cmd": "SHOW_MNEMONIC"})
    resp = ch.recv_json(timeout=30)
    if resp.get("ok"):
        print("[✓] Mnemonic displayed on device!")
    else:
        print("[!] Failed to display mnemonic")


def recover_wallet(ch: SecureChannel):
    """Recover wallet from 12-word BIP39 mnemonic with device code verification."""
    print("\n=== Wallet Recovery ===")
    print("[!] SECURITY: This uses 2-step verification")
    print("    1. Device shows 6-digit code")
    print("    2. You enter code here to prove physical access\n")
    
    # Step 1: Request device to display recovery code
    print("[*] Step 1: Requesting recovery code from device...")
    ch.send_json({"cmd": "RECOVERY_INIT"})
    resp = ch.recv_json(timeout=10)
    
    if not resp.get("ok"):
        error = resp.get("error", "unknown")
        if error == "device_locked":
            print("[!] Device is locked. Enter PIN on device first.")
        else:
            print(f"[!] Failed to init recovery: {error}")
        return False
    
    print("[✓] Recovery code is now displayed on device screen!")
    print("[!] Look at your hardware wallet and enter the 6-digit code:\n")
    
    # Step 2: Get device code from user
    device_code = input("Enter 6-digit code from device: ").strip()
    try:
        device_code = int(device_code)
        if device_code < 0 or device_code > 999999:
            raise ValueError()
    except ValueError:
        print("[!] Invalid code format. Must be 6 digits.")
        return False
    
    # Step 3: Get mnemonic words
    print("\n[*] Step 2: Enter your 12-word BIP39 backup phrase:")
    words = []
    for i in range(12):
        word = input(f"Word {i+1}: ").strip().lower()
        if not word:
            print("[!] Word cannot be empty")
            return False
        words.append(word)
    
    # Step 4: Send recovery request with code
    print("\n[*] Sending recovery request...")
    cmd = {"cmd": "RECOVER", "device_code": device_code}
    for i, word in enumerate(words):
        cmd[f"word{i}"] = word
    
    ch.send_json(cmd)
    resp = ch.recv_json(timeout=30)  # May take time for BIP39 derivation
    
    if resp.get("ok"):
        print("[✓] Wallet recovered successfully!")
        print("[*] ESP32 will restart...")
        return True
    else:
        error = resp.get("error", "unknown")
        if error == "invalid_code":
            print("[!] Wrong device code! Recovery cancelled.")
        elif error == "no_recovery_code":
            print("[!] Recovery code expired. Try again from the beginning.")
        elif error == "invalid_mnemonic":
            print("[!] Invalid BIP39 mnemonic. Check your words.")
        else:
            print(f"[!] Recovery failed: {error}")
        return False


def set_wifi(ch: SecureChannel):
    """Configure WiFi credentials on ESP32 with physical confirmation."""
    print("\n=== WiFi Configuration ===")
    print("[!] SECURITY: Requires physical button confirmation on device\n")
    
    ssid = input("WiFi SSID: ").strip()
    password = input("WiFi Password: ").strip()
    
    if not ssid:
        print("[!] SSID cannot be empty")
        return False
    
    print("\n[*] Sending WiFi credentials...")
    print("[!] Look at device screen and press OK to confirm, or BACK to cancel")
    print("[*] Waiting up to 60 seconds for confirmation...\n")
    
    ch.send_json({"cmd": "SET_WIFI", "ssid": ssid, "password": password})
    
    try:
        resp = ch.recv_json(timeout=60)  # 60 second timeout for user confirmation
    except TimeoutError:
        print("[!] Timeout waiting for device confirmation")
        return False
    
    if resp.get("ok"):
        print("[✓] WiFi credentials saved!")
        print("[*] ESP32 will restart with new WiFi...")
        return True
    else:
        error = resp.get("error", "unknown")
        if error == "user_cancelled":
            print("[!] WiFi update cancelled by user on device")
        elif error == "device_locked":
            print("[!] Device is locked. Enter PIN on device first.")
        else:
            print(f"[!] Update failed: {error}")
        return False


def main():
    print("\n" + "="*50)
    print("  Solana Hardware Wallet CLI")
    print("  Secure Ed25519 signing on ESP32")
    print("="*50 + "\n")
    
    # Connect to Solana RPC
    client = SolanaClient(RPC_URL)
    print(f"[*] RPC: {RPC_URL}")
    
    # Establish secure channel
    ch, transport = get_channel()
    
    # Get wallet public key
    try:
        sender = request_pubkey(ch)
        print(f"\n[✓] Wallet Address: {sender}\n")
    except Exception as e:
        print(f"[!] Failed to get public key: {e}")
        sys.exit(1)
    
    # Main menu loop
    while True:
        print("\n--- Wallet Menu ---")
        print("1) Check Balance")
        print("2) Request Airdrop (devnet, 1 SOL)")
        print("3) Send SOL")
        print("4) Show Address")
        print("5) Show Mnemonic (on device)")
        print("6) Recover Wallet")
        print("7) Set WiFi")
        print("8) Exit")
        
        choice = input("\n> ").strip()
        
        if choice == "1":
            try:
                bal = client.get_balance(sender).value
                sol = bal / 1_000_000_000
                print(f"\n[Balance] {bal:,} lamports")
                print(f"[Balance] {sol:.9f} SOL")
            except Exception as e:
                print(f"[!] Error fetching balance: {e}")
        
        elif choice == "2":
            try:
                print("\n[*] Requesting airdrop from devnet faucet...")
                client.request_airdrop(sender, 1_000_000_000)
                print("[*] Airdrop requested. Waiting for confirmation...")
                time.sleep(10)
                bal = client.get_balance(sender).value
                print(f"[✓] New balance: {bal:,} lamports")
            except Exception as e:
                print(f"[!] Airdrop failed: {e}")
        
        elif choice == "3":
            try:
                print("\n--- Send SOL ---")
                to_addr = input("Recipient address: ").strip()
                if not to_addr:
                    print("[!] Cancelled.")
                    continue
                
                amount_str = input(f"Amount in lamports (default {DEFAULT_LAMPORTS:,}): ").strip()
                lamports = int(amount_str) if amount_str else DEFAULT_LAMPORTS
                
                print(f"\n[*] Preparing transaction...")
                print(f"    From: {sender}")
                print(f"    To:   {to_addr}")
                print(f"    Amount: {lamports:,} lamports ({lamports/1e9:.9f} SOL)")
                
                receiver = Pubkey.from_string(to_addr)
                blockhash = client.get_latest_blockhash().value.blockhash
                
                ix = transfer(TransferParams(
                    from_pubkey=sender,
                    to_pubkey=receiver,
                    lamports=lamports
                ))
                
                msg = Message.new_with_blockhash([ix], payer=sender, blockhash=blockhash)
                tx = Transaction.new_unsigned(msg)
                msg_hex = binascii.hexlify(bytes(tx.message)).decode()
                
                # Request signature from hardware wallet
                sig = request_sign(ch, msg_hex)
                
                # Attach signature and broadcast
                tx.signatures = [Signature(sig)]
                result = client.send_raw_transaction(bytes(tx))
                
                tx_sig = getattr(result, "value", result)
                print(f"\n[✓] Transaction sent!")
                print(f"[✓] Signature: {tx_sig}")
                print(f"[✓] Explorer: https://explorer.solana.com/tx/{tx_sig}?cluster=devnet")
                
            except Exception as e:
                print(f"\n[!] Transaction failed: {e}")
        
        elif choice == "4":
            print(f"\n[Address] {sender}")
        
        elif choice == "5":
            show_mnemonic(ch)
        
        elif choice == "6":
            if recover_wallet(ch):
                print("[*] Please reconnect after ESP32 restarts.")
                break
        
        elif choice == "7":
            set_wifi(ch)
        
        elif choice == "8":
            print("\n[*] Goodbye!")
            break
        
        else:
            print("[!] Invalid choice.")
    
    # Cleanup
    if hasattr(transport, "close"):
        try:
            transport.close()
        except:
            pass


if __name__ == "__main__":
    main()
