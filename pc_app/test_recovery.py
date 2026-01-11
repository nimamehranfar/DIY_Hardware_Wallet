#!/usr/bin/env python3
"""
Test Recovery Script - Tests wallet recovery via WebSocket
Uses the words: away camera cargo bitter ball awake arrow anger anxiety about bean afraid
"""
import json
import asyncio
import websockets
import sys

# ESP32 WebSocket configuration
ESP32_IP = "172.20.10.9"  # Change to your ESP32 IP
ESP32_PORT = 8444

# Test mnemonic words
TEST_WORDS = [
    "away", "camera", "cargo", "bitter", "ball", "awake",
    "arrow", "anger", "anxiety", "about", "bean", "afraid"
]

async def test_recovery():
    uri = f"ws://{ESP32_IP}:{ESP32_PORT}"
    print(f"[*] Connecting to {uri}...")
    
    try:
        async with websockets.connect(uri, timeout=10) as ws:
            print("[+] Connected!")
            
            # Step 1: Get current public key
            print("\n[*] Getting current public key...")
            await ws.send(json.dumps({"cmd": "PUBKEY"}))
            resp = await asyncio.wait_for(ws.recv(), timeout=10)
            data = json.loads(resp)
            print(f"[*] Response: {data}")
            old_pubkey = data.get("pubkey", "")
            print(f"[*] Current pubkey: {old_pubkey}")
            
            # Step 2: Send RECOVER command
            print("\n[*] Sending RECOVER command...")
            recover_cmd = {"cmd": "RECOVER"}
            for i, word in enumerate(TEST_WORDS):
                recover_cmd[f"word{i}"] = word
            
            print(f"[*] Command: {json.dumps(recover_cmd)}")
            await ws.send(json.dumps(recover_cmd))
            
            # Wait for response (device may take time to process)
            try:
                resp = await asyncio.wait_for(ws.recv(), timeout=30)
                data = json.loads(resp)
                print(f"[*] Response: {data}")
                
                if data.get("ok"):
                    print("\n[✓] Recovery command accepted!")
                    print("[*] Device will restart...")
                    print("[*] Wait 5 seconds for device to reboot...")
                else:
                    error = data.get("error", "unknown")
                    print(f"\n[!] Recovery failed: {error}")
                    return False
                    
            except asyncio.TimeoutError:
                print("[!] Timeout waiting for response")
                return False
                
    except websockets.exceptions.ConnectionClosed:
        print("[*] Connection closed (device is restarting)")
        
    except Exception as e:
        print(f"[!] Error: {e}")
        return False
    
    # Wait for device to restart
    print("\n[*] Waiting 8 seconds for device to restart...")
    await asyncio.sleep(8)
    
    # Step 3: Reconnect and verify new public key
    print(f"[*] Reconnecting to {uri}...")
    try:
        async with websockets.connect(uri, timeout=15) as ws:
            print("[+] Reconnected!")
            
            # Get new public key
            print("[*] Getting new public key...")
            await ws.send(json.dumps({"cmd": "PUBKEY"}))
            resp = await asyncio.wait_for(ws.recv(), timeout=10)
            data = json.loads(resp)
            new_pubkey = data.get("pubkey", "")
            print(f"[*] New pubkey: {new_pubkey}")
            
            # Compare
            print("\n" + "="*50)
            print(f"OLD: {old_pubkey}")
            print(f"NEW: {new_pubkey}")
            print("="*50)
            
            if old_pubkey != new_pubkey:
                print("\n[✓] SUCCESS! Public key changed - recovery worked!")
                return True
            else:
                print("\n[!] FAILED! Public key is still the same!")
                print("[!] Recovery did not change the wallet address")
                return False
                
    except Exception as e:
        print(f"[!] Reconnection error: {e}")
        print("[!] Device may still be locked (waiting for PIN entry)")
        return False

def main():
    if len(sys.argv) > 1:
        global ESP32_IP
        ESP32_IP = sys.argv[1]
    
    print("="*50)
    print("  Wallet Recovery Test")
    print("="*50)
    print(f"ESP32 IP: {ESP32_IP}:{ESP32_PORT}")
    print(f"Test words: {' '.join(TEST_WORDS)}")
    print("="*50 + "\n")
    
    print("[!] IMPORTANT: Device must be UNLOCKED (PIN entered)")
    print("[!] This will replace the current wallet!\n")
    
    input("Press Enter to continue (Ctrl+C to cancel)...")
    
    result = asyncio.run(test_recovery())
    
    if result:
        print("\n[✓] Test PASSED")
        sys.exit(0)
    else:
        print("\n[!] Test FAILED")
        sys.exit(1)

if __name__ == "__main__":
    main()
