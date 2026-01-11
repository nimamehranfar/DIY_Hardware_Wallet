# comm_selector.py
"""
Communication selector for Hardware Wallet
Supports both USB and WiFi connections to ESP32

Implements Trust on First Use (TOFU) for per-device TLS certificates:
- First connection: saves certificate fingerprint
- Subsequent connections: verifies fingerprint matches
- Alerts user if fingerprint changes (possible attack)
"""
import socket
import ssl
import os
import json
import hashlib


# Default ESP32 address - UPDATE THIS with your ESP32's IP!
ESP32_HOST = "192.168.1.100"  # Update this with your ESP32's IP!  
ESP32_PORT = 8443

# TLS settings
USE_TLS = True  # Set to True to enable TLS
TRUSTED_CERTS_FILE = os.path.join(os.path.dirname(__file__), "trusted_devices.json")


def get_cert_fingerprint(cert_der: bytes) -> str:
    """Calculate SHA256 fingerprint of certificate."""
    return hashlib.sha256(cert_der).hexdigest()


def load_trusted_devices() -> dict:
    """Load trusted device fingerprints from file."""
    if os.path.exists(TRUSTED_CERTS_FILE):
        try:
            with open(TRUSTED_CERTS_FILE, 'r') as f:
                return json.load(f)
        except:
            return {}
    return {}


def save_trusted_devices(devices: dict):
    """Save trusted device fingerprints to file."""
    with open(TRUSTED_CERTS_FILE, 'w') as f:
        json.dump(devices, f, indent=2)


def verify_tofu(host: str, port: int, cert_der: bytes) -> bool:
    """
    Trust on First Use verification.
    Returns True if certificate should be trusted, False to reject.
    """
    fingerprint = get_cert_fingerprint(cert_der)
    device_id = f"{host}:{port}"
    
    devices = load_trusted_devices()
    
    # First connection to this device
    if device_id not in devices:
        print(f"\n{'='*60}")
        print("🔑 NEW DEVICE DETECTED - Trust on First Use")
        print(f"{'='*60}")
        print(f"Device: {device_id}")
        print(f"Certificate fingerprint (SHA256):")
        print(f"  {fingerprint[:32]}")
        print(f"  {fingerprint[32:]}")
        print(f"{'='*60}")
        
        # Ask user to verify
        response = input("\nDo you want to trust this device? [y/N]: ").strip().lower()
        
        if response in ('y', 'yes'):
            devices[device_id] = {
                "fingerprint": fingerprint,
                "first_seen": __import__('datetime').datetime.now().isoformat()
            }
            save_trusted_devices(devices)
            print("[+] Device trusted and saved.")
            return True
        else:
            print("[!] Device NOT trusted. Connection rejected.")
            return False
    
    # Known device - verify fingerprint matches
    stored_fingerprint = devices[device_id]["fingerprint"]
    
    if fingerprint == stored_fingerprint:
        print(f"[+] Certificate verified for {device_id}")
        return True
    else:
        # FINGERPRINT MISMATCH - POSSIBLE ATTACK!
        print(f"\n{'!'*60}")
        print("⚠️  SECURITY WARNING: CERTIFICATE FINGERPRINT CHANGED!")
        print(f"{'!'*60}")
        print(f"Device: {device_id}")
        print(f"\nExpected fingerprint:")
        print(f"  {stored_fingerprint[:32]}")
        print(f"  {stored_fingerprint[32:]}")
        print(f"\nReceived fingerprint:")
        print(f"  {fingerprint[:32]}")
        print(f"  {fingerprint[32:]}")
        print(f"\n{'!'*60}")
        print("This could mean:")
        print("  1. Device was factory reset (legitimate)")
        print("  2. Man-in-the-middle attack (DANGER)")
        print("  3. Different device on same IP")
        print(f"{'!'*60}")
        
        response = input("\nDo you want to trust the NEW certificate? [y/N]: ").strip().lower()
        
        if response in ('y', 'yes'):
            devices[device_id] = {
                "fingerprint": fingerprint,
                "first_seen": __import__('datetime').datetime.now().isoformat(),
                "previous_fingerprint": stored_fingerprint
            }
            save_trusted_devices(devices)
            print("[+] New certificate trusted.")
            return True
        else:
            print("[!] Connection rejected for security.")
            return False


def run_wifi():
    """
    Connect to ESP32 wallet over WiFi.
    The ESP32 runs as a TCP server on port 8443.
    If USE_TLS is True, wraps connection in TLS with TOFU verification.
    """
    # Prompt user for IP address
    print(f"[*] Default ESP32 IP: {ESP32_HOST}")
    ip_input = input(f"Enter ESP32 IP (or press Enter for default): ").strip()
    host = ip_input if ip_input else ESP32_HOST
    port = ESP32_PORT
    
    print(f"[*] Connecting to ESP32 at {host}:{port}...")
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.settimeout(30)
    
    try:
        sock.connect((host, port))
        
        if USE_TLS:
            print("[*] Wrapping connection with TLS...")
            context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
            context.check_hostname = False  # ESP32 uses IP, not hostname
            
            # Accept any certificate initially (we verify via TOFU)
            context.verify_mode = ssl.CERT_NONE
            
            ssl_sock = context.wrap_socket(sock, server_hostname=host)
            print("[+] TLS handshake complete!")
            
            # Get the server's certificate for TOFU verification
            cert_der = ssl_sock.getpeercert(binary_form=True)
            
            if cert_der:
                if not verify_tofu(host, port, cert_der):
                    ssl_sock.close()
                    return None
            else:
                print("[!] Warning: Server provided no certificate")
            
            print("[+] Connected to ESP32 wallet!")
            return ssl_sock
        else:
            print("[+] Connected to ESP32 wallet (no TLS)!")
            return sock
            
    except ssl.SSLError as e:
        print(f"[!] TLS error: {e}")
        print("[!] ESP32 may not support TLS. Set USE_TLS=False to use plain TCP.")
        return None
    except ConnectionRefusedError:
        print(f"[!] Connection refused. Is the ESP32 running and on the network?")
        print(f"[!] Make sure ESP32 IP is {ESP32_HOST}")
        return None
    except socket.timeout:
        print(f"[!] Connection timed out. Check ESP32 is reachable.")
        return None
    except Exception as e:
        print(f"[!] Connection failed: {e}")
        return None


def run_usb():
    """
    Connect to ESP32 wallet over USB serial.
    Returns tuple of (serial_port, aes_key) after pairing.
    """
    try:
        from usb.usb_pair import run_usb as usb_pair
        return usb_pair()
    except ImportError as e:
        print(f"[!] USB support not available: {e}")
        print("[!] Install pyserial: pip install pyserial")
        return None


def select_comm():
    """
    Interactive communication method selector.
    Returns socket for WiFi, or (serial, aes_key) tuple for USB.
    """
    print("\n=== Communication Selector ===")
    print("1) WiFi (connect to ESP32 server)")
    print("2) USB (serial connection)")
    
    method = input("\nSelect [1/2] or [wifi/usb]: ").strip().lower()
    
    if method in ("1", "wifi"):
        return run_wifi()
    elif method in ("2", "usb"):
        return run_usb()
    else:
        print("Unknown method. Please select 'wifi' or 'usb'.")
        return None


def forget_device(host: str = None, port: int = None):
    """Remove a device from trusted list (for testing or re-pairing)."""
    if host is None:
        host = ESP32_HOST
    if port is None:
        port = ESP32_PORT
    
    device_id = f"{host}:{port}"
    devices = load_trusted_devices()
    
    if device_id in devices:
        del devices[device_id]
        save_trusted_devices(devices)
        print(f"[+] Removed {device_id} from trusted devices")
    else:
        print(f"[!] {device_id} not in trusted devices")


if __name__ == "__main__":
    import sys
    
    if len(sys.argv) > 1 and sys.argv[1] == "forget":
        forget_device()
    else:
        result = select_comm()
        if result:
            print("[OK] Connection established!")
        else:
            print("[!] No connection.")
