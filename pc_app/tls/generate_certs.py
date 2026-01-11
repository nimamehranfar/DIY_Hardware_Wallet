"""
TLS Certificate Generator for DIY Hardware Wallet
Generates self-signed certificates for the TLS server.
Run this script to create server.key and server.crt
"""

import os
import subprocess
import sys

def generate_certificates():
    """Generate self-signed TLS certificates using Python's cryptography library"""
    try:
        from cryptography import x509
        from cryptography.x509.oid import NameOID
        from cryptography.hazmat.primitives import hashes
        from cryptography.hazmat.backends import default_backend
        from cryptography.hazmat.primitives.asymmetric import rsa
        from cryptography.hazmat.primitives import serialization
        import datetime
    except ImportError:
        print("[!] cryptography library not found. Installing...")
        subprocess.check_call([sys.executable, "-m", "pip", "install", "cryptography"])
        from cryptography import x509
        from cryptography.x509.oid import NameOID
        from cryptography.hazmat.primitives import hashes
        from cryptography.hazmat.backends import default_backend
        from cryptography.hazmat.primitives.asymmetric import rsa
        from cryptography.hazmat.primitives import serialization
        import datetime

    HERE = os.path.dirname(os.path.abspath(__file__))
    KEY_FILE = os.path.join(HERE, "server.key")
    CERT_FILE = os.path.join(HERE, "server.crt")

    print("[*] Generating RSA 2048-bit private key...")
    key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=2048,
        backend=default_backend()
    )

    # Write the private key
    with open(KEY_FILE, "wb") as f:
        f.write(key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.TraditionalOpenSSL,
            encryption_algorithm=serialization.NoEncryption()
        ))
    print(f"[✓] Private key saved: {KEY_FILE}")

    # Generate self-signed certificate
    print("[*] Generating self-signed certificate (valid 10 years)...")
    subject = issuer = x509.Name([
        x509.NameAttribute(NameOID.COMMON_NAME, u"HardwareWalletServer"),
    ])

    cert = (
        x509.CertificateBuilder()
        .subject_name(subject)
        .issuer_name(issuer)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(datetime.datetime.utcnow())
        .not_valid_after(datetime.datetime.utcnow() + datetime.timedelta(days=3650))
        .add_extension(
            x509.BasicConstraints(ca=True, path_length=None),
            critical=True,
        )
        .sign(key, hashes.SHA256(), default_backend())
    )

    # Write the certificate
    with open(CERT_FILE, "wb") as f:
        f.write(cert.public_bytes(serialization.Encoding.PEM))
    print(f"[✓] Certificate saved: {CERT_FILE}")

    # Print the certificate for copying to ESP32
    print("\n" + "="*60)
    print("IMPORTANT: Copy this certificate to wallet_main.ino")
    print("Replace the SERVER_CERT_PEM content with this:")
    print("="*60 + "\n")
    
    with open(CERT_FILE, "r") as f:
        cert_content = f.read()
        print(cert_content)
    
    print("="*60)
    print("\n[✓] Certificate generation complete!")
    return cert_content


if __name__ == "__main__":
    generate_certificates()
