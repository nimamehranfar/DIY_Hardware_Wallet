#!/usr/bin/env python3
"""
Verify Base58 encoding for pubkey bytes
"""
import base58

# The pubkey bytes from ESP32 debug output
pubkey_hex = "CD917B0874897F26984F8F123E9965A1AF7942A90E1F4B1F2D3B243860A14020"
pubkey_bytes = bytes.fromhex(pubkey_hex)

# Convert to Base58 (Solana uses standard Base58, not Base58Check)
b58 = base58.b58encode(pubkey_bytes).decode()

print(f"Pubkey bytes: {pubkey_hex}")
print(f"Expected Base58: {b58}")
print(f"ESP32 returns: EqTF2UqCgqDpe3NhzADWdhA8X8atqoLV8Epod72TP5Fu")
print(f"Match: {b58 == 'EqTF2UqCgqDpe3NhzADWdhA8X8atqoLV8Epod72TP5Fu'}")
