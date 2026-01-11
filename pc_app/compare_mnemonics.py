#!/usr/bin/env python3
"""
Compare mnemonic derivation for two word sets
Uses the same algorithm as ESP32 mnemonic.h
"""
import hashlib
import base58

# 256-word list from mnemonic.h (first 256 words alphabetically)
MNEMONIC_WORDS = [
    "abandon", "ability", "about", "above", "absent", "absorb", "abstract", "absurd",
    "abuse", "access", "accident", "account", "achieve", "acid", "acquire", "across",
    "action", "actor", "actual", "adapt", "add", "adjust", "admit", "adult",
    "advance", "advice", "afford", "afraid", "after", "again", "agent", "agree",
    "ahead", "aim", "airport", "alarm", "album", "alert", "alien", "all",
    "almost", "alone", "alpha", "already", "also", "alter", "always", "amateur",
    "amazing", "among", "amount", "amused", "anchor", "ancient", "anger", "angle",
    "angry", "animal", "announce", "annual", "another", "answer", "antenna", "antique",
    "anxiety", "apart", "apology", "appear", "apple", "approve", "april", "arctic",
    "area", "arena", "argue", "arm", "armed", "armor", "army", "around",
    "arrange", "arrest", "arrive", "arrow", "art", "artist", "artwork", "ask",
    "aspect", "assault", "asset", "assist", "assume", "athlete", "atom", "attack",
    "attend", "attract", "auction", "august", "aunt", "author", "auto", "autumn",
    "average", "avoid", "awake", "aware", "away", "awesome", "awful", "awkward",
    "baby", "bachelor", "bacon", "badge", "balance", "balcony", "ball", "bamboo",
    "banana", "banner", "bar", "bargain", "barrel", "base", "basic", "basket",
    "battle", "beach", "bean", "beauty", "because", "become", "beef", "before",
    "begin", "behave", "behind", "believe", "below", "belt", "bench", "benefit",
    "best", "betray", "better", "between", "beyond", "bicycle", "bid", "bike",
    "bind", "biology", "bird", "birth", "bitter", "black", "blade", "blame",
    "blanket", "blast", "bleak", "bless", "blind", "blood", "blossom", "blouse",
    "blue", "board", "boat", "body", "boil", "bold", "bomb", "bone",
    "bonus", "book", "border", "boring", "borrow", "boss", "bottom", "bounce",
    "box", "boy", "bracket", "brain", "brand", "brave", "bread", "breeze",
    "brick", "bridge", "brief", "bright", "bring", "brisk", "bronze", "brother",
    "brown", "brush", "bubble", "budget", "build", "bulb", "bull", "bundle",
    "bunker", "burden", "burger", "burst", "bus", "business", "busy", "butter",
    "buyer", "buzz", "cabin", "cactus", "cage", "cake", "call", "calm",
    "camera", "camp", "can", "canal", "cancel", "candy", "cannon", "canoe",
    "canvas", "capable", "capital", "captain", "car", "carbon", "card", "cargo",
    "carpet", "carry", "cart", "case", "cash", "casino", "castle", "casual"
]

def mnemonic_to_entropy(words):
    """Convert 12 words to 12 bytes of entropy (word indices)"""
    entropy = []
    for word in words:
        if word in MNEMONIC_WORDS:
            entropy.append(MNEMONIC_WORDS.index(word))
        else:
            print(f"WARNING: '{word}' not in wordlist!")
            return None
    return bytes(entropy)

def entropy_to_key(entropy):
    """Derive Ed25519 private key from entropy (same as ESP32)"""
    # SHA256 of first 11 bytes
    temp = hashlib.sha256(entropy[:11]).digest()
    
    # Hash again with prefix byte
    input_data = b'\x01' + temp
    sk = hashlib.sha256(input_data).digest()
    return sk

def ed25519_pubkey(sk):
    """Get Ed25519 public key from private key"""
    from nacl.signing import SigningKey
    signing_key = SigningKey(sk)
    return bytes(signing_key.verify_key)

def derive_address(words_str):
    """Full derivation from mnemonic words to Solana address"""
    words = words_str.lower().split()
    print(f"Words: {' '.join(words)}")
    
    entropy = mnemonic_to_entropy(words)
    if entropy is None:
        return None
    
    print(f"Entropy (word indices): {entropy.hex().upper()}")
    
    sk = entropy_to_key(entropy)
    print(f"Private key: {sk.hex().upper()}")
    
    pk = ed25519_pubkey(sk)
    print(f"Public key: {pk.hex().upper()}")
    
    address = base58.b58encode(pk).decode()
    print(f"Solana address: {address}")
    return address

print("="*60)
print("OLD MNEMONIC (before recovery):")
print("="*60)
old_addr = derive_address("alpha betray autumn bold brand antique apology bull arm access accident birth")

print("\n" + "="*60)
print("NEW MNEMONIC (recovery words):")
print("="*60)
new_addr = derive_address("away camera cargo bitter ball awake arrow anger anxiety about bean afraid")

print("\n" + "="*60)
print("COMPARISON:")
print("="*60)
print(f"Old address: {old_addr}")
print(f"New address: {new_addr}")
print(f"Same address: {old_addr == new_addr}")
