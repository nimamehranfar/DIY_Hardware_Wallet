# pc_app/secure_channel.py
# AES-GCM line-framed secure channel for both USB serial and TLS sockets.
# Key MUST be 16/24/32 bytes. Nonce: 12 bytes = 8-byte salt || 4-byte counter.
# Frames are ASCII lines: b"ENC:" + base64(nonce || ciphertext || tag) + b"\n"
# JSON payloads are UTF-8 bytes inside AES-GCM.
import os, json, base64, struct, time
from typing import Optional

try:
    from Crypto.Cipher import AES  # pycryptodome
except Exception:
    from cryptography.hazmat.primitives.ciphers.aead import AESGCM
    AES = None

class Transport:
    # Abstract transport with write(bytes) and readline()->bytes
    def write(self, b: bytes): raise NotImplementedError
    def readline(self) -> bytes: raise NotImplementedError

class SerialTransport(Transport):
    def __init__(self, ser):
        self.ser = ser
    def write(self, b: bytes):
        self.ser.write(b)
    def readline(self) -> bytes:
        return self.ser.readline()

class SocketTransport(Transport):
    def __init__(self, sock):
        self.sock = sock.makefile("rwb", buffering=0)
    def write(self, b: bytes):
        self.sock.write(b)
        self.sock.flush()
    def readline(self) -> bytes:
        return self.sock.readline()

class SecureChannel:
    def __init__(self, key: bytes, transport: Transport, salt: Optional[bytes]=None):
        if len(key) not in (16,24,32):
            raise ValueError("AES key must be 16/24/32 bytes")
        self.key = key
        self.t = transport
        self.salt = salt or os.urandom(8)
        self.tx_counter = 1
        self.rx_seen = set()

        self._use_pycryptodome = AES is not None
        if not self._use_pycryptodome:
            AESGCM  # ensure import exists

    def _nonce(self, ctr:int)->bytes:
        return self.salt + struct.pack(">I", ctr)

    def _enc(self, plaintext: bytes, aad: bytes=b""):
        nonce = self._nonce(self.tx_counter)
        self.tx_counter += 1
        if self._use_pycryptodome:
            cipher = AES.new(self.key, AES.MODE_GCM, nonce=nonce)
            cipher.update(aad)
            ct, tag = cipher.encrypt_and_digest(plaintext)
        else:
            a = AESGCM(self.key)
            ct = a.encrypt(nonce, plaintext, aad)  # ct||tag
            tag, ct = ct[-16:], ct[:-16]
        return nonce, ct, tag

    def _dec(self, nonce: bytes, ct: bytes, tag: bytes, aad: bytes=b""):
        if nonce in self.rx_seen:
            raise ValueError("replayed frame")
        if self._use_pycryptodome:
            cipher = AES.new(self.key, AES.MODE_GCM, nonce=nonce)
            cipher.update(aad)
            pt = cipher.decrypt_and_verify(ct, tag)
        else:
            from cryptography.hazmat.primitives.ciphers.aead import AESGCM
            a = AESGCM(self.key)
            pt = a.decrypt(nonce, ct+tag, aad)
        self.rx_seen.add(nonce)
        if len(self.rx_seen) > 2048:
            self.rx_seen = set(list(self.rx_seen)[-1024:])
        return pt

    def send_json(self, obj: dict):
        data = json.dumps(obj, separators=(",",":")).encode("utf-8")
        
        # If key is all zeros, send plain JSON (before key exchange)
        if self.key == b"\x00" * len(self.key):
            self.t.write(data + b"\n")
            return
        
        # Otherwise, send encrypted
        nonce, ct, tag = self._enc(data)
        frame = base64.b64encode(nonce + ct + tag)
        self.t.write(b"ENC:" + frame + b"\n")

    def recv_json(self, timeout: float=10.0) -> dict:
        start = time.time()
        while True:
            if timeout and (time.time() - start) > timeout:
                raise TimeoutError("timed out")
            line = self.t.readline()
            if not line:
                continue
            line = line.strip()
            if not line:
                continue
            
            # Check if encrypted (ENC: prefix)
            if line.startswith(b"ENC:"):
                raw = base64.b64decode(line[4:])
                if len(raw) < 12+16:
                    continue
                nonce, rest = raw[:12], raw[12:]
                ct, tag = rest[:-16], rest[-16:]
                pt = self._dec(nonce, ct, tag)
                return json.loads(pt.decode("utf-8"))
            
            # Otherwise, try to parse as plain JSON (for initial handshake)
            try:
                return json.loads(line.decode("utf-8"))
            except (json.JSONDecodeError, UnicodeDecodeError):
                continue  # Not valid JSON, keep waiting

