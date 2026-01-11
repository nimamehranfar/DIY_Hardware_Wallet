/**
 * SecureChannel - ECDH + AES-GCM encrypted communication with ESP32
 * 
 * SECURITY: All sensitive data is encrypted before transmission.
 * Uses secp256r1 (P-256) ECDH for key exchange, SHA-256 for key derivation,
 * and AES-128-GCM for authenticated encryption.
 */

// Use '.js' extensions for Expo/Metro bundler compatibility
import { p256 } from '@noble/curves/nist.js';
import { sha256 } from '@noble/hashes/sha2.js';
import { gcm } from '@noble/ciphers/aes.js';
import { bytesToHex, hexToBytes } from '@noble/hashes/utils.js';
import * as Crypto from 'expo-crypto';

export class SecureChannel {
    private sharedKey: Uint8Array | null = null;
    private salt: Uint8Array | null = null;
    private privateKey: Uint8Array | null = null;
    private publicKey: Uint8Array | null = null;
    private txCounter: number = 1;
    private ready: boolean = false;
    private pairingCode: number | null = null;

    /**
     * Generate our keypair for ECDH
     */
    generateKeyPair(): { publicKey: Uint8Array; publicKeyHex: string } {
        // Use expo-crypto for React Native compatible random bytes
        this.privateKey = Crypto.getRandomBytes(32);
        this.publicKey = p256.getPublicKey(this.privateKey, false); // uncompressed 65 bytes

        return {
            publicKey: this.publicKey,
            publicKeyHex: bytesToHex(this.publicKey),
        };
    }

    /**
     * Complete key exchange with ESP32's response
     * @param espPublicKeyHex - ESP32's 65-byte uncompressed public key as hex
     * @param saltHex - 8-byte session salt as hex
     */
    completeKeyExchange(espPublicKeyHex: string, saltHex: string): boolean {
        if (!this.privateKey || !this.publicKey) {
            console.error('[SecureChannel] Key pair not generated');
            return false;
        }

        try {
            const espPublicKey = hexToBytes(espPublicKeyHex);
            this.salt = hexToBytes(saltHex);

            // Derive shared secret using ECDH
            const sharedPoint = p256.getSharedSecret(this.privateKey, espPublicKey);

            // Derive key using same method as ESP32:
            // ESP32 uses: wallet_pub (ESP) + peerPub (App) + salt
            // So we must use: ESP_X + App_X + salt to match
            const keyMaterial = new Uint8Array(72);
            keyMaterial.set(espPublicKey.slice(1, 33), 0);   // ESP's X coord FIRST
            keyMaterial.set(this.publicKey.slice(1, 33), 32); // Our X coord SECOND
            keyMaterial.set(this.salt, 64);                   // Session salt

            const hash = sha256(keyMaterial);
            this.sharedKey = hash.slice(0, 16); // First 16 bytes as AES-128 key

            // Calculate pairing code from hash (bytes 16-18) - same algorithm as ESP32
            // pairingCode = (hash[16] << 16 | hash[17] << 8 | hash[18]) % 1000000
            this.pairingCode = ((hash[16] << 16) | (hash[17] << 8) | hash[18]) % 1000000;

            this.txCounter = 1;
            this.ready = true;

            console.log('[SecureChannel] Key exchange complete');
            return true;
        } catch (e) {
            console.error('[SecureChannel] Key exchange failed:', e);
            return false;
        }
    }

    /**
     * Get the 6-digit pairing code for user verification
     */
    getPairingCode(): string | null {
        if (this.pairingCode === null) return null;
        return this.pairingCode.toString().padStart(6, '0');
    }

    /**
     * Encrypt a message using AES-128-GCM
     */
    encrypt(plaintext: string): string | null {
        if (!this.ready || !this.sharedKey || !this.salt) {
            console.error('[SecureChannel] Channel not ready');
            return null;
        }

        try {
            // Generate nonce: salt (8) + counter (4) = 12 bytes
            const nonce = new Uint8Array(12);
            nonce.set(this.salt, 0);
            const counterBytes = new Uint8Array(4);
            new DataView(counterBytes.buffer).setUint32(0, this.txCounter++, true);
            nonce.set(counterBytes, 8);

            // Encrypt with AES-GCM
            const cipher = gcm(this.sharedKey, nonce);
            const plaintextBytes = new TextEncoder().encode(plaintext);
            const ciphertext = cipher.encrypt(plaintextBytes);

            // Return as hex: nonce (12) + ciphertext (includes 16-byte tag)
            return bytesToHex(nonce) + bytesToHex(ciphertext);
        } catch (e) {
            console.error('[SecureChannel] Encryption failed:', e);
            return null;
        }
    }

    /**
     * Decrypt a message using AES-128-GCM
     */
    decrypt(ciphertextHex: string): string | null {
        if (!this.ready || !this.sharedKey) {
            console.error('[SecureChannel] Channel not ready');
            return null;
        }

        try {
            const data = hexToBytes(ciphertextHex);
            const nonce = data.slice(0, 12);
            const ciphertext = data.slice(12);

            const cipher = gcm(this.sharedKey, nonce);
            const plaintext = cipher.decrypt(ciphertext);

            return new TextDecoder().decode(plaintext);
        } catch (e) {
            console.error('[SecureChannel] Decryption failed:', e);
            return null;
        }
    }

    /**
     * Check if secure channel is ready
     */
    isReady(): boolean {
        return this.ready;
    }

    /**
     * Reset the channel (disconnect)
     */
    reset(): void {
        this.sharedKey = null;
        this.salt = null;
        this.privateKey = null;
        this.publicKey = null;
        this.pairingCode = null;
        this.txCounter = 1;
        this.ready = false;
    }
}

// Singleton instance
export const secureChannel = new SecureChannel();
