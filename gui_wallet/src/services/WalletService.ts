/**
 * WalletService - Secure communication layer for ESP32 Hardware Wallet
 * 
 * SECURITY: All commands are encrypted using ECDH + AES-GCM after initial handshake.
 * The WebSocket transport layer carries encrypted payloads.
 */

import { secureChannel, SecureChannel } from './SecureChannel';
import { Alert } from 'react-native';

export interface WalletResponse {
  ok: boolean;
  error?: string;
  pubkey?: string;
  sig_b58?: string;
  pong?: boolean;
  ecdh_pub?: string;
  salt?: string;
}

class WalletService {
  private ws: WebSocket | null = null;
  private connected = false;
  private secureChannelEstablished = false;
  private pendingResolves: Map<string, (value: WalletResponse) => void> = new Map();
  private ourPublicKeyHex: string = '';

  // Connect to ESP32 and establish secure channel
  async connect(ip: string, port: number = 8444): Promise<boolean> {
    return new Promise((resolve, reject) => {
      try {
        const url = `ws://${ip}:${port}`;
        console.log(`[WS] Connecting to ${url}...`);

        this.ws = new WebSocket(url);

        this.ws.onopen = async () => {
          console.log('[WS] Connected');
          this.connected = true;

          try {
            // Generate keypair and perform ECDH key exchange
            const { publicKeyHex } = secureChannel.generateKeyPair();
            this.ourPublicKeyHex = publicKeyHex;

            // Send KEY_EXCHANGE (only X coordinate)
            const xCoordHex = publicKeyHex.slice(2, 66);
            this.ws?.send(JSON.stringify({ cmd: 'KEY_EXCHANGE', pubkey: xCoordHex }));
          } catch (e: any) {
            console.error('[WS] Handshake failed:', e.message);
            reject(new Error('Handshake failed: ' + e.message));
          }
        };

        this.ws.onclose = () => {
          console.log('[WS] Disconnected');
          this.connected = false;
          this.secureChannelEstablished = false;
          secureChannel.reset();
        };

        this.ws.onerror = (error) => {
          console.error('[WS] Error:', error);
          reject(error);
        };

        this.ws.onmessage = (event) => {
          try {
            // Check if this is the KEY_EXCHANGE response
            if (!this.secureChannelEstablished) {
              const data: WalletResponse & { status?: string; code?: string } = JSON.parse(event.data);

              // Step 1: Pending response with pairing code (user must approve on device)
              if (data.status === 'pending' && data.ecdh_pub && data.salt) {
                console.log('[WS] Received pairing code, waiting for device approval...');

                // Complete key exchange to derive same pairing code
                if (secureChannel.completeKeyExchange(data.ecdh_pub, data.salt)) {
                  const pairingCode = secureChannel.getPairingCode();
                  console.log('[WS] Pairing code: ' + pairingCode);

                  // Show code to user while they verify on device
                  Alert.alert(
                    'Verify Pairing Code',
                    `Code: ${pairingCode || data.code}\n\nConfirm this matches the code on your device, then press OK on the device.`,
                    [{ text: 'OK', style: 'default' }]
                  );
                } else {
                  reject(new Error('Key derivation failed'));
                }
                // Don't resolve yet - wait for confirmed response
                return;
              }

              // Step 2: Confirmed response (user approved on device)
              if (data.ok === true && data.ecdh_pub && data.salt) {
                console.log('[WS] Device approved connection!');

                // If we haven't completed key exchange yet (shouldn't happen)
                if (!secureChannel.isReady()) {
                  secureChannel.completeKeyExchange(data.ecdh_pub, data.salt);
                }

                this.secureChannelEstablished = true;
                console.log('[WS] Secure channel established!');
                resolve(true);
                return;
              }

              // Error response
              if (data.error) {
                if (data.error === 'user_denied') {
                  reject(new Error('Connection denied by user on device'));
                } else {
                  reject(new Error(data.error));
                }
                return;
              }
            }

            // Handle encrypted responses
            if (this.secureChannelEstablished) {
              // Try to decrypt if it looks like hex
              const rawData = event.data as string;
              if (/^[0-9a-fA-F]+$/.test(rawData) && rawData.length > 24) {
                const decrypted = secureChannel.decrypt(rawData);
                if (decrypted) {
                  const data: WalletResponse = JSON.parse(decrypted);
                  console.log('[WS] Received (decrypted):', data);
                  this.resolveAllPending(data);
                  return;
                }
              }

              // Fallback: try parsing as unencrypted JSON (for compatibility)
              const data: WalletResponse = JSON.parse(rawData);
              console.log('[WS] Received:', data);
              this.resolveAllPending(data);
            } else {
              // Before secure channel, parse as JSON
              const data: WalletResponse = JSON.parse(event.data);
              console.log('[WS] Received:', data);
              this.resolveAllPending(data);
            }
          } catch (e) {
            console.error('[WS] Parse error:', e);
          }
        };

        // Timeout after 15 seconds
        setTimeout(() => {
          if (!this.secureChannelEstablished) {
            reject(new Error('Secure channel timeout'));
          }
        }, 15000);

      } catch (e) {
        reject(e);
      }
    });
  }

  private resolveAllPending(data: WalletResponse) {
    this.pendingResolves.forEach((resolve, key) => {
      resolve(data);
      this.pendingResolves.delete(key);
    });
  }

  // Disconnect from ESP32
  disconnect() {
    if (this.ws) {
      this.ws.close();
      this.ws = null;
      this.connected = false;
      this.secureChannelEstablished = false;
      secureChannel.reset();
    }
  }

  // Send encrypted command and wait for response
  private async sendCommand(cmd: object): Promise<WalletResponse> {
    return new Promise((resolve, reject) => {
      if (!this.ws || !this.connected) {
        reject(new Error('Not connected'));
        return;
      }

      if (!this.secureChannelEstablished) {
        reject(new Error('Secure channel not established'));
        return;
      }

      const id = Date.now().toString();
      this.pendingResolves.set(id, resolve);

      const payload = JSON.stringify(cmd);

      // SECURITY: Encrypt all commands
      const encrypted = secureChannel.encrypt(payload);
      if (!encrypted) {
        this.pendingResolves.delete(id);
        reject(new Error('Encryption failed'));
        return;
      }

      console.log('[WS] Sending encrypted command');
      this.ws.send(encrypted);

      // Timeout after 60 seconds (for signing which requires user interaction)
      setTimeout(() => {
        if (this.pendingResolves.has(id)) {
          this.pendingResolves.delete(id);
          reject(new Error('Command timeout'));
        }
      }, 60000);
    });
  }

  // Get public key from device
  async getPublicKey(): Promise<string> {
    const resp = await this.sendCommand({ cmd: 'PUBKEY' });
    if (resp.ok && resp.pubkey) {
      return resp.pubkey;
    }
    throw new Error(resp.error || 'Failed to get public key');
  }

  // Request signature from device
  async sign(message: string): Promise<string> {
    const resp = await this.sendCommand({
      cmd: 'SIGN',
      msg: message,
      nonce: Date.now(),
      ts: Math.floor(Date.now() / 1000),
    });
    if (resp.ok && resp.sig_b58) {
      return resp.sig_b58;
    }
    throw new Error(resp.error || 'Signing failed');
  }

  // Ping device to check connection
  async ping(): Promise<boolean> {
    const resp = await this.sendCommand({ cmd: 'PING' });
    return resp.pong === true;
  }

  // Show mnemonic on device
  async showMnemonic(): Promise<boolean> {
    const resp = await this.sendCommand({ cmd: 'SHOW_MNEMONIC' });
    return resp.ok === true;
  }

  // Set WiFi credentials (SECURITY: now encrypted!)
  async setWifi(ssid: string, password: string): Promise<boolean> {
    const resp = await this.sendCommand({ cmd: 'SET_WIFI', ssid, password });
    return resp.ok === true;
  }

  // Initialize recovery - displays 6-digit code on device
  // SECURITY: User must physically see device to get this code
  async initRecovery(): Promise<boolean> {
    const resp = await this.sendCommand({ cmd: 'RECOVERY_INIT' });
    if (resp.ok) {
      console.log('[Wallet] Recovery code displayed on device');
      return true;
    }
    throw new Error(resp.error || 'Failed to init recovery');
  }

  // Recover wallet from mnemonic 
  // SECURITY: Requires device code for physical access verification
  async recover(words: string[], deviceCode: number): Promise<boolean> {
    if (words.length !== 12) {
      throw new Error('Mnemonic must be exactly 12 words');
    }
    if (!deviceCode || deviceCode < 0 || deviceCode > 999999) {
      throw new Error('Invalid device code - must be 6 digits');
    }

    const cmd: any = {
      cmd: 'RECOVER',
      device_code: deviceCode
    };
    words.forEach((word, i) => {
      cmd[`word${i}`] = word;
    });

    const resp = await this.sendCommand(cmd);
    return resp.ok === true;
  }

  // Factory reset device
  async factoryReset(): Promise<boolean> {
    const resp = await this.sendCommand({ cmd: 'FACTORY_RESET' });
    return resp.ok === true;
  }

  // Check if connected with secure channel
  isConnected(): boolean {
    return this.connected && this.secureChannelEstablished;
  }

  // Check if secure channel is established
  isSecure(): boolean {
    return this.secureChannelEstablished;
  }
}

// Singleton instance
export const walletService = new WalletService();
