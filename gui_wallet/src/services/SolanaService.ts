/**
 * SolanaService - Full Solana Transaction Support for React Native
 * Uses direct RPC calls with proper transaction serialization
 */
import bs58 from 'bs58';

// Default to devnet, can be changed via setRpcUrl
let RPC_URL = 'https://api.devnet.solana.com';

// System Program ID (for transfers)
const SYSTEM_PROGRAM_ID = '11111111111111111111111111111111';

// Export function to change RPC endpoint
export function setRpcUrl(url: string) {
    RPC_URL = url;
    console.log('[Solana] RPC URL changed to:', url);
}

export function getRpcUrl(): string {
    return RPC_URL;
}

class SolanaService {
    // Get balance in lamports
    async getBalance(pubkey: string): Promise<number> {
        try {
            const resp = await fetch(RPC_URL, {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({
                    jsonrpc: '2.0',
                    id: 1,
                    method: 'getBalance',
                    params: [pubkey],
                }),
            });
            const data = await resp.json();
            return data.result?.value || 0;
        } catch (e) {
            console.error('[Solana] Balance error:', e);
            return 0;
        }
    }

    // Get SOL price from CoinGecko
    async getSolPrice(): Promise<number> {
        try {
            const resp = await fetch(
                'https://api.coingecko.com/api/v3/simple/price?ids=solana&vs_currencies=usd'
            );
            const data = await resp.json();
            return data.solana?.usd || 0;
        } catch {
            return 0;
        }
    }

    // Request airdrop (devnet only)
    async requestAirdrop(pubkey: string, lamports: number = 1e9): Promise<string> {
        try {
            const resp = await fetch(RPC_URL, {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({
                    jsonrpc: '2.0',
                    id: 1,
                    method: 'requestAirdrop',
                    params: [pubkey, lamports],
                }),
            });
            const data = await resp.json();
            if (data.error) {
                throw new Error(data.error.message);
            }
            return data.result;
        } catch (e: any) {
            throw new Error(e.message || 'Airdrop failed');
        }
    }

    // Get latest blockhash
    async getLatestBlockhash(): Promise<{ blockhash: string; lastValidBlockHeight: number }> {
        const resp = await fetch(RPC_URL, {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({
                jsonrpc: '2.0',
                id: 1,
                method: 'getLatestBlockhash',
                params: [{ commitment: 'finalized' }],
            }),
        });
        const data = await resp.json();
        if (!data.result?.value?.blockhash) {
            throw new Error('Failed to get blockhash');
        }
        return {
            blockhash: data.result.value.blockhash,
            lastValidBlockHeight: data.result.value.lastValidBlockHeight,
        };
    }

    // Validate Solana address (base58, 32-44 chars)
    isValidAddress(address: string): boolean {
        if (!address || address.length < 32 || address.length > 44) {
            return false;
        }
        const base58Regex = /^[1-9A-HJ-NP-Za-km-z]+$/;
        return base58Regex.test(address);
    }

    /**
     * Build a Solana transfer transaction message
     * Returns the serialized message bytes for signing
     */
    buildTransferMessage(
        from: string,
        to: string,
        lamports: number,
        blockhash: string
    ): Uint8Array {
        const fromPubkey = bs58.decode(from);
        const toPubkey = bs58.decode(to);
        const programId = bs58.decode(SYSTEM_PROGRAM_ID);
        const blockhashBytes = bs58.decode(blockhash);

        // Build the transfer instruction data
        // SystemProgram::Transfer = instruction index 2
        // Data: [2 (u32 LE), lamports (u64 LE)]
        const instructionData = new Uint8Array(12);
        const view = new DataView(instructionData.buffer);
        view.setUint32(0, 2, true); // Transfer instruction = 2
        // Set lamports as little-endian u64
        view.setBigUint64(4, BigInt(lamports), true);

        // Build the message according to Solana spec:
        // Header: [num_required_signatures, num_readonly_signed, num_readonly_unsigned]
        // Account keys: [from, to, system_program]
        // Recent blockhash
        // Instructions

        const header = new Uint8Array([1, 0, 1]); // 1 signer, 0 readonly signed, 1 readonly unsigned

        // Compact array encoding for account keys (3 accounts)
        const numAccounts = 3;
        const accountKeys = new Uint8Array(1 + 32 * 3);
        accountKeys[0] = numAccounts;
        accountKeys.set(fromPubkey, 1);
        accountKeys.set(toPubkey, 33);
        accountKeys.set(programId, 65);

        // Instructions compact array (1 instruction)
        // Instruction format: program_id_index, accounts_length, account_indices..., data_length, data...
        const instruction = new Uint8Array([
            1,                      // Number of instructions
            2,                      // Program ID index (System Program = index 2)
            2,                      // Number of account indices
            0, 1,                   // Account indices [from=0, to=1]
            instructionData.length, // Data length
            ...instructionData,     // Data
        ]);

        // Build the full message
        const message = new Uint8Array(
            header.length +
            accountKeys.length +
            32 + // blockhash
            instruction.length
        );

        let offset = 0;
        message.set(header, offset);
        offset += header.length;
        message.set(accountKeys, offset);
        offset += accountKeys.length;
        message.set(blockhashBytes, offset);
        offset += 32;
        message.set(instruction, offset);

        console.log('[Solana] Built message:', message.length, 'bytes');
        return message;
    }

    /**
     * Prepare a transfer for ESP32 signing
     * Returns the message as hex string for the SIGN command
     */
    async prepareTransfer(
        from: string,
        to: string,
        lamports: number
    ): Promise<{ messageHex: string; blockhash: string; messageBytes: Uint8Array }> {
        const { blockhash } = await this.getLatestBlockhash();

        const messageBytes = this.buildTransferMessage(from, to, lamports, blockhash);
        const messageHex = Buffer.from(messageBytes).toString('hex');

        console.log('[Solana] Prepared transfer:');
        console.log('  From:', from);
        console.log('  To:', to);
        console.log('  Amount:', lamports, 'lamports');
        console.log('  Blockhash:', blockhash);
        console.log('  Message hex:', messageHex.substring(0, 64) + '...');

        return { messageHex, blockhash, messageBytes };
    }

    /**
     * Build and broadcast a signed transaction
     */
    async sendSignedTransaction(
        messageBytes: Uint8Array,
        signatureHex: string
    ): Promise<string> {
        // Convert hex signature to bytes
        const signature = new Uint8Array(
            signatureHex.match(/.{1,2}/g)!.map(byte => parseInt(byte, 16))
        );

        if (signature.length !== 64) {
            throw new Error(`Invalid signature length: ${signature.length}, expected 64`);
        }

        // Build the signed transaction
        // Format: [signatures_length, signature, message]
        const signedTx = new Uint8Array(1 + 64 + messageBytes.length);
        signedTx[0] = 1; // 1 signature
        signedTx.set(signature, 1);
        signedTx.set(messageBytes, 65);

        // Encode as base64 for sendTransaction
        const txBase64 = Buffer.from(signedTx).toString('base64');

        console.log('[Solana] Broadcasting transaction...');
        console.log('[Solana] Signature:', signatureHex.substring(0, 32) + '...');

        const resp = await fetch(RPC_URL, {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({
                jsonrpc: '2.0',
                id: 1,
                method: 'sendTransaction',
                params: [
                    txBase64,
                    {
                        encoding: 'base64',
                        skipPreflight: false,
                        preflightCommitment: 'confirmed',
                    },
                ],
            }),
        });

        const data = await resp.json();

        if (data.error) {
            console.error('[Solana] Transaction error:', data.error);
            throw new Error(data.error.message || 'Transaction failed');
        }

        const txSignature = data.result;
        console.log('[Solana] Transaction sent!');
        console.log('[Solana] Signature:', txSignature);

        return txSignature;
    }

    /**
     * Get transaction status
     */
    async getTransactionStatus(signature: string): Promise<'confirmed' | 'finalized' | 'failed' | 'pending'> {
        try {
            const resp = await fetch(RPC_URL, {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({
                    jsonrpc: '2.0',
                    id: 1,
                    method: 'getSignatureStatuses',
                    params: [[signature]],
                }),
            });
            const data = await resp.json();
            const status = data.result?.value?.[0];

            if (!status) return 'pending';
            if (status.err) return 'failed';
            if (status.confirmationStatus === 'finalized') return 'finalized';
            if (status.confirmationStatus === 'confirmed') return 'confirmed';
            return 'pending';
        } catch {
            return 'pending';
        }
    }

    /**
     * Get explorer URL for a transaction
     */
    getExplorerUrl(signature: string): string {
        return `https://explorer.solana.com/tx/${signature}?cluster=devnet`;
    }

    /**
     * Get recent transaction history for an address
     */
    async getTransactionHistory(pubkey: string, limit: number = 10): Promise<Array<{
        signature: string;
        slot: number;
        blockTime: number | null;
        err: any;
        type: 'send' | 'receive' | 'unknown';
        amount: number;
        otherParty: string;
    }>> {
        try {
            // Get recent signatures
            const sigResp = await fetch(RPC_URL, {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({
                    jsonrpc: '2.0',
                    id: 1,
                    method: 'getSignaturesForAddress',
                    params: [pubkey, { limit }],
                }),
            });
            const sigData = await sigResp.json();
            const signatures = sigData.result || [];

            if (signatures.length === 0) return [];

            // Get transaction details for each signature
            const txPromises = signatures.slice(0, 5).map(async (sig: any) => {
                try {
                    const txResp = await fetch(RPC_URL, {
                        method: 'POST',
                        headers: { 'Content-Type': 'application/json' },
                        body: JSON.stringify({
                            jsonrpc: '2.0',
                            id: 1,
                            method: 'getTransaction',
                            params: [sig.signature, { encoding: 'jsonParsed', maxSupportedTransactionVersion: 0 }],
                        }),
                    });
                    const txData = await txResp.json();
                    const tx = txData.result;

                    if (!tx) return null;

                    // Parse transaction
                    const meta = tx.meta;
                    const preBalances = meta?.preBalances || [];
                    const postBalances = meta?.postBalances || [];
                    const accountKeys = tx.transaction?.message?.accountKeys || [];

                    // Find this wallet's index
                    const walletIndex = accountKeys.findIndex((key: any) =>
                        (typeof key === 'string' ? key : key.pubkey) === pubkey
                    );

                    let type: 'send' | 'receive' | 'unknown' = 'unknown';
                    let amount = 0;
                    let otherParty = '';

                    if (walletIndex >= 0 && preBalances[walletIndex] !== undefined) {
                        const diff = postBalances[walletIndex] - preBalances[walletIndex];
                        if (diff > 0) {
                            type = 'receive';
                            amount = diff;
                            // Find sender (first signer that's not us)
                            otherParty = accountKeys[0]?.pubkey || accountKeys[0] || 'Unknown';
                        } else if (diff < 0) {
                            type = 'send';
                            amount = Math.abs(diff);
                            // Find receiver (second account typically)
                            otherParty = accountKeys[1]?.pubkey || accountKeys[1] || 'Unknown';
                        }
                    }

                    return {
                        signature: sig.signature,
                        slot: sig.slot,
                        blockTime: tx.blockTime,
                        err: sig.err,
                        type,
                        amount,
                        otherParty: typeof otherParty === 'string' ? otherParty : otherParty || 'Unknown',
                    };
                } catch {
                    return null;
                }
            });

            const results = await Promise.all(txPromises);
            return results.filter((tx): tx is NonNullable<typeof tx> => tx !== null);
        } catch (e) {
            console.error('[Solana] Transaction history error:', e);
            return [];
        }
    }
}

export const solanaService = new SolanaService();
