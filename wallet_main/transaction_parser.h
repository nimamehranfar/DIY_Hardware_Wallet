#pragma once
/**
 * transaction_parser.h - Solana Transaction Parser for Hardware Wallet
 * 
 * Parses Solana transactions to display:
 * - Recipient address
 * - Amount (in SOL)
 * - Program type (System, Token, etc.)
 */

#include <Arduino.h>
#include "mbedtls/base64.h"

// Solana Program IDs (first 4 bytes of pubkey)
const uint8_t SYSTEM_PROGRAM_PREFIX[] = {0x00, 0x00, 0x00, 0x00};
const uint8_t TOKEN_PROGRAM_PREFIX[] = {0x06, 0xdd, 0xf6, 0xe1};  // TokenkegQfeZyiNwAJbNbGKPFXCWuBvf9Ss623VQ5DA

// Transaction types
enum TxType {
  TX_UNKNOWN,
  TX_TRANSFER_SOL,
  TX_TRANSFER_TOKEN,
  TX_CREATE_ACCOUNT,
  TX_OTHER
};

// Parsed transaction info
struct ParsedTx {
  TxType type;
  uint8_t recipient[32];      // Destination pubkey
  uint64_t amount;            // Lamports or token amount
  uint8_t decimals;           // Token decimals (if token transfer)
  bool parsed;                // Was able to parse
  const char* programName;    // Human readable program name
};

// Base58 encode for display (truncated)
inline void pubkeyToShortString(const uint8_t pk[32], char* out, size_t maxLen) {
  // Simple hex representation: first 4 + ... + last 4
  if (maxLen >= 14) {
    snprintf(out, maxLen, "%02X%02X..%02X%02X", 
             pk[0], pk[1], pk[30], pk[31]);
  } else {
    out[0] = '\0';
  }
}

// Convert lamports to SOL (with decimals)
inline void lamportsToSol(uint64_t lamports, char* out, size_t maxLen) {
  uint64_t sol = lamports / 1000000000ULL;
  uint64_t decimals = (lamports % 1000000000ULL) / 10000000ULL;  // 2 decimals
  snprintf(out, maxLen, "%llu.%02llu SOL", sol, decimals);
}

// Parse Solana transaction
// Transaction format (simplified):
// - Header: numSigs (1), numReadonly (1), numReadonlyUnsigned (1)
// - Account keys: compact array of 32-byte pubkeys
// - Recent blockhash: 32 bytes
// - Instructions: compact array of instruction data
inline ParsedTx parseSolanaTx(const uint8_t* txData, size_t txLen) {
  ParsedTx result;
  result.type = TX_UNKNOWN;
  result.parsed = false;
  result.amount = 0;
  result.decimals = 9;
  result.programName = "Unknown";
  memset(result.recipient, 0, 32);

  if (txLen < 100) {
    return result;  // Too short to be valid
  }

  // Skip signature (we're given the message portion usually)
  size_t pos = 0;
  
  // Read header
  uint8_t numRequiredSigs = txData[pos++];
  uint8_t numReadonlySigned = txData[pos++];
  uint8_t numReadonlyUnsigned = txData[pos++];
  
  // Read number of account keys (compact-u16)
  uint8_t numAccounts = txData[pos++];
  if (numAccounts > 64 || pos + numAccounts * 32 > txLen) {
    return result;  // Invalid
  }
  
  // Store account keys
  uint8_t accounts[16][32];  // Max 16 accounts for our parsing
  int storedAccounts = numAccounts > 16 ? 16 : numAccounts;
  for (int i = 0; i < storedAccounts; i++) {
    memcpy(accounts[i], &txData[pos], 32);
    pos += 32;
  }
  pos += (numAccounts - storedAccounts) * 32;  // Skip rest
  
  // Skip blockhash
  pos += 32;
  
  // Read number of instructions
  if (pos >= txLen) return result;
  uint8_t numInstructions = txData[pos++];
  
  // Parse first instruction (most important)
  if (numInstructions > 0 && pos < txLen) {
    uint8_t programIdIndex = txData[pos++];
    
    if (programIdIndex < storedAccounts) {
      // Check if System Program (all zeros)
      bool isSystemProgram = true;
      for (int i = 0; i < 32; i++) {
        if (accounts[programIdIndex][i] != 0) {
          isSystemProgram = false;
          break;
        }
      }
      
      if (isSystemProgram) {
        result.programName = "System";
        
        // Parse System instruction
        uint8_t numAccountIdxs = txData[pos++];
        pos += numAccountIdxs;  // Skip account indices
        
        uint8_t dataLen = txData[pos++];
        if (dataLen >= 12 && pos + dataLen <= txLen) {
          uint32_t instrType = *(uint32_t*)&txData[pos];
          
          if (instrType == 2) {  // Transfer
            result.type = TX_TRANSFER_SOL;
            result.amount = *(uint64_t*)&txData[pos + 4];
            
            // Get destination from account indices
            if (numAccountIdxs >= 2) {
              uint8_t destIdx = txData[pos - dataLen - numAccountIdxs + 1];
              if (destIdx < storedAccounts) {
                memcpy(result.recipient, accounts[destIdx], 32);
              }
            }
            result.parsed = true;
          } else if (instrType == 0) {
            result.type = TX_CREATE_ACCOUNT;
            result.programName = "CreateAcct";
            result.parsed = true;
          }
        }
      } else {
        // Check for Token Program
        if (memcmp(accounts[programIdIndex], TOKEN_PROGRAM_PREFIX, 4) == 0) {
          result.programName = "Token";
          result.type = TX_TRANSFER_TOKEN;
          result.parsed = true;
        }
      }
    }
  }
  
  return result;
}

// Display parsed transaction on OLED (caller provides u8g2)
// Returns true if user approves, false if rejects
inline void displayParsedTx(const ParsedTx& tx, char* line1, char* line2, char* line3, size_t maxLen) {
  if (tx.type == TX_TRANSFER_SOL) {
    strncpy(line1, "SEND SOL", maxLen);
    
    char recipientStr[16];
    pubkeyToShortString(tx.recipient, recipientStr, sizeof(recipientStr));
    snprintf(line2, maxLen, "To: %s", recipientStr);
    
    lamportsToSol(tx.amount, line3, maxLen);
    
  } else if (tx.type == TX_TRANSFER_TOKEN) {
    strncpy(line1, "TOKEN TRANSFER", maxLen);
    strncpy(line2, "SPL Token", maxLen);
    strncpy(line3, "Check details!", maxLen);
    
  } else if (tx.type == TX_CREATE_ACCOUNT) {
    strncpy(line1, "CREATE ACCOUNT", maxLen);
    strncpy(line2, "New account", maxLen);
    lamportsToSol(tx.amount, line3, maxLen);
    
  } else {
    strncpy(line1, "UNKNOWN TX", maxLen);
    snprintf(line2, maxLen, "Prog: %s", tx.programName);
    strncpy(line3, "Review carefully!", maxLen);
  }
}
