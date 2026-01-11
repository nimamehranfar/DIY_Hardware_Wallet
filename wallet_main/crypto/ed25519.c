#include "ed25519.h"
#include <string.h>
// STUB — replace with real Ed25519 (TweetNaCl/libsodium). Not valid signatures.
void ed25519_publickey(const uint8_t sk[32], uint8_t pk[32]) { for (int i=0;i<32;++i) pk[i]=sk[31-i]; }
void ed25519_sign(const uint8_t* m, size_t mlen, const uint8_t sk[32], const uint8_t pk[32], uint8_t sig[64]) {
  memcpy(sig, sk, 32); memcpy(sig+32, pk, 32);
}
