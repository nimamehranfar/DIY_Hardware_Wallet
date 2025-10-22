#pragma once
#include <stdint.h>
#ifdef __cplusplus
extern "C" {
#endif
void ed25519_publickey(const uint8_t sk[32], uint8_t pk[32]);
void ed25519_sign(const uint8_t* m, size_t mlen, const uint8_t sk[32], const uint8_t pk[32], uint8_t sig[64]);
#ifdef __cplusplus
}
#endif
