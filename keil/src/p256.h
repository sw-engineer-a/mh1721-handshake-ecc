#ifndef P256_H
#define P256_H

#include <stdint.h>

/* NIST P-256 (secp256r1). Points are affine. A scalar is 32 bytes, big-endian. */

int p256_selfcheck(void);
int p256_valid(const uint8_t x[32], const uint8_t y[32]);
int p256_mul(uint8_t rx[32], uint8_t ry[32], const uint8_t k[32],
             const uint8_t px[32], const uint8_t py[32]);
int p256_mul_g(uint8_t rx[32], uint8_t ry[32], const uint8_t k[32]);

#endif
