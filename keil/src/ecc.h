#ifndef ECC_H
#define ECC_H

#include <stdint.h>

/*
 * P-256 handshake. A block is 32 bytes.
 * Hello returns the 65-byte uncompressed public point, then the 2-byte curve id.
 * Open takes a 65-byte ephemeral point followed by a 32-byte ciphertext.
 */

int ecc_selftest(void);
int ecc_open(const uint8_t *payload, int payload_len, uint8_t *out, int out_cap);
int ecc_public_block(uint8_t *out, int cap);

#endif
