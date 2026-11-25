#include "ecc.h"
#include "key.h"
#include "p256.h"
#include "sha256.h"

#include <string.h>

static void mask_block(uint8_t out[ECC_BLOCK_BYTES], const uint8_t z[ECC_COORD_BYTES],
                       const uint8_t block[ECC_BLOCK_BYTES]) {
    uint8_t mask[32];
    int i;

    sha256(z, ECC_COORD_BYTES, mask);
    for (i = 0; i < ECC_BLOCK_BYTES; i++) {
        out[i] = (uint8_t)(block[i] ^ mask[i]);
    }
}

static int shared_x(uint8_t z[ECC_COORD_BYTES], const uint8_t k[ECC_SCALAR_BYTES],
                    const uint8_t px[ECC_COORD_BYTES], const uint8_t py[ECC_COORD_BYTES]) {
    uint8_t y[ECC_COORD_BYTES];
    return p256_mul(z, y, k, px, py);
}

int ecc_public_block(uint8_t *out, int cap) {
    int total = 2 + ECC_POINT_BYTES + 2 + ECC_CURVE_BYTES;

    if (!out || cap < total) {
        return -1;
    }
    out[0] = (uint8_t)(ECC_POINT_BYTES >> 8);
    out[1] = (uint8_t)ECC_POINT_BYTES;
    out[2] = 0x04;
    memcpy(out + 3, ECC_QX, ECC_COORD_BYTES);
    memcpy(out + 35, ECC_QY, ECC_COORD_BYTES);
    out[67] = (uint8_t)(ECC_CURVE_BYTES >> 8);
    out[68] = (uint8_t)ECC_CURVE_BYTES;
    memcpy(out + 69, ECC_CURVE, ECC_CURVE_BYTES);
    return total;
}

int ecc_open(const uint8_t *payload, int payload_len, uint8_t *out, int out_cap) {
    uint8_t z[ECC_COORD_BYTES];
    uint8_t plain[ECC_BLOCK_BYTES];

    if (!payload || !out || payload_len != ECC_OPEN_BYTES || out_cap < ECC_BLOCK_BYTES) {
        return -1;
    }
    if (payload[0] != 0x04 || !p256_valid(payload + 1, payload + 33)) {
        return -1;
    }
    if (!shared_x(z, ECC_D, payload + 1, payload + 33)) {
        return -1;
    }
    mask_block(plain, z, payload + ECC_POINT_BYTES);
    memcpy(out, plain, ECC_BLOCK_BYTES);
    return ECC_BLOCK_BYTES;
}

int ecc_selftest(void) {
    static const uint8_t abc_digest[32] = {
        0xba, 0x78, 0x16, 0xbf, 0x8f, 0x01, 0xcf, 0xea, 0x41, 0x41, 0x40, 0xde, 0x5d, 0xae, 0x22, 0x23,
        0xb0, 0x03, 0x61, 0xa3, 0x96, 0x17, 0x7a, 0x9c, 0xb4, 0x10, 0xff, 0x61, 0xf2, 0x00, 0x15, 0xad
    };
    uint8_t digest[32];
    uint8_t point[ECC_POINT_BYTES];
    uint8_t z_phone[ECC_COORD_BYTES];
    uint8_t z_board[ECC_COORD_BYTES];
    uint8_t cipher[ECC_BLOCK_BYTES];
    uint8_t opened[ECC_BLOCK_BYTES];
    uint8_t payload[ECC_OPEN_BYTES];
    uint8_t pub[80];
    int pub_len;

    sha256((const uint8_t *)"abc", 3, digest);
    if (memcmp(digest, abc_digest, 32) != 0 || !p256_selfcheck()) {
        return 0;
    }
    if (!p256_mul_g(point + 1, point + 33, ECC_D) ||
        memcmp(point + 1, ECC_QX, ECC_COORD_BYTES) != 0 ||
        memcmp(point + 33, ECC_QY, ECC_COORD_BYTES) != 0) {
        return 0;
    }
    if (!p256_mul_g(payload + 1, payload + 33, ECC_K) ||
        memcmp(payload + 1, ECC_RX, ECC_COORD_BYTES) != 0 ||
        memcmp(payload + 33, ECC_RY, ECC_COORD_BYTES) != 0) {
        return 0;
    }
    if (!shared_x(z_phone, ECC_K, ECC_QX, ECC_QY) ||
        !shared_x(z_board, ECC_D, ECC_RX, ECC_RY) ||
        memcmp(z_phone, z_board, ECC_COORD_BYTES) != 0) {
        return 0;
    }
    mask_block(cipher, z_phone, ECC_PLAIN);
    if (memcmp(cipher, ECC_CIPHER, ECC_BLOCK_BYTES) != 0) {
        return 0;
    }
    payload[0] = 0x04;
    memcpy(payload + ECC_POINT_BYTES, ECC_CIPHER, ECC_BLOCK_BYTES);
    if (ecc_open(payload, ECC_OPEN_BYTES, opened, ECC_BLOCK_BYTES) != ECC_BLOCK_BYTES ||
        memcmp(opened, ECC_PLAIN, ECC_BLOCK_BYTES) != 0) {
        return 0;
    }
    pub_len = ecc_public_block(pub, (int)sizeof(pub));
    if (pub_len != 2 + ECC_POINT_BYTES + 2 + ECC_CURVE_BYTES || pub[2] != 0x04) {
        return 0;
    }
    return memcmp(pub + 3, ECC_QX, ECC_COORD_BYTES) == 0 &&
           memcmp(pub + 35, ECC_QY, ECC_COORD_BYTES) == 0 &&
           memcmp(pub + 69, ECC_CURVE, ECC_CURVE_BYTES) == 0;
}
