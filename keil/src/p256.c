#include "p256.h"

#include <string.h>

/*
 * Field elements are eight little-endian 32-bit limbs.
 * p = 2^256 - 2^224 + 2^192 + 2^96 - 1
 * a = -3, so the doubling formula uses (X - Z^2) * (X + Z^2).
 * Points in the scalar loop are Jacobian: (X : Y : Z) is (X/Z^2, Y/Z^3).
 */

static const uint32_t FE_P[8] = {
    0xFFFFFFFFu, 0xFFFFFFFFu, 0xFFFFFFFFu, 0x00000000u,
    0x00000000u, 0x00000000u, 0x00000001u, 0xFFFFFFFFu
};

/* 2^256 - p = 2^224 - 2^192 - 2^96 + 1 */
static const uint32_t FE_DELTA[8] = {
    0x00000001u, 0x00000000u, 0x00000000u, 0xFFFFFFFFu,
    0xFFFFFFFFu, 0xFFFFFFFFu, 0xFFFFFFFEu, 0x00000000u
};

static const uint8_t B_BYTES[32] = {
    0x5A, 0xC6, 0x35, 0xD8, 0xAA, 0x3A, 0x93, 0xE7, 0xB3, 0xEB, 0xBD, 0x55, 0x76, 0x98, 0x86, 0xBC,
    0x65, 0x1D, 0x06, 0xB0, 0xCC, 0x53, 0xB0, 0xF6, 0x3B, 0xCE, 0x3C, 0x3E, 0x27, 0xD2, 0x60, 0x4B
};

static const uint8_t GX_BYTES[32] = {
    0x6B, 0x17, 0xD1, 0xF2, 0xE1, 0x2C, 0x42, 0x47, 0xF8, 0xBC, 0xE6, 0xE5, 0x63, 0xA4, 0x40, 0xF2,
    0x77, 0x03, 0x7D, 0x81, 0x2D, 0xEB, 0x33, 0xA0, 0xF4, 0xA1, 0x39, 0x45, 0xD8, 0x98, 0xC2, 0x96
};

static const uint8_t GY_BYTES[32] = {
    0x4F, 0xE3, 0x42, 0xE2, 0xFE, 0x1A, 0x7F, 0x9B, 0x8E, 0xE7, 0xEB, 0x4A, 0x7C, 0x0F, 0x9E, 0x16,
    0x2B, 0xCE, 0x33, 0x57, 0x6B, 0x31, 0x5E, 0xCE, 0xCB, 0xB6, 0x40, 0x68, 0x37, 0xBF, 0x51, 0xF5
};

static int fe_failed;

typedef struct {
    uint32_t x[8];
    uint32_t y[8];
    uint32_t z[8];
} jac_point;

static void fe_copy(uint32_t r[8], const uint32_t a[8]) {
    int i;
    for (i = 0; i < 8; i++) {
        r[i] = a[i];
    }
}

static int fe_cmp(const uint32_t a[8], const uint32_t b[8]) {
    int i;
    for (i = 7; i >= 0; i--) {
        if (a[i] != b[i]) {
            return a[i] > b[i] ? 1 : -1;
        }
    }
    return 0;
}

static int fe_is_zero(const uint32_t a[8]) {
    int i;
    for (i = 0; i < 8; i++) {
        if (a[i] != 0) {
            return 0;
        }
    }
    return 1;
}

static void fe_set_one(uint32_t r[8]) {
    memset(r, 0, 8 * sizeof(uint32_t));
    r[0] = 1u;
}

static uint32_t add_raw(uint32_t r[8], const uint32_t a[8], const uint32_t b[8]) {
    uint64_t carry = 0;
    int i;
    for (i = 0; i < 8; i++) {
        carry += (uint64_t)a[i] + b[i];
        r[i] = (uint32_t)carry;
        carry >>= 32;
    }
    return (uint32_t)carry;
}

static uint32_t sub_raw(uint32_t r[8], const uint32_t a[8], const uint32_t b[8]) {
    uint32_t borrow = 0;
    int i;
    for (i = 0; i < 8; i++) {
        uint64_t wide = (uint64_t)a[i];
        uint64_t take = (uint64_t)b[i] + borrow;
        r[i] = (uint32_t)(wide - take);
        borrow = wide < take;
    }
    return borrow;
}

static void fe_add(uint32_t r[8], const uint32_t a[8], const uint32_t b[8]) {
    uint32_t sum[8];
    uint32_t carry = add_raw(sum, a, b);
    if (carry) {
        /* a and b are reduced, so a + b = 2^256 + sum = sum + (2^256 - p) mod p. */
        add_raw(r, sum, FE_DELTA);
    } else if (fe_cmp(sum, FE_P) >= 0) {
        sub_raw(r, sum, FE_P);
    } else {
        fe_copy(r, sum);
    }
}

static void fe_sub(uint32_t r[8], const uint32_t a[8], const uint32_t b[8]) {
    uint32_t diff[8];
    if (sub_raw(diff, a, b)) {
        add_raw(r, diff, FE_P);
    } else {
        fe_copy(r, diff);
    }
}

static int acc_add_word(uint32_t *acc, int n, int index, uint32_t word) {
    uint64_t carry = word;
    int i;
    for (i = index; i < n; i++) {
        carry += acc[i];
        acc[i] = (uint32_t)carry;
        carry >>= 32;
        if (carry == 0) {
            return 1;
        }
    }
    return 0;
}

static int acc_sub_word(uint32_t *acc, int n, int index, uint32_t word) {
    uint32_t borrow = word;
    int i;
    for (i = index; i < n; i++) {
        uint32_t cur = acc[i];
        acc[i] = cur - borrow;
        if (cur >= borrow) {
            return 1;
        }
        borrow = 1u;
    }
    return 0;
}

/* Fold a 512-bit product with 2^256 ≡ 2^224 - 2^192 - 2^96 + 1 (mod p). */
static int fe_reduce(uint32_t r[8], const uint32_t prod[16]) {
    enum { ACC_WORDS = 24 };
    uint32_t acc[ACC_WORDS];
    uint32_t high[16];
    int round;
    int i;

    memset(acc, 0, sizeof(acc));
    for (i = 0; i < 16; i++) {
        acc[i] = prod[i];
    }
    /* c is about 2^224, so each pass removes about 32 bits. A 512-bit product needs several passes. */
    for (round = 0; round < 12; round++) {
        int pending = 0;
        for (i = 8; i < ACC_WORDS; i++) {
            if (acc[i] != 0) {
                pending = 1;
            }
        }
        if (!pending) {
            break;
        }
        for (i = 0; i < 16; i++) {
            high[i] = acc[8 + i];
        }
        for (i = 8; i < ACC_WORDS; i++) {
            acc[i] = 0;
        }
        for (i = 0; i < 16; i++) {
            uint32_t word = high[i];
            if (word == 0) {
                continue;
            }
            if (i + 7 >= ACC_WORDS ||
                !acc_add_word(acc, ACC_WORDS, i, word) ||
                !acc_add_word(acc, ACC_WORDS, i + 7, word) ||
                !acc_sub_word(acc, ACC_WORDS, i + 6, word) ||
                !acc_sub_word(acc, ACC_WORDS, i + 3, word)) {
                return 0;
            }
        }
    }
    for (i = 8; i < ACC_WORDS; i++) {
        if (acc[i] != 0) {
            return 0;
        }
    }
    for (round = 0; round < 2; round++) {
        if (fe_cmp(acc, FE_P) < 0) {
            break;
        }
        if (sub_raw(acc, acc, FE_P)) {
            return 0;
        }
    }
    if (fe_cmp(acc, FE_P) >= 0) {
        return 0;
    }
    fe_copy(r, acc);
    return 1;
}

static void fe_mul(uint32_t r[8], const uint32_t a[8], const uint32_t b[8]) {
    uint16_t aa[16];
    uint16_t bb[16];
    uint64_t col[32];
    uint32_t limb[32];
    uint32_t prod[16];
    uint32_t out[8];
    uint64_t carry = 0;
    int i;
    int j;

    if (fe_failed) {
        return;
    }
    for (i = 0; i < 8; i++) {
        aa[2 * i] = (uint16_t)(a[i] & 0xffffu);
        aa[2 * i + 1] = (uint16_t)(a[i] >> 16);
        bb[2 * i] = (uint16_t)(b[i] & 0xffffu);
        bb[2 * i + 1] = (uint16_t)(b[i] >> 16);
    }
    for (i = 0; i < 32; i++) {
        col[i] = 0;
    }
    for (i = 0; i < 16; i++) {
        for (j = 0; j < 16; j++) {
            col[i + j] += (uint64_t)aa[i] * (uint64_t)bb[j];
        }
    }
    for (i = 0; i < 32; i++) {
        carry += col[i];
        limb[i] = (uint32_t)(carry & 0xffffu);
        carry >>= 16;
    }
    if (carry != 0) {
        fe_failed = 1;
        return;
    }
    for (i = 0; i < 16; i++) {
        prod[i] = limb[2 * i] | (limb[2 * i + 1] << 16);
    }
    if (!fe_reduce(out, prod)) {
        fe_failed = 1;
        return;
    }
    fe_copy(r, out);
}

static void fe_inv(uint32_t r[8], const uint32_t a[8]) {
    uint32_t exp[8];
    uint32_t base[8];
    uint32_t result[8];
    int bit;

    /* p is odd and greater than 2, so p - 2 does not borrow. */
    sub_raw(exp, FE_P, (const uint32_t[8]){2u, 0, 0, 0, 0, 0, 0, 0});
    fe_copy(base, a);
    fe_set_one(result);
    for (bit = 0; bit < 256; bit++) {
        if ((exp[bit >> 5] >> (bit & 31)) & 1u) {
            fe_mul(result, result, base);
        }
        if (bit != 255) {
            fe_mul(base, base, base);
        }
    }
    fe_copy(r, result);
}

static void fe_from_bytes(uint32_t r[8], const uint8_t in[32]) {
    int i;
    for (i = 0; i < 8; i++) {
        int offset = (7 - i) * 4;
        r[i] = ((uint32_t)in[offset] << 24) | ((uint32_t)in[offset + 1] << 16) |
               ((uint32_t)in[offset + 2] << 8) | (uint32_t)in[offset + 3];
    }
}

static void fe_to_bytes(uint8_t out[32], const uint32_t a[8]) {
    int i;
    for (i = 0; i < 8; i++) {
        int offset = (7 - i) * 4;
        out[offset] = (uint8_t)(a[i] >> 24);
        out[offset + 1] = (uint8_t)(a[i] >> 16);
        out[offset + 2] = (uint8_t)(a[i] >> 8);
        out[offset + 3] = (uint8_t)a[i];
    }
}

static int fe_bytes_ok(const uint8_t in[32], uint32_t out[8]) {
    fe_from_bytes(out, in);
    return fe_cmp(out, FE_P) < 0;
}

static void jac_double(jac_point *r, const jac_point *p) {
    uint32_t delta[8], gamma[8], beta[8], alpha[8];
    uint32_t t1[8], t2[8], x3[8], y3[8], z3[8];

    if (fe_is_zero(p->z)) {
        *r = *p;
        return;
    }
    fe_mul(delta, p->z, p->z);
    fe_mul(gamma, p->y, p->y);
    fe_mul(beta, p->x, gamma);
    fe_add(t1, p->x, delta);
    fe_sub(t2, p->x, delta);
    fe_mul(alpha, t1, t2);
    fe_add(t1, alpha, alpha);
    fe_add(alpha, t1, alpha);
    fe_mul(x3, alpha, alpha);
    fe_add(t1, beta, beta);
    fe_add(t1, t1, t1);
    fe_add(t1, t1, t1);
    fe_sub(x3, x3, t1);
    fe_add(t1, p->y, p->z);
    fe_mul(t1, t1, t1);
    fe_sub(t1, t1, gamma);
    fe_sub(z3, t1, delta);
    fe_add(t1, beta, beta);
    fe_add(t1, t1, t1);
    fe_sub(t1, t1, x3);
    fe_mul(t1, alpha, t1);
    fe_mul(t2, gamma, gamma);
    fe_add(t2, t2, t2);
    fe_add(t2, t2, t2);
    fe_add(t2, t2, t2);
    fe_sub(y3, t1, t2);
    fe_copy(r->x, x3);
    fe_copy(r->y, y3);
    fe_copy(r->z, z3);
}

static void jac_add_affine(jac_point *r, const jac_point *p, const uint32_t x2[8], const uint32_t y2[8]) {
    uint32_t z1z1[8], z1z1z1[8], u2[8], s2[8], h[8], hh[8];
    uint32_t i4[8], j[8], rr[8], v[8], x3[8], y3[8], z3[8], t1[8];

    if (fe_is_zero(p->z)) {
        fe_copy(r->x, x2);
        fe_copy(r->y, y2);
        fe_set_one(r->z);
        return;
    }
    fe_mul(z1z1, p->z, p->z);
    fe_mul(z1z1z1, z1z1, p->z);
    fe_mul(u2, x2, z1z1);
    fe_mul(s2, y2, z1z1z1);
    fe_sub(h, u2, p->x);
    fe_sub(t1, s2, p->y);
    if (fe_is_zero(h)) {
        if (fe_is_zero(t1)) {
            jac_double(r, p);
        } else {
            memset(r, 0, sizeof(*r));
        }
        return;
    }
    fe_mul(hh, h, h);
    fe_add(i4, hh, hh);
    fe_add(i4, i4, i4);
    fe_mul(j, h, i4);
    fe_add(rr, t1, t1);
    fe_mul(v, p->x, i4);
    fe_mul(x3, rr, rr);
    fe_sub(x3, x3, j);
    fe_add(t1, v, v);
    fe_sub(x3, x3, t1);
    fe_sub(t1, v, x3);
    fe_mul(y3, rr, t1);
    fe_mul(t1, p->y, j);
    fe_add(t1, t1, t1);
    fe_sub(y3, y3, t1);
    fe_add(t1, p->z, h);
    fe_mul(t1, t1, t1);
    fe_sub(t1, t1, z1z1);
    fe_sub(z3, t1, hh);
    fe_copy(r->x, x3);
    fe_copy(r->y, y3);
    fe_copy(r->z, z3);
}

static int jac_affine(uint8_t rx[32], uint8_t ry[32], const jac_point *p) {
    uint32_t zinv[8], zinv2[8], zinv3[8], x[8], y[8];

    if (fe_is_zero(p->z) || fe_failed) {
        return 0;
    }
    fe_inv(zinv, p->z);
    fe_mul(zinv2, zinv, zinv);
    fe_mul(zinv3, zinv2, zinv);
    fe_mul(x, p->x, zinv2);
    fe_mul(y, p->y, zinv3);
    if (fe_failed) {
        return 0;
    }
    fe_to_bytes(rx, x);
    fe_to_bytes(ry, y);
    return 1;
}

static int scalar_mul(uint8_t rx[32], uint8_t ry[32], const uint8_t k[32],
                      const uint32_t px[8], const uint32_t py[8]) {
    jac_point acc;
    int i;
    int started = 0;

    memset(&acc, 0, sizeof(acc));
    for (i = 0; i < 256; i++) {
        int bit = (k[i >> 3] >> (7 - (i & 7))) & 1;
        if (!started) {
            if (!bit) {
                continue;
            }
            fe_copy(acc.x, px);
            fe_copy(acc.y, py);
            fe_set_one(acc.z);
            started = 1;
            continue;
        }
        jac_double(&acc, &acc);
        if (bit) {
            jac_add_affine(&acc, &acc, px, py);
        }
    }
    if (!started) {
        return 0;
    }
    return jac_affine(rx, ry, &acc);
}

int p256_valid(const uint8_t x[32], const uint8_t y[32]) {
    uint32_t fx[8], fy[8], y2[8], x2[8], x3[8], t[8], b[8];
    int ok;

    if (!x || !y || !fe_bytes_ok(x, fx) || !fe_bytes_ok(y, fy)) {
        return 0;
    }
    fe_failed = 0;
    fe_mul(y2, fy, fy);
    fe_mul(x2, fx, fx);
    fe_mul(x3, x2, fx);
    fe_add(t, fx, fx);
    fe_add(t, t, fx);
    fe_sub(t, x3, t);
    fe_from_bytes(b, B_BYTES);
    fe_add(t, t, b);
    ok = !fe_failed && fe_cmp(y2, t) == 0;
    fe_failed = 0;
    return ok;
}

int p256_selfcheck(void) {
    uint32_t pm1[8], one[8], sum[8], diff[8], square[8];

    fe_failed = 0;
    fe_copy(pm1, FE_P);
    pm1[0] -= 1u;
    fe_set_one(one);
    fe_add(sum, pm1, one);
    if (!fe_is_zero(sum)) {
        return 0;
    }
    fe_sub(diff, sum, one);
    if (fe_cmp(diff, pm1) != 0) {
        return 0;
    }
    fe_mul(square, pm1, pm1);
    if (fe_failed || fe_cmp(square, one) != 0 || !p256_valid(GX_BYTES, GY_BYTES)) {
        return 0;
    }
    return 1;
}

int p256_mul(uint8_t rx[32], uint8_t ry[32], const uint8_t k[32],
             const uint8_t px[32], const uint8_t py[32]) {
    uint32_t x[8], y[8];

    if (!rx || !ry || !k || !p256_valid(px, py)) {
        return 0;
    }
    fe_failed = 0;
    fe_from_bytes(x, px);
    fe_from_bytes(y, py);
    if (!scalar_mul(rx, ry, k, x, y) || fe_failed || !p256_valid(rx, ry)) {
        return 0;
    }
    return 1;
}

int p256_mul_g(uint8_t rx[32], uint8_t ry[32], const uint8_t k[32]) {
    return p256_mul(rx, ry, k, GX_BYTES, GY_BYTES);
}
