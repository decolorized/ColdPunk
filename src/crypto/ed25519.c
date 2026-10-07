// Ed25519 field, group and scalar arithmetic (ref10 model) plus the extras
// Monero needs. Platform independent: identical object code semantics on the
// host test runner and on the ESP32-S3.
//
// The field layout is ref10's: h = sum h[i] * 2^ceil(25.5*i), limbs signed,
// even limbs 26 bits, odd limbs 25 bits.
//
// Scalar arithmetic mod l uses Barrett reduction over 32-bit limbs. Every
// scalar routine is constant time with respect to its inputs; only the
// explicitly named *_vartime point routines branch on their data, and those
// are used on public values only.
#include "ed25519.h"
#include "hash.h"
#include "memzero.h"
#include "random.h"

#include <string.h>

// ---------------------------------------------------------------------------
// Tables and curve constants (ed25519_tables.c)
// ---------------------------------------------------------------------------
extern const mw_ge_precomp mw_ge_base[32][8];
extern const mw_ge_precomp mw_ge_Bi[8];
extern const mw_fe mw_fe_d;
extern const mw_fe mw_fe_d2;
extern const mw_fe mw_fe_sqrtm1;

// ===========================================================================
// Field arithmetic
// ===========================================================================

void mw_fe_0(mw_fe h) {
    for (int i = 0; i < 10; ++i) { h[i] = 0; }
}

void mw_fe_1(mw_fe h) {
    h[0] = 1;
    for (int i = 1; i < 10; ++i) { h[i] = 0; }
}

void mw_fe_copy(mw_fe h, const mw_fe f) {
    for (int i = 0; i < 10; ++i) { h[i] = f[i]; }
}

void mw_fe_add(mw_fe h, const mw_fe f, const mw_fe g) {
    for (int i = 0; i < 10; ++i) { h[i] = f[i] + g[i]; }
}

void mw_fe_sub(mw_fe h, const mw_fe f, const mw_fe g) {
    for (int i = 0; i < 10; ++i) { h[i] = f[i] - g[i]; }
}

void mw_fe_neg(mw_fe h, const mw_fe f) {
    for (int i = 0; i < 10; ++i) { h[i] = -f[i]; }
}

// Constant-time conditional move: h = b ? g : h. b must be 0 or 1.
void mw_fe_cmov(mw_fe h, const mw_fe g, unsigned int b) {
    uint32_t mask = (uint32_t)0u - (b & 1u);
    for (int i = 0; i < 10; ++i) {
        uint32_t x = ((uint32_t)h[i] ^ (uint32_t)g[i]) & mask;
        h[i] = (int32_t)((uint32_t)h[i] ^ x);
    }
}

void mw_fe_mul(mw_fe h, const mw_fe f, const mw_fe g) {
    int32_t f0 = f[0];
    int32_t f1 = f[1];
    int32_t f2 = f[2];
    int32_t f3 = f[3];
    int32_t f4 = f[4];
    int32_t f5 = f[5];
    int32_t f6 = f[6];
    int32_t f7 = f[7];
    int32_t f8 = f[8];
    int32_t f9 = f[9];
    int32_t g0 = g[0];
    int32_t g1 = g[1];
    int32_t g2 = g[2];
    int32_t g3 = g[3];
    int32_t g4 = g[4];
    int32_t g5 = g[5];
    int32_t g6 = g[6];
    int32_t g7 = g[7];
    int32_t g8 = g[8];
    int32_t g9 = g[9];
    int32_t f1_2 = 2 * f1;
    int32_t f3_2 = 2 * f3;
    int32_t f5_2 = 2 * f5;
    int32_t f7_2 = 2 * f7;
    int32_t f9_2 = 2 * f9;
    int32_t g1_19 = 19 * g1;
    int32_t g2_19 = 19 * g2;
    int32_t g3_19 = 19 * g3;
    int32_t g4_19 = 19 * g4;
    int32_t g5_19 = 19 * g5;
    int32_t g6_19 = 19 * g6;
    int32_t g7_19 = 19 * g7;
    int32_t g8_19 = 19 * g8;
    int32_t g9_19 = 19 * g9;
    int64_t carry;
    int64_t h0 = (int64_t)f0 * (int64_t)g0 +
                 (int64_t)f1_2 * (int64_t)g9_19 +
                 (int64_t)f2 * (int64_t)g8_19 +
                 (int64_t)f3_2 * (int64_t)g7_19 +
                 (int64_t)f4 * (int64_t)g6_19 +
                 (int64_t)f5_2 * (int64_t)g5_19 +
                 (int64_t)f6 * (int64_t)g4_19 +
                 (int64_t)f7_2 * (int64_t)g3_19 +
                 (int64_t)f8 * (int64_t)g2_19 +
                 (int64_t)f9_2 * (int64_t)g1_19;
    int64_t h1 = (int64_t)f0 * (int64_t)g1 +
                 (int64_t)f1 * (int64_t)g0 +
                 (int64_t)f2 * (int64_t)g9_19 +
                 (int64_t)f3 * (int64_t)g8_19 +
                 (int64_t)f4 * (int64_t)g7_19 +
                 (int64_t)f5 * (int64_t)g6_19 +
                 (int64_t)f6 * (int64_t)g5_19 +
                 (int64_t)f7 * (int64_t)g4_19 +
                 (int64_t)f8 * (int64_t)g3_19 +
                 (int64_t)f9 * (int64_t)g2_19;
    int64_t h2 = (int64_t)f0 * (int64_t)g2 +
                 (int64_t)f1_2 * (int64_t)g1 +
                 (int64_t)f2 * (int64_t)g0 +
                 (int64_t)f3_2 * (int64_t)g9_19 +
                 (int64_t)f4 * (int64_t)g8_19 +
                 (int64_t)f5_2 * (int64_t)g7_19 +
                 (int64_t)f6 * (int64_t)g6_19 +
                 (int64_t)f7_2 * (int64_t)g5_19 +
                 (int64_t)f8 * (int64_t)g4_19 +
                 (int64_t)f9_2 * (int64_t)g3_19;
    int64_t h3 = (int64_t)f0 * (int64_t)g3 +
                 (int64_t)f1 * (int64_t)g2 +
                 (int64_t)f2 * (int64_t)g1 +
                 (int64_t)f3 * (int64_t)g0 +
                 (int64_t)f4 * (int64_t)g9_19 +
                 (int64_t)f5 * (int64_t)g8_19 +
                 (int64_t)f6 * (int64_t)g7_19 +
                 (int64_t)f7 * (int64_t)g6_19 +
                 (int64_t)f8 * (int64_t)g5_19 +
                 (int64_t)f9 * (int64_t)g4_19;
    int64_t h4 = (int64_t)f0 * (int64_t)g4 +
                 (int64_t)f1_2 * (int64_t)g3 +
                 (int64_t)f2 * (int64_t)g2 +
                 (int64_t)f3_2 * (int64_t)g1 +
                 (int64_t)f4 * (int64_t)g0 +
                 (int64_t)f5_2 * (int64_t)g9_19 +
                 (int64_t)f6 * (int64_t)g8_19 +
                 (int64_t)f7_2 * (int64_t)g7_19 +
                 (int64_t)f8 * (int64_t)g6_19 +
                 (int64_t)f9_2 * (int64_t)g5_19;
    int64_t h5 = (int64_t)f0 * (int64_t)g5 +
                 (int64_t)f1 * (int64_t)g4 +
                 (int64_t)f2 * (int64_t)g3 +
                 (int64_t)f3 * (int64_t)g2 +
                 (int64_t)f4 * (int64_t)g1 +
                 (int64_t)f5 * (int64_t)g0 +
                 (int64_t)f6 * (int64_t)g9_19 +
                 (int64_t)f7 * (int64_t)g8_19 +
                 (int64_t)f8 * (int64_t)g7_19 +
                 (int64_t)f9 * (int64_t)g6_19;
    int64_t h6 = (int64_t)f0 * (int64_t)g6 +
                 (int64_t)f1_2 * (int64_t)g5 +
                 (int64_t)f2 * (int64_t)g4 +
                 (int64_t)f3_2 * (int64_t)g3 +
                 (int64_t)f4 * (int64_t)g2 +
                 (int64_t)f5_2 * (int64_t)g1 +
                 (int64_t)f6 * (int64_t)g0 +
                 (int64_t)f7_2 * (int64_t)g9_19 +
                 (int64_t)f8 * (int64_t)g8_19 +
                 (int64_t)f9_2 * (int64_t)g7_19;
    int64_t h7 = (int64_t)f0 * (int64_t)g7 +
                 (int64_t)f1 * (int64_t)g6 +
                 (int64_t)f2 * (int64_t)g5 +
                 (int64_t)f3 * (int64_t)g4 +
                 (int64_t)f4 * (int64_t)g3 +
                 (int64_t)f5 * (int64_t)g2 +
                 (int64_t)f6 * (int64_t)g1 +
                 (int64_t)f7 * (int64_t)g0 +
                 (int64_t)f8 * (int64_t)g9_19 +
                 (int64_t)f9 * (int64_t)g8_19;
    int64_t h8 = (int64_t)f0 * (int64_t)g8 +
                 (int64_t)f1_2 * (int64_t)g7 +
                 (int64_t)f2 * (int64_t)g6 +
                 (int64_t)f3_2 * (int64_t)g5 +
                 (int64_t)f4 * (int64_t)g4 +
                 (int64_t)f5_2 * (int64_t)g3 +
                 (int64_t)f6 * (int64_t)g2 +
                 (int64_t)f7_2 * (int64_t)g1 +
                 (int64_t)f8 * (int64_t)g0 +
                 (int64_t)f9_2 * (int64_t)g9_19;
    int64_t h9 = (int64_t)f0 * (int64_t)g9 +
                 (int64_t)f1 * (int64_t)g8 +
                 (int64_t)f2 * (int64_t)g7 +
                 (int64_t)f3 * (int64_t)g6 +
                 (int64_t)f4 * (int64_t)g5 +
                 (int64_t)f5 * (int64_t)g4 +
                 (int64_t)f6 * (int64_t)g3 +
                 (int64_t)f7 * (int64_t)g2 +
                 (int64_t)f8 * (int64_t)g1 +
                 (int64_t)f9 * (int64_t)g0;

    carry = (h0 + (int64_t)(1 << 25)) >> 26; h1 += carry; h0 -= carry * ((int64_t)1 << 26);
    carry = (h4 + (int64_t)(1 << 25)) >> 26; h5 += carry; h4 -= carry * ((int64_t)1 << 26);

    carry = (h1 + (int64_t)(1 << 24)) >> 25; h2 += carry; h1 -= carry * ((int64_t)1 << 25);
    carry = (h5 + (int64_t)(1 << 24)) >> 25; h6 += carry; h5 -= carry * ((int64_t)1 << 25);

    carry = (h2 + (int64_t)(1 << 25)) >> 26; h3 += carry; h2 -= carry * ((int64_t)1 << 26);
    carry = (h6 + (int64_t)(1 << 25)) >> 26; h7 += carry; h6 -= carry * ((int64_t)1 << 26);

    carry = (h3 + (int64_t)(1 << 24)) >> 25; h4 += carry; h3 -= carry * ((int64_t)1 << 25);
    carry = (h7 + (int64_t)(1 << 24)) >> 25; h8 += carry; h7 -= carry * ((int64_t)1 << 25);

    carry = (h4 + (int64_t)(1 << 25)) >> 26; h5 += carry; h4 -= carry * ((int64_t)1 << 26);
    carry = (h8 + (int64_t)(1 << 25)) >> 26; h9 += carry; h8 -= carry * ((int64_t)1 << 26);

    carry = (h9 + (int64_t)(1 << 24)) >> 25; h0 += carry * 19; h9 -= carry * ((int64_t)1 << 25);

    carry = (h0 + (int64_t)(1 << 25)) >> 26; h1 += carry; h0 -= carry * ((int64_t)1 << 26);

    h[0] = (int32_t)h0;
    h[1] = (int32_t)h1;
    h[2] = (int32_t)h2;
    h[3] = (int32_t)h3;
    h[4] = (int32_t)h4;
    h[5] = (int32_t)h5;
    h[6] = (int32_t)h6;
    h[7] = (int32_t)h7;
    h[8] = (int32_t)h8;
    h[9] = (int32_t)h9;
}

void mw_fe_sq(mw_fe h, const mw_fe f) {
    int32_t f0 = f[0];
    int32_t f1 = f[1];
    int32_t f2 = f[2];
    int32_t f3 = f[3];
    int32_t f4 = f[4];
    int32_t f5 = f[5];
    int32_t f6 = f[6];
    int32_t f7 = f[7];
    int32_t f8 = f[8];
    int32_t f9 = f[9];
    int32_t f0_2 = 2 * f0;
    int32_t f1_2 = 2 * f1;
    int32_t f2_2 = 2 * f2;
    int32_t f3_2 = 2 * f3;
    int32_t f4_2 = 2 * f4;
    int32_t f5_2 = 2 * f5;
    int32_t f5_38 = 38 * f5;
    int32_t f6_2 = 2 * f6;
    int32_t f6_19 = 19 * f6;
    int32_t f7_2 = 2 * f7;
    int32_t f7_19 = 19 * f7;
    int32_t f7_38 = 38 * f7;
    int32_t f8_2 = 2 * f8;
    int32_t f8_19 = 19 * f8;
    int32_t f9_19 = 19 * f9;
    int32_t f9_38 = 38 * f9;
    int64_t carry;
    int64_t h0 = (int64_t)f0 * (int64_t)f0 +
                 (int64_t)f1_2 * (int64_t)f9_38 +
                 (int64_t)f2_2 * (int64_t)f8_19 +
                 (int64_t)f3_2 * (int64_t)f7_38 +
                 (int64_t)f4_2 * (int64_t)f6_19 +
                 (int64_t)f5_38 * (int64_t)f5;
    int64_t h1 = (int64_t)f0_2 * (int64_t)f1 +
                 (int64_t)f2_2 * (int64_t)f9_19 +
                 (int64_t)f3_2 * (int64_t)f8_19 +
                 (int64_t)f4_2 * (int64_t)f7_19 +
                 (int64_t)f5_2 * (int64_t)f6_19;
    int64_t h2 = (int64_t)f0_2 * (int64_t)f2 +
                 (int64_t)f1_2 * (int64_t)f1 +
                 (int64_t)f3_2 * (int64_t)f9_38 +
                 (int64_t)f4_2 * (int64_t)f8_19 +
                 (int64_t)f5_2 * (int64_t)f7_38 +
                 (int64_t)f6_19 * (int64_t)f6;
    int64_t h3 = (int64_t)f0_2 * (int64_t)f3 +
                 (int64_t)f1_2 * (int64_t)f2 +
                 (int64_t)f4_2 * (int64_t)f9_19 +
                 (int64_t)f5_2 * (int64_t)f8_19 +
                 (int64_t)f6_2 * (int64_t)f7_19;
    int64_t h4 = (int64_t)f0_2 * (int64_t)f4 +
                 (int64_t)f1_2 * (int64_t)f3_2 +
                 (int64_t)f2 * (int64_t)f2 +
                 (int64_t)f5_2 * (int64_t)f9_38 +
                 (int64_t)f6_2 * (int64_t)f8_19 +
                 (int64_t)f7_38 * (int64_t)f7;
    int64_t h5 = (int64_t)f0_2 * (int64_t)f5 +
                 (int64_t)f1_2 * (int64_t)f4 +
                 (int64_t)f2_2 * (int64_t)f3 +
                 (int64_t)f6_2 * (int64_t)f9_19 +
                 (int64_t)f7_2 * (int64_t)f8_19;
    int64_t h6 = (int64_t)f0_2 * (int64_t)f6 +
                 (int64_t)f1_2 * (int64_t)f5_2 +
                 (int64_t)f2_2 * (int64_t)f4 +
                 (int64_t)f3_2 * (int64_t)f3 +
                 (int64_t)f7_2 * (int64_t)f9_38 +
                 (int64_t)f8_19 * (int64_t)f8;
    int64_t h7 = (int64_t)f0_2 * (int64_t)f7 +
                 (int64_t)f1_2 * (int64_t)f6 +
                 (int64_t)f2_2 * (int64_t)f5 +
                 (int64_t)f3_2 * (int64_t)f4 +
                 (int64_t)f8_2 * (int64_t)f9_19;
    int64_t h8 = (int64_t)f0_2 * (int64_t)f8 +
                 (int64_t)f1_2 * (int64_t)f7_2 +
                 (int64_t)f2_2 * (int64_t)f6 +
                 (int64_t)f3_2 * (int64_t)f5_2 +
                 (int64_t)f4 * (int64_t)f4 +
                 (int64_t)f9_38 * (int64_t)f9;
    int64_t h9 = (int64_t)f0_2 * (int64_t)f9 +
                 (int64_t)f1_2 * (int64_t)f8 +
                 (int64_t)f2_2 * (int64_t)f7 +
                 (int64_t)f3_2 * (int64_t)f6 +
                 (int64_t)f4_2 * (int64_t)f5;

    carry = (h0 + (int64_t)(1 << 25)) >> 26; h1 += carry; h0 -= carry * ((int64_t)1 << 26);
    carry = (h4 + (int64_t)(1 << 25)) >> 26; h5 += carry; h4 -= carry * ((int64_t)1 << 26);

    carry = (h1 + (int64_t)(1 << 24)) >> 25; h2 += carry; h1 -= carry * ((int64_t)1 << 25);
    carry = (h5 + (int64_t)(1 << 24)) >> 25; h6 += carry; h5 -= carry * ((int64_t)1 << 25);

    carry = (h2 + (int64_t)(1 << 25)) >> 26; h3 += carry; h2 -= carry * ((int64_t)1 << 26);
    carry = (h6 + (int64_t)(1 << 25)) >> 26; h7 += carry; h6 -= carry * ((int64_t)1 << 26);

    carry = (h3 + (int64_t)(1 << 24)) >> 25; h4 += carry; h3 -= carry * ((int64_t)1 << 25);
    carry = (h7 + (int64_t)(1 << 24)) >> 25; h8 += carry; h7 -= carry * ((int64_t)1 << 25);

    carry = (h4 + (int64_t)(1 << 25)) >> 26; h5 += carry; h4 -= carry * ((int64_t)1 << 26);
    carry = (h8 + (int64_t)(1 << 25)) >> 26; h9 += carry; h8 -= carry * ((int64_t)1 << 26);

    carry = (h9 + (int64_t)(1 << 24)) >> 25; h0 += carry * 19; h9 -= carry * ((int64_t)1 << 25);

    carry = (h0 + (int64_t)(1 << 25)) >> 26; h1 += carry; h0 -= carry * ((int64_t)1 << 26);

    h[0] = (int32_t)h0;
    h[1] = (int32_t)h1;
    h[2] = (int32_t)h2;
    h[3] = (int32_t)h3;
    h[4] = (int32_t)h4;
    h[5] = (int32_t)h5;
    h[6] = (int32_t)h6;
    h[7] = (int32_t)h7;
    h[8] = (int32_t)h8;
    h[9] = (int32_t)h9;
}

// h = 2 * f^2
void mw_fe_sq2(mw_fe h, const mw_fe f) {
    int32_t f0 = f[0];
    int32_t f1 = f[1];
    int32_t f2 = f[2];
    int32_t f3 = f[3];
    int32_t f4 = f[4];
    int32_t f5 = f[5];
    int32_t f6 = f[6];
    int32_t f7 = f[7];
    int32_t f8 = f[8];
    int32_t f9 = f[9];
    int32_t f0_2 = 2 * f0;
    int32_t f1_2 = 2 * f1;
    int32_t f2_2 = 2 * f2;
    int32_t f3_2 = 2 * f3;
    int32_t f4_2 = 2 * f4;
    int32_t f5_2 = 2 * f5;
    int32_t f5_38 = 38 * f5;
    int32_t f6_2 = 2 * f6;
    int32_t f6_19 = 19 * f6;
    int32_t f7_2 = 2 * f7;
    int32_t f7_19 = 19 * f7;
    int32_t f7_38 = 38 * f7;
    int32_t f8_2 = 2 * f8;
    int32_t f8_19 = 19 * f8;
    int32_t f9_19 = 19 * f9;
    int32_t f9_38 = 38 * f9;
    int64_t carry;
    int64_t h0 = (int64_t)f0 * (int64_t)f0 +
                 (int64_t)f1_2 * (int64_t)f9_38 +
                 (int64_t)f2_2 * (int64_t)f8_19 +
                 (int64_t)f3_2 * (int64_t)f7_38 +
                 (int64_t)f4_2 * (int64_t)f6_19 +
                 (int64_t)f5_38 * (int64_t)f5;
    int64_t h1 = (int64_t)f0_2 * (int64_t)f1 +
                 (int64_t)f2_2 * (int64_t)f9_19 +
                 (int64_t)f3_2 * (int64_t)f8_19 +
                 (int64_t)f4_2 * (int64_t)f7_19 +
                 (int64_t)f5_2 * (int64_t)f6_19;
    int64_t h2 = (int64_t)f0_2 * (int64_t)f2 +
                 (int64_t)f1_2 * (int64_t)f1 +
                 (int64_t)f3_2 * (int64_t)f9_38 +
                 (int64_t)f4_2 * (int64_t)f8_19 +
                 (int64_t)f5_2 * (int64_t)f7_38 +
                 (int64_t)f6_19 * (int64_t)f6;
    int64_t h3 = (int64_t)f0_2 * (int64_t)f3 +
                 (int64_t)f1_2 * (int64_t)f2 +
                 (int64_t)f4_2 * (int64_t)f9_19 +
                 (int64_t)f5_2 * (int64_t)f8_19 +
                 (int64_t)f6_2 * (int64_t)f7_19;
    int64_t h4 = (int64_t)f0_2 * (int64_t)f4 +
                 (int64_t)f1_2 * (int64_t)f3_2 +
                 (int64_t)f2 * (int64_t)f2 +
                 (int64_t)f5_2 * (int64_t)f9_38 +
                 (int64_t)f6_2 * (int64_t)f8_19 +
                 (int64_t)f7_38 * (int64_t)f7;
    int64_t h5 = (int64_t)f0_2 * (int64_t)f5 +
                 (int64_t)f1_2 * (int64_t)f4 +
                 (int64_t)f2_2 * (int64_t)f3 +
                 (int64_t)f6_2 * (int64_t)f9_19 +
                 (int64_t)f7_2 * (int64_t)f8_19;
    int64_t h6 = (int64_t)f0_2 * (int64_t)f6 +
                 (int64_t)f1_2 * (int64_t)f5_2 +
                 (int64_t)f2_2 * (int64_t)f4 +
                 (int64_t)f3_2 * (int64_t)f3 +
                 (int64_t)f7_2 * (int64_t)f9_38 +
                 (int64_t)f8_19 * (int64_t)f8;
    int64_t h7 = (int64_t)f0_2 * (int64_t)f7 +
                 (int64_t)f1_2 * (int64_t)f6 +
                 (int64_t)f2_2 * (int64_t)f5 +
                 (int64_t)f3_2 * (int64_t)f4 +
                 (int64_t)f8_2 * (int64_t)f9_19;
    int64_t h8 = (int64_t)f0_2 * (int64_t)f8 +
                 (int64_t)f1_2 * (int64_t)f7_2 +
                 (int64_t)f2_2 * (int64_t)f6 +
                 (int64_t)f3_2 * (int64_t)f5_2 +
                 (int64_t)f4 * (int64_t)f4 +
                 (int64_t)f9_38 * (int64_t)f9;
    int64_t h9 = (int64_t)f0_2 * (int64_t)f9 +
                 (int64_t)f1_2 * (int64_t)f8 +
                 (int64_t)f2_2 * (int64_t)f7 +
                 (int64_t)f3_2 * (int64_t)f6 +
                 (int64_t)f4_2 * (int64_t)f5;

    h0 += h0;
    h1 += h1;
    h2 += h2;
    h3 += h3;
    h4 += h4;
    h5 += h5;
    h6 += h6;
    h7 += h7;
    h8 += h8;
    h9 += h9;

    carry = (h0 + (int64_t)(1 << 25)) >> 26; h1 += carry; h0 -= carry * ((int64_t)1 << 26);
    carry = (h4 + (int64_t)(1 << 25)) >> 26; h5 += carry; h4 -= carry * ((int64_t)1 << 26);

    carry = (h1 + (int64_t)(1 << 24)) >> 25; h2 += carry; h1 -= carry * ((int64_t)1 << 25);
    carry = (h5 + (int64_t)(1 << 24)) >> 25; h6 += carry; h5 -= carry * ((int64_t)1 << 25);

    carry = (h2 + (int64_t)(1 << 25)) >> 26; h3 += carry; h2 -= carry * ((int64_t)1 << 26);
    carry = (h6 + (int64_t)(1 << 25)) >> 26; h7 += carry; h6 -= carry * ((int64_t)1 << 26);

    carry = (h3 + (int64_t)(1 << 24)) >> 25; h4 += carry; h3 -= carry * ((int64_t)1 << 25);
    carry = (h7 + (int64_t)(1 << 24)) >> 25; h8 += carry; h7 -= carry * ((int64_t)1 << 25);

    carry = (h4 + (int64_t)(1 << 25)) >> 26; h5 += carry; h4 -= carry * ((int64_t)1 << 26);
    carry = (h8 + (int64_t)(1 << 25)) >> 26; h9 += carry; h8 -= carry * ((int64_t)1 << 26);

    carry = (h9 + (int64_t)(1 << 24)) >> 25; h0 += carry * 19; h9 -= carry * ((int64_t)1 << 25);

    carry = (h0 + (int64_t)(1 << 25)) >> 26; h1 += carry; h0 -= carry * ((int64_t)1 << 26);

    h[0] = (int32_t)h0;
    h[1] = (int32_t)h1;
    h[2] = (int32_t)h2;
    h[3] = (int32_t)h3;
    h[4] = (int32_t)h4;
    h[5] = (int32_t)h5;
    h[6] = (int32_t)h6;
    h[7] = (int32_t)h7;
    h[8] = (int32_t)h8;
    h[9] = (int32_t)h9;
}

void mw_fe_mul121666(mw_fe h, const mw_fe f) {
    int64_t t[10];
    int64_t carry;
    for (int i = 0; i < 10; ++i) {
        t[i] = (int64_t)f[i] * 121666;
    }
    int64_t h0 = t[0], h1 = t[1], h2 = t[2], h3 = t[3], h4 = t[4];
    int64_t h5 = t[5], h6 = t[6], h7 = t[7], h8 = t[8], h9 = t[9];

    carry = (h9 + (int64_t)(1 << 24)) >> 25; h0 += carry * 19; h9 -= carry * ((int64_t)1 << 25);
    carry = (h1 + (int64_t)(1 << 24)) >> 25; h2 += carry; h1 -= carry * ((int64_t)1 << 25);
    carry = (h3 + (int64_t)(1 << 24)) >> 25; h4 += carry; h3 -= carry * ((int64_t)1 << 25);
    carry = (h5 + (int64_t)(1 << 24)) >> 25; h6 += carry; h5 -= carry * ((int64_t)1 << 25);
    carry = (h7 + (int64_t)(1 << 24)) >> 25; h8 += carry; h7 -= carry * ((int64_t)1 << 25);

    carry = (h0 + (int64_t)(1 << 25)) >> 26; h1 += carry; h0 -= carry * ((int64_t)1 << 26);
    carry = (h2 + (int64_t)(1 << 25)) >> 26; h3 += carry; h2 -= carry * ((int64_t)1 << 26);
    carry = (h4 + (int64_t)(1 << 25)) >> 26; h5 += carry; h4 -= carry * ((int64_t)1 << 26);
    carry = (h6 + (int64_t)(1 << 25)) >> 26; h7 += carry; h6 -= carry * ((int64_t)1 << 26);
    carry = (h8 + (int64_t)(1 << 25)) >> 26; h9 += carry; h8 -= carry * ((int64_t)1 << 26);

    h[0] = (int32_t)h0; h[1] = (int32_t)h1; h[2] = (int32_t)h2; h[3] = (int32_t)h3;
    h[4] = (int32_t)h4; h[5] = (int32_t)h5; h[6] = (int32_t)h6; h[7] = (int32_t)h7;
    h[8] = (int32_t)h8; h[9] = (int32_t)h9;
}

// Left shift performed in the unsigned domain: shifting a negative signed
// value is undefined behaviour in C, and the project's CI builds with UBSan.
static inline int32_t shl32(int32_t v, int n) {
    return (int32_t)((uint32_t)v << n);
}

static inline int mw_shl_i(int v, int n) {
    return (int)((unsigned int)v << n);
}

// Bit offset of each limb inside the 255-bit representation.
static const uint8_t fe_off[10] = { 0, 26, 51, 77, 102, 128, 153, 179, 204, 230 };
static const uint8_t fe_bits[10] = { 26, 25, 26, 25, 26, 25, 26, 25, 26, 25 };

// Parses 32 little-endian bytes. `wide` == 0 ignores bit 255 (canonical
// point / field decoding); `wide` == 1 folds it back in as 2^255 == 19,
// which is what Monero's ge_fromfe_frombytes_vartime does.
static void fe_frombytes_impl(mw_fe h, const uint8_t s[32], int wide) {
    uint8_t buf[36];
    memcpy(buf, s, 32);
    memset(buf + 32, 0, 4);

    for (int k = 0; k < 10; ++k) {
        int off  = fe_off[k];
        int byte = off >> 3;
        int bit  = off & 7;
        uint64_t v = 0;
        for (int i = 0; i < 5; ++i) {
            v |= (uint64_t)buf[byte + i] << (8 * i);
        }
        v >>= bit;
        v &= ((uint64_t)1 << fe_bits[k]) - 1;
        h[k] = (int32_t)v;
    }
    if (wide) {
        // Bit 255 has weight 2^255 == 19 (mod p).
        h[0] += 19 * (int32_t)(buf[31] >> 7);
    }

    // ref10 balances the limbs before handing them to fe_mul/fe_sq: without
    // this, limbs sit just below 2^26 and a later fe_add would push 19*g past
    // INT32_MAX inside the multiplier.
    {
        int64_t t[10];
        int64_t carry;
        for (int k = 0; k < 10; ++k) { t[k] = h[k]; }

        carry = (t[9] + (int64_t)(1 << 24)) >> 25; t[0] += carry * 19; t[9] -= carry * ((int64_t)1 << 25);
        for (int k = 1; k <= 7; k += 2) {
            carry = (t[k] + (int64_t)(1 << 24)) >> 25; t[k + 1] += carry; t[k] -= carry * ((int64_t)1 << 25);
        }
        for (int k = 0; k <= 8; k += 2) {
            carry = (t[k] + (int64_t)(1 << 25)) >> 26; t[k + 1] += carry; t[k] -= carry * ((int64_t)1 << 26);
        }
        for (int k = 0; k < 10; ++k) { h[k] = (int32_t)t[k]; }
    }

    mw_memzero(buf, sizeof(buf));
}

void mw_fe_frombytes(mw_fe h, const uint8_t s[32]) {
    fe_frombytes_impl(h, s, 0);
}

void mw_fe_frombytes_wide(mw_fe h, const uint8_t s[32]) {
    fe_frombytes_impl(h, s, 1);
}

void mw_fe_tobytes(uint8_t s[32], const mw_fe h) {
    int32_t t[10];
    int32_t q;
    int32_t carry;

    for (int i = 0; i < 10; ++i) { t[i] = h[i]; }

    // Work out whether the value is >= p and subtract p if so, then carry
    // everything into canonical unsigned limbs.
    q = (19 * t[9] + (((int32_t)1) << 24)) >> 25;
    q = (t[0] + q) >> 26;
    q = (t[1] + q) >> 25;
    q = (t[2] + q) >> 26;
    q = (t[3] + q) >> 25;
    q = (t[4] + q) >> 26;
    q = (t[5] + q) >> 25;
    q = (t[6] + q) >> 26;
    q = (t[7] + q) >> 25;
    q = (t[8] + q) >> 26;
    q = (t[9] + q) >> 25;

    t[0] += 19 * q;

    for (int i = 0; i < 9; ++i) {
        carry = t[i] >> fe_bits[i];
        t[i + 1] += carry;
        t[i] -= shl32(carry, fe_bits[i]);
    }
    carry = t[9] >> 25;
    t[9] -= shl32(carry, 25);

    memset(s, 0, 32);
    for (int k = 0; k < 10; ++k) {
        int off  = fe_off[k];
        int byte = off >> 3;
        int bit  = off & 7;
        uint64_t v = (uint64_t)(uint32_t)t[k] << bit;
        for (int i = 0; i < 4 && byte + i < 32; ++i) {
            s[byte + i] |= (uint8_t)(v >> (8 * i));
        }
    }
    mw_memzero(t, sizeof(t));
}

int mw_fe_isnegative(const mw_fe f) {
    uint8_t s[32];
    mw_fe_tobytes(s, f);
    int r = s[0] & 1;
    mw_memzero(s, sizeof(s));
    return r;
}

int mw_fe_isnonzero(const mw_fe f) {
    uint8_t s[32];
    mw_fe_tobytes(s, f);
    int r = !mw_ct_is_zero(s, 32);
    mw_memzero(s, sizeof(s));
    return r;
}

static int fe_eq(const mw_fe a, const mw_fe b) {
    mw_fe d;
    mw_fe_sub(d, a, b);
    int r = !mw_fe_isnonzero(d);
    mw_memzero(d, sizeof(d));
    return r;
}

// out = z^(p-2) = z^-1
void mw_fe_invert(mw_fe out, const mw_fe z) {
    mw_fe t0, t1, t2, t3;
    int i;

    mw_fe_sq(t0, z);
    mw_fe_sq(t1, t0);
    mw_fe_sq(t1, t1);
    mw_fe_mul(t1, z, t1);
    mw_fe_mul(t0, t0, t1);
    mw_fe_sq(t2, t0);
    mw_fe_mul(t1, t1, t2);
    mw_fe_sq(t2, t1);
    for (i = 1; i < 5; ++i) { mw_fe_sq(t2, t2); }
    mw_fe_mul(t1, t2, t1);
    mw_fe_sq(t2, t1);
    for (i = 1; i < 10; ++i) { mw_fe_sq(t2, t2); }
    mw_fe_mul(t2, t2, t1);
    mw_fe_sq(t3, t2);
    for (i = 1; i < 20; ++i) { mw_fe_sq(t3, t3); }
    mw_fe_mul(t2, t3, t2);
    mw_fe_sq(t2, t2);
    for (i = 1; i < 10; ++i) { mw_fe_sq(t2, t2); }
    mw_fe_mul(t1, t2, t1);
    mw_fe_sq(t2, t1);
    for (i = 1; i < 50; ++i) { mw_fe_sq(t2, t2); }
    mw_fe_mul(t2, t2, t1);
    mw_fe_sq(t3, t2);
    for (i = 1; i < 100; ++i) { mw_fe_sq(t3, t3); }
    mw_fe_mul(t2, t3, t2);
    mw_fe_sq(t2, t2);
    for (i = 1; i < 50; ++i) { mw_fe_sq(t2, t2); }
    mw_fe_mul(t1, t2, t1);
    mw_fe_sq(t1, t1);
    for (i = 1; i < 5; ++i) { mw_fe_sq(t1, t1); }
    mw_fe_mul(out, t1, t0);

    mw_memzero(t0, sizeof(t0)); mw_memzero(t1, sizeof(t1));
    mw_memzero(t2, sizeof(t2)); mw_memzero(t3, sizeof(t3));
}

// out = z^((p-5)/8)
void mw_fe_pow22523(mw_fe out, const mw_fe z) {
    mw_fe t0, t1, t2;
    int i;

    mw_fe_sq(t0, z);
    mw_fe_sq(t1, t0);
    mw_fe_sq(t1, t1);
    mw_fe_mul(t1, z, t1);
    mw_fe_mul(t0, t0, t1);
    mw_fe_sq(t0, t0);
    mw_fe_mul(t0, t1, t0);
    mw_fe_sq(t1, t0);
    for (i = 1; i < 5; ++i) { mw_fe_sq(t1, t1); }
    mw_fe_mul(t0, t1, t0);
    mw_fe_sq(t1, t0);
    for (i = 1; i < 10; ++i) { mw_fe_sq(t1, t1); }
    mw_fe_mul(t1, t1, t0);
    mw_fe_sq(t2, t1);
    for (i = 1; i < 20; ++i) { mw_fe_sq(t2, t2); }
    mw_fe_mul(t1, t2, t1);
    mw_fe_sq(t1, t1);
    for (i = 1; i < 10; ++i) { mw_fe_sq(t1, t1); }
    mw_fe_mul(t0, t1, t0);
    mw_fe_sq(t1, t0);
    for (i = 1; i < 50; ++i) { mw_fe_sq(t1, t1); }
    mw_fe_mul(t1, t1, t0);
    mw_fe_sq(t2, t1);
    for (i = 1; i < 100; ++i) { mw_fe_sq(t2, t2); }
    mw_fe_mul(t1, t2, t1);
    mw_fe_sq(t1, t1);
    for (i = 1; i < 50; ++i) { mw_fe_sq(t1, t1); }
    mw_fe_mul(t0, t1, t0);
    mw_fe_sq(t0, t0);
    mw_fe_sq(t0, t0);
    mw_fe_mul(out, t0, z);

    mw_memzero(t0, sizeof(t0)); mw_memzero(t1, sizeof(t1));
    mw_memzero(t2, sizeof(t2));
}

// ===========================================================================
// Group arithmetic
// ===========================================================================

void mw_ge_p3_0(mw_ge_p3* h) {
    mw_fe_0(h->X); mw_fe_1(h->Y); mw_fe_1(h->Z); mw_fe_0(h->T);
}

void mw_ge_p2_0(mw_ge_p2* h) {
    mw_fe_0(h->X); mw_fe_1(h->Y); mw_fe_1(h->Z);
}

void mw_ge_precomp_0(mw_ge_precomp* h) {
    mw_fe_1(h->yplusx); mw_fe_1(h->yminusx); mw_fe_0(h->xy2d);
}

static void ge_cached_0(mw_ge_cached* h) {
    mw_fe_1(h->YplusX); mw_fe_1(h->YminusX); mw_fe_1(h->Z); mw_fe_0(h->T2d);
}

void mw_ge_p3_to_p2(mw_ge_p2* r, const mw_ge_p3* p) {
    mw_fe_copy(r->X, p->X);
    mw_fe_copy(r->Y, p->Y);
    mw_fe_copy(r->Z, p->Z);
}

void mw_ge_p3_to_cached(mw_ge_cached* r, const mw_ge_p3* p) {
    mw_fe_add(r->YplusX, p->Y, p->X);
    mw_fe_sub(r->YminusX, p->Y, p->X);
    mw_fe_copy(r->Z, p->Z);
    mw_fe_mul(r->T2d, p->T, mw_fe_d2);
}

void mw_ge_p1p1_to_p2(mw_ge_p2* r, const mw_ge_p1p1* p) {
    mw_fe_mul(r->X, p->X, p->T);
    mw_fe_mul(r->Y, p->Y, p->Z);
    mw_fe_mul(r->Z, p->Z, p->T);
}

void mw_ge_p1p1_to_p3(mw_ge_p3* r, const mw_ge_p1p1* p) {
    mw_fe_mul(r->X, p->X, p->T);
    mw_fe_mul(r->Y, p->Y, p->Z);
    mw_fe_mul(r->Z, p->Z, p->T);
    mw_fe_mul(r->T, p->X, p->Y);
}

void mw_ge_add(mw_ge_p1p1* r, const mw_ge_p3* p, const mw_ge_cached* q) {
    mw_fe t0;
    mw_fe_add(r->X, p->Y, p->X);
    mw_fe_sub(r->Y, p->Y, p->X);
    mw_fe_mul(r->Z, r->X, q->YplusX);
    mw_fe_mul(r->Y, r->Y, q->YminusX);
    mw_fe_mul(r->T, q->T2d, p->T);
    mw_fe_mul(r->X, p->Z, q->Z);
    mw_fe_add(t0, r->X, r->X);
    mw_fe_sub(r->X, r->Z, r->Y);
    mw_fe_add(r->Y, r->Z, r->Y);
    mw_fe_add(r->Z, t0, r->T);
    mw_fe_sub(r->T, t0, r->T);
}

void mw_ge_sub(mw_ge_p1p1* r, const mw_ge_p3* p, const mw_ge_cached* q) {
    mw_fe t0;
    mw_fe_add(r->X, p->Y, p->X);
    mw_fe_sub(r->Y, p->Y, p->X);
    mw_fe_mul(r->Z, r->X, q->YminusX);
    mw_fe_mul(r->Y, r->Y, q->YplusX);
    mw_fe_mul(r->T, q->T2d, p->T);
    mw_fe_mul(r->X, p->Z, q->Z);
    mw_fe_add(t0, r->X, r->X);
    mw_fe_sub(r->X, r->Z, r->Y);
    mw_fe_add(r->Y, r->Z, r->Y);
    mw_fe_sub(r->Z, t0, r->T);
    mw_fe_add(r->T, t0, r->T);
}

void mw_ge_madd(mw_ge_p1p1* r, const mw_ge_p3* p, const mw_ge_precomp* q) {
    mw_fe t0;
    mw_fe_add(r->X, p->Y, p->X);
    mw_fe_sub(r->Y, p->Y, p->X);
    mw_fe_mul(r->Z, r->X, q->yplusx);
    mw_fe_mul(r->Y, r->Y, q->yminusx);
    mw_fe_mul(r->T, q->xy2d, p->T);
    mw_fe_add(t0, p->Z, p->Z);
    mw_fe_sub(r->X, r->Z, r->Y);
    mw_fe_add(r->Y, r->Z, r->Y);
    mw_fe_add(r->Z, t0, r->T);
    mw_fe_sub(r->T, t0, r->T);
}

void mw_ge_msub(mw_ge_p1p1* r, const mw_ge_p3* p, const mw_ge_precomp* q) {
    mw_fe t0;
    mw_fe_add(r->X, p->Y, p->X);
    mw_fe_sub(r->Y, p->Y, p->X);
    mw_fe_mul(r->Z, r->X, q->yminusx);
    mw_fe_mul(r->Y, r->Y, q->yplusx);
    mw_fe_mul(r->T, q->xy2d, p->T);
    mw_fe_add(t0, p->Z, p->Z);
    mw_fe_sub(r->X, r->Z, r->Y);
    mw_fe_add(r->Y, r->Z, r->Y);
    mw_fe_sub(r->Z, t0, r->T);
    mw_fe_add(r->T, t0, r->T);
}

void mw_ge_p2_dbl(mw_ge_p1p1* r, const mw_ge_p2* p) {
    mw_fe t0;
    mw_fe_sq(r->X, p->X);
    mw_fe_sq(r->Z, p->Y);
    mw_fe_sq2(r->T, p->Z);
    mw_fe_add(r->Y, p->X, p->Y);
    mw_fe_sq(t0, r->Y);
    mw_fe_add(r->Y, r->Z, r->X);
    mw_fe_sub(r->Z, r->Z, r->X);
    mw_fe_sub(r->X, t0, r->Y);
    mw_fe_sub(r->T, r->T, r->Z);
}

void mw_ge_p3_dbl(mw_ge_p1p1* r, const mw_ge_p3* p) {
    mw_ge_p2 q;
    mw_ge_p3_to_p2(&q, p);
    mw_ge_p2_dbl(r, &q);
}

void mw_ge_mul8(mw_ge_p1p1* r, const mw_ge_p2* p) {
    mw_ge_p2 u;
    mw_ge_p2_dbl(r, p);
    mw_ge_p1p1_to_p2(&u, r);
    mw_ge_p2_dbl(r, &u);
    mw_ge_p1p1_to_p2(&u, r);
    mw_ge_p2_dbl(r, &u);
}

void mw_ge_p2_tobytes(mw_point_t* out, const mw_ge_p2* h) {
    mw_fe recip, x, y;
    mw_fe_invert(recip, h->Z);
    mw_fe_mul(x, h->X, recip);
    mw_fe_mul(y, h->Y, recip);
    mw_fe_tobytes(out->b, y);
    out->b[31] ^= (uint8_t)(mw_fe_isnegative(x) << 7);
}

void mw_ge_p3_tobytes(mw_point_t* out, const mw_ge_p3* h) {
    mw_fe recip, x, y;
    mw_fe_invert(recip, h->Z);
    mw_fe_mul(x, h->X, recip);
    mw_fe_mul(y, h->Y, recip);
    mw_fe_tobytes(out->b, y);
    out->b[31] ^= (uint8_t)(mw_fe_isnegative(x) << 7);
}

int mw_ge_frombytes_vartime(mw_ge_p3* h, const mw_point_t* p) {
    mw_fe u, v, v3, vxx, check;

    mw_fe_frombytes(h->Y, p->b);
    mw_fe_1(h->Z);
    mw_fe_sq(u, h->Y);
    mw_fe_mul(v, u, mw_fe_d);
    mw_fe_sub(u, u, h->Z);      // u = y^2 - 1
    mw_fe_add(v, v, h->Z);      // v = d*y^2 + 1

    mw_fe_sq(v3, v);
    mw_fe_mul(v3, v3, v);       // v^3
    mw_fe_sq(h->X, v3);
    mw_fe_mul(h->X, h->X, v);
    mw_fe_mul(h->X, h->X, u);   // u * v^7

    mw_fe_pow22523(h->X, h->X); // (u*v^7)^((p-5)/8)
    mw_fe_mul(h->X, h->X, v3);
    mw_fe_mul(h->X, h->X, u);   // u*v^3 * (u*v^7)^((p-5)/8)

    mw_fe_sq(vxx, h->X);
    mw_fe_mul(vxx, vxx, v);
    mw_fe_sub(check, vxx, u);
    if (mw_fe_isnonzero(check)) {
        mw_fe_add(check, vxx, u);
        if (mw_fe_isnonzero(check)) {
            return -1;
        }
        mw_fe_mul(h->X, h->X, mw_fe_sqrtm1);
    }

    if (mw_fe_isnegative(h->X) != (p->b[31] >> 7)) {
        mw_fe_neg(h->X, h->X);
    }
    mw_fe_mul(h->T, h->X, h->Y);
    return 0;
}

// ---------------------------------------------------------------------------
// Constant-time selection helpers
// ---------------------------------------------------------------------------

static uint8_t ct_eq_i8(int8_t a, int8_t b) {
    uint32_t x = (uint32_t)((uint8_t)a ^ (uint8_t)b);
    return (uint8_t)(((x - 1u) >> 31) & 1u);
}

static uint8_t ct_is_neg_i8(int8_t b) {
    return (uint8_t)(((uint32_t)(uint8_t)b >> 7) & 1u);
}

static void ge_precomp_cmov(mw_ge_precomp* t, const mw_ge_precomp* u, unsigned int b) {
    mw_fe_cmov(t->yplusx, u->yplusx, b);
    mw_fe_cmov(t->yminusx, u->yminusx, b);
    mw_fe_cmov(t->xy2d, u->xy2d, b);
}

static void ge_cached_cmov(mw_ge_cached* t, const mw_ge_cached* u, unsigned int b) {
    mw_fe_cmov(t->YplusX, u->YplusX, b);
    mw_fe_cmov(t->YminusX, u->YminusX, b);
    mw_fe_cmov(t->Z, u->Z, b);
    mw_fe_cmov(t->T2d, u->T2d, b);
}

// Constant-time lookup of |b| * 16^(2*pos) * B, negated when b < 0.
static void ge_base_select(mw_ge_precomp* t, int pos, int8_t b) {
    mw_ge_precomp minus;
    uint8_t bneg = ct_is_neg_i8(b);
    uint8_t babs = (uint8_t)(b - (int8_t)((uint8_t)(0u - bneg) & (uint8_t)b) * 2);

    mw_ge_precomp_0(t);
    for (int i = 0; i < 8; ++i) {
        ge_precomp_cmov(t, &mw_ge_base[pos][i], ct_eq_i8((int8_t)babs, (int8_t)(i + 1)));
    }
    mw_fe_copy(minus.yplusx, t->yminusx);
    mw_fe_copy(minus.yminusx, t->yplusx);
    mw_fe_neg(minus.xy2d, t->xy2d);
    ge_precomp_cmov(t, &minus, bneg);

    mw_memzero(&minus, sizeof(minus));
}

// Splits a 32-byte scalar into 64 signed nibbles in [-8, 8].
static void scalar_to_signed_nibbles(int8_t e[64], const uint8_t a[32]) {
    for (int i = 0; i < 32; ++i) {
        e[2 * i + 0] = (int8_t)(a[i] & 15);
        e[2 * i + 1] = (int8_t)((a[i] >> 4) & 15);
    }
    int8_t carry = 0;
    for (int i = 0; i < 63; ++i) {
        e[i] = (int8_t)(e[i] + carry);
        carry = (int8_t)((e[i] + 8) >> 4);
        e[i] = (int8_t)(e[i] - mw_shl_i(carry, 4));
    }
    e[63] = (int8_t)(e[63] + carry);
}

void mw_ge_scalarmult_base(mw_ge_p3* r, const mw_scalar_t* a) {
    int8_t        e[64];
    mw_ge_p1p1    t;
    mw_ge_p2      s;
    mw_ge_precomp pc;

    scalar_to_signed_nibbles(e, a->b);

    mw_ge_p3_0(r);
    for (int i = 1; i < 64; i += 2) {
        ge_base_select(&pc, i / 2, e[i]);
        mw_ge_madd(&t, r, &pc);
        mw_ge_p1p1_to_p3(r, &t);
    }

    mw_ge_p3_dbl(&t, r);  mw_ge_p1p1_to_p2(&s, &t);
    mw_ge_p2_dbl(&t, &s); mw_ge_p1p1_to_p2(&s, &t);
    mw_ge_p2_dbl(&t, &s); mw_ge_p1p1_to_p2(&s, &t);
    mw_ge_p2_dbl(&t, &s); mw_ge_p1p1_to_p3(r, &t);

    for (int i = 0; i < 64; i += 2) {
        ge_base_select(&pc, i / 2, e[i]);
        mw_ge_madd(&t, r, &pc);
        mw_ge_p1p1_to_p3(r, &t);
    }

    mw_memzero(e, sizeof(e));
    mw_memzero(&pc, sizeof(pc));
    mw_memzero(&t, sizeof(t));
    mw_memzero(&s, sizeof(s));
}

void mw_ge_scalarmult(mw_ge_p3* r, const mw_scalar_t* a, const mw_ge_p3* p) {
    mw_ge_cached tbl[8];     // 1P .. 8P
    mw_ge_cached sel, minus;
    mw_ge_p1p1   t;
    mw_ge_p2     s;
    mw_ge_p3     cur;
    int8_t       e[64];

    mw_ge_p3_to_cached(&tbl[0], p);
    cur = *p;
    for (int i = 1; i < 8; ++i) {
        mw_ge_add(&t, &cur, &tbl[0]);
        mw_ge_p1p1_to_p3(&cur, &t);
        mw_ge_p3_to_cached(&tbl[i], &cur);
    }

    scalar_to_signed_nibbles(e, a->b);

    mw_ge_p3_0(r);
    for (int i = 63; i >= 0; --i) {
        // r = 16 * r
        mw_ge_p3_dbl(&t, r);  mw_ge_p1p1_to_p2(&s, &t);
        mw_ge_p2_dbl(&t, &s); mw_ge_p1p1_to_p2(&s, &t);
        mw_ge_p2_dbl(&t, &s); mw_ge_p1p1_to_p2(&s, &t);
        mw_ge_p2_dbl(&t, &s); mw_ge_p1p1_to_p3(r, &t);

        uint8_t bneg = ct_is_neg_i8(e[i]);
        uint8_t babs = (uint8_t)(e[i] - (int8_t)((uint8_t)(0u - bneg) & (uint8_t)e[i]) * 2);

        ge_cached_0(&sel);
        for (int j = 0; j < 8; ++j) {
            ge_cached_cmov(&sel, &tbl[j], ct_eq_i8((int8_t)babs, (int8_t)(j + 1)));
        }
        mw_fe_copy(minus.YplusX, sel.YminusX);
        mw_fe_copy(minus.YminusX, sel.YplusX);
        mw_fe_copy(minus.Z, sel.Z);
        mw_fe_neg(minus.T2d, sel.T2d);
        ge_cached_cmov(&sel, &minus, bneg);

        mw_ge_add(&t, r, &sel);
        mw_ge_p1p1_to_p3(r, &t);
    }

    mw_memzero(tbl, sizeof(tbl));
    mw_memzero(&sel, sizeof(sel));
    mw_memzero(&minus, sizeof(minus));
    mw_memzero(&t, sizeof(t));
    mw_memzero(&s, sizeof(s));
    mw_memzero(&cur, sizeof(cur));
    mw_memzero(e, sizeof(e));
}

// ---------------------------------------------------------------------------
// Variable-time double scalar multiplication (PUBLIC data only)
// ---------------------------------------------------------------------------

// Non-adjacent form with a window of 5 (ref10's `slide`).
static void slide(int8_t r[256], const uint8_t a[32]) {
    for (int i = 0; i < 256; ++i) {
        r[i] = (int8_t)(1 & (a[i >> 3] >> (i & 7)));
    }
    for (int i = 0; i < 256; ++i) {
        if (!r[i]) { continue; }
        for (int b = 1; b <= 6 && i + b < 256; ++b) {
            if (!r[i + b]) { continue; }
            int shifted = mw_shl_i(r[i + b], b);
            if (r[i] + shifted <= 15) {
                r[i] = (int8_t)(r[i] + shifted);
                r[i + b] = 0;
            } else if (r[i] - shifted >= -15) {
                r[i] = (int8_t)(r[i] - shifted);
                for (int k = i + b; k < 256; ++k) {
                    if (!r[k]) { r[k] = 1; break; }
                    r[k] = 0;
                }
            } else {
                break;
            }
        }
    }
}

// Builds A, 3A, 5A, ..., 15A in cached form.
static void build_odd_table(mw_ge_cached ai[8], const mw_ge_p3* a) {
    mw_ge_p3   a2, u;
    mw_ge_p1p1 t;

    mw_ge_p3_to_cached(&ai[0], a);
    mw_ge_p3_dbl(&t, a);
    mw_ge_p1p1_to_p3(&a2, &t);
    for (int i = 0; i < 7; ++i) {
        mw_ge_add(&t, &a2, &ai[i]);
        mw_ge_p1p1_to_p3(&u, &t);
        mw_ge_p3_to_cached(&ai[i + 1], &u);
    }
}

void mw_ge_double_scalarmult_base_vartime(mw_ge_p2* r, const mw_scalar_t* a,
                                          const mw_ge_p3* p, const mw_scalar_t* b) {
    int8_t       aslide[256];
    int8_t       bslide[256];
    mw_ge_cached ai[8];
    mw_ge_p1p1   t;
    mw_ge_p3     u;
    int          i;

    slide(aslide, a->b);
    slide(bslide, b->b);
    build_odd_table(ai, p);

    mw_ge_p2_0(r);

    for (i = 255; i >= 0; --i) {
        if (aslide[i] || bslide[i]) { break; }
    }
    for (; i >= 0; --i) {
        mw_ge_p2_dbl(&t, r);
        if (aslide[i] > 0) {
            mw_ge_p1p1_to_p3(&u, &t);
            mw_ge_add(&t, &u, &ai[aslide[i] / 2]);
        } else if (aslide[i] < 0) {
            mw_ge_p1p1_to_p3(&u, &t);
            mw_ge_sub(&t, &u, &ai[(-aslide[i]) / 2]);
        }
        if (bslide[i] > 0) {
            mw_ge_p1p1_to_p3(&u, &t);
            mw_ge_madd(&t, &u, &mw_ge_Bi[bslide[i] / 2]);
        } else if (bslide[i] < 0) {
            mw_ge_p1p1_to_p3(&u, &t);
            mw_ge_msub(&t, &u, &mw_ge_Bi[(-bslide[i]) / 2]);
        }
        mw_ge_p1p1_to_p2(r, &t);
    }
}

void mw_ge_double_scalarmult_vartime(mw_ge_p2* r, const mw_scalar_t* a,
                                     const mw_ge_p3* p, const mw_scalar_t* b,
                                     const mw_ge_p3* q) {
    int8_t       aslide[256];
    int8_t       bslide[256];
    mw_ge_cached ai[8], bi[8];
    mw_ge_p1p1   t;
    mw_ge_p3     u;
    int          i;

    slide(aslide, a->b);
    slide(bslide, b->b);
    build_odd_table(ai, p);
    build_odd_table(bi, q);

    mw_ge_p2_0(r);

    for (i = 255; i >= 0; --i) {
        if (aslide[i] || bslide[i]) { break; }
    }
    for (; i >= 0; --i) {
        mw_ge_p2_dbl(&t, r);
        if (aslide[i] > 0) {
            mw_ge_p1p1_to_p3(&u, &t);
            mw_ge_add(&t, &u, &ai[aslide[i] / 2]);
        } else if (aslide[i] < 0) {
            mw_ge_p1p1_to_p3(&u, &t);
            mw_ge_sub(&t, &u, &ai[(-aslide[i]) / 2]);
        }
        if (bslide[i] > 0) {
            mw_ge_p1p1_to_p3(&u, &t);
            mw_ge_add(&t, &u, &bi[bslide[i] / 2]);
        } else if (bslide[i] < 0) {
            mw_ge_p1p1_to_p3(&u, &t);
            mw_ge_sub(&t, &u, &bi[(-bslide[i]) / 2]);
        }
        mw_ge_p1p1_to_p2(r, &t);
    }
}

// ===========================================================================
// Scalar arithmetic mod l  (Barrett reduction, 32-bit limbs)
// ===========================================================================

#define SC_LIMBS 8

// l = 2^252 + 27742317777372353535851937790883648493
static const uint32_t SC_L[SC_LIMBS] = {
    0x5cf5d3edu, 0x5812631au, 0xa2f79cd6u, 0x14def9deu,
    0x00000000u, 0x00000000u, 0x00000000u, 0x10000000u
};

// mu = floor(2^512 / l), 260 bits -> 9 limbs.
static const uint32_t SC_MU[SC_LIMBS + 1] = {
    0x0a2c131bu, 0xed9ce5a3u, 0x086329a7u, 0x2106215du,
    0xffffffebu, 0xffffffffu, 0xffffffffu, 0xffffffffu, 0x0000000fu
};

// Column-wise ("comba") multiply; writes exactly `n_out` low limbs of a*b.
static void bn_mul_low(uint32_t* out, size_t n_out,
                       const uint32_t* a, size_t na,
                       const uint32_t* b, size_t nb) {
    uint64_t acc = 0;
    uint32_t hi  = 0;
    for (size_t k = 0; k < n_out; ++k) {
        size_t i_lo = (k + 1 > nb) ? (k + 1 - nb) : 0;
        size_t i_hi = (k < na - 1) ? k : (na - 1);
        for (size_t i = i_lo; i <= i_hi; ++i) {
            uint64_t prod = (uint64_t)a[i] * (uint64_t)b[k - i];
            uint64_t prev = acc;
            acc += prod;
            if (acc < prev) { hi++; }
        }
        out[k] = (uint32_t)acc;
        acc = (acc >> 32) | ((uint64_t)hi << 32);
        hi  = 0;
    }
}

// out = a - b (mod 2^(32*n)); returns the borrow.
static uint32_t bn_sub(uint32_t* out, const uint32_t* a, const uint32_t* b, size_t n) {
    uint64_t borrow = 0;
    for (size_t i = 0; i < n; ++i) {
        uint64_t d = (uint64_t)a[i] - (uint64_t)b[i] - borrow;
        out[i] = (uint32_t)d;
        borrow = (d >> 63) & 1u;
    }
    return (uint32_t)borrow;
}

// Constant-time: out = cond ? a : b.
static void bn_select(uint32_t* out, const uint32_t* a, const uint32_t* b,
                      size_t n, uint32_t cond) {
    uint32_t mask = (uint32_t)0u - (cond & 1u);
    for (size_t i = 0; i < n; ++i) {
        out[i] = (b[i] ^ ((a[i] ^ b[i]) & mask));
    }
}

// Subtracts l from r while r >= l. `n` must be >= SC_LIMBS.
static void bn_cond_sub_l(uint32_t* r, size_t n, int rounds) {
    uint32_t tmp[SC_LIMBS + 1];
    uint32_t lext[SC_LIMBS + 1];
    for (size_t i = 0; i < SC_LIMBS; ++i) { lext[i] = SC_L[i]; }
    for (size_t i = SC_LIMBS; i < n; ++i) { lext[i] = 0; }

    for (int k = 0; k < rounds; ++k) {
        uint32_t borrow = bn_sub(tmp, r, lext, n);
        // borrow == 0 means r >= l, so keep the difference.
        bn_select(r, tmp, r, n, borrow ^ 1u);
    }
    mw_memzero(tmp, sizeof(tmp));
}

// Barrett reduction of the 512-bit value `x` (16 limbs) modulo l.
static void sc_barrett(uint32_t out[SC_LIMBS], const uint32_t x[2 * SC_LIMBS]) {
    const size_t k = SC_LIMBS;
    uint32_t q1[SC_LIMBS + 1];      // floor(x / b^(k-1)), 9 limbs
    uint32_t q2[2 * SC_LIMBS + 2];  // q1 * mu, 18 limbs
    uint32_t q3[SC_LIMBS + 1];      // floor(q2 / b^(k+1)), 9 limbs
    uint32_t r1[SC_LIMBS + 1];      // x mod b^(k+1)
    uint32_t r2[SC_LIMBS + 1];      // (q3 * l) mod b^(k+1)
    uint32_t r[SC_LIMBS + 1];

    for (size_t i = 0; i < k + 1; ++i) { q1[i] = x[k - 1 + i]; }
    bn_mul_low(q2, 2 * k + 2, q1, k + 1, SC_MU, k + 1);
    for (size_t i = 0; i < k + 1; ++i) { q3[i] = q2[k + 1 + i]; }

    for (size_t i = 0; i < k + 1; ++i) { r1[i] = x[i]; }
    bn_mul_low(r2, k + 1, q3, k + 1, SC_L, k);

    (void)bn_sub(r, r1, r2, k + 1);   // mod b^(k+1), borrow discarded
    bn_cond_sub_l(r, k + 1, 3);

    for (size_t i = 0; i < k; ++i) { out[i] = r[i]; }

    mw_memzero(q1, sizeof(q1)); mw_memzero(q2, sizeof(q2));
    mw_memzero(q3, sizeof(q3)); mw_memzero(r1, sizeof(r1));
    mw_memzero(r2, sizeof(r2)); mw_memzero(r,  sizeof(r));
}

static void sc_from_bytes(uint32_t out[SC_LIMBS], const uint8_t in[32]) {
    for (int i = 0; i < SC_LIMBS; ++i) {
        out[i] = (uint32_t)in[4 * i] | ((uint32_t)in[4 * i + 1] << 8) |
                 ((uint32_t)in[4 * i + 2] << 16) | ((uint32_t)in[4 * i + 3] << 24);
    }
}

static void sc_to_bytes(uint8_t out[32], const uint32_t in[SC_LIMBS]) {
    for (int i = 0; i < SC_LIMBS; ++i) {
        out[4 * i]     = (uint8_t)(in[i]);
        out[4 * i + 1] = (uint8_t)(in[i] >> 8);
        out[4 * i + 2] = (uint8_t)(in[i] >> 16);
        out[4 * i + 3] = (uint8_t)(in[i] >> 24);
    }
}

void mw_sc_reduce64(mw_scalar_t* out, const uint8_t in[64]) {
    uint32_t x[2 * SC_LIMBS];
    uint32_t r[SC_LIMBS];
    for (int i = 0; i < 2 * SC_LIMBS; ++i) {
        x[i] = (uint32_t)in[4 * i] | ((uint32_t)in[4 * i + 1] << 8) |
               ((uint32_t)in[4 * i + 2] << 16) | ((uint32_t)in[4 * i + 3] << 24);
    }
    sc_barrett(r, x);
    sc_to_bytes(out->b, r);
    mw_memzero(x, sizeof(x));
    mw_memzero(r, sizeof(r));
}

void mw_sc_reduce32(mw_scalar_t* s) {
    uint32_t x[2 * SC_LIMBS];
    uint32_t r[SC_LIMBS];
    memset(x, 0, sizeof(x));
    sc_from_bytes(x, s->b);
    sc_barrett(r, x);
    sc_to_bytes(s->b, r);
    mw_memzero(x, sizeof(x));
    mw_memzero(r, sizeof(r));
}

void mw_sc_add(mw_scalar_t* r, const mw_scalar_t* a, const mw_scalar_t* b) {
    uint32_t xa[SC_LIMBS + 1], xb[SC_LIMBS + 1], s[SC_LIMBS + 1];
    memset(xa, 0, sizeof(xa));
    memset(xb, 0, sizeof(xb));
    sc_from_bytes(xa, a->b);
    sc_from_bytes(xb, b->b);

    uint64_t carry = 0;
    for (int i = 0; i < SC_LIMBS + 1; ++i) {
        uint64_t t = (uint64_t)xa[i] + (uint64_t)xb[i] + carry;
        s[i] = (uint32_t)t;
        carry = t >> 32;
    }
    bn_cond_sub_l(s, SC_LIMBS + 1, 2);
    sc_to_bytes(r->b, s);

    mw_memzero(xa, sizeof(xa)); mw_memzero(xb, sizeof(xb));
    mw_memzero(s, sizeof(s));
}

void mw_sc_sub(mw_scalar_t* r, const mw_scalar_t* a, const mw_scalar_t* b) {
    uint32_t xa[SC_LIMBS], xb[SC_LIMBS], d[SC_LIMBS], dl[SC_LIMBS];
    sc_from_bytes(xa, a->b);
    sc_from_bytes(xb, b->b);

    uint32_t borrow = bn_sub(d, xa, xb, SC_LIMBS);
    // If a < b add l back.
    uint64_t carry = 0;
    for (int i = 0; i < SC_LIMBS; ++i) {
        uint64_t t = (uint64_t)d[i] + (uint64_t)SC_L[i] + carry;
        dl[i] = (uint32_t)t;
        carry = t >> 32;
    }
    bn_select(d, dl, d, SC_LIMBS, borrow);
    sc_to_bytes(r->b, d);

    mw_memzero(xa, sizeof(xa)); mw_memzero(xb, sizeof(xb));
    mw_memzero(d, sizeof(d));   mw_memzero(dl, sizeof(dl));
}

void mw_sc_mul(mw_scalar_t* r, const mw_scalar_t* a, const mw_scalar_t* b) {
    uint32_t xa[SC_LIMBS], xb[SC_LIMBS], prod[2 * SC_LIMBS], res[SC_LIMBS];
    sc_from_bytes(xa, a->b);
    sc_from_bytes(xb, b->b);
    bn_mul_low(prod, 2 * SC_LIMBS, xa, SC_LIMBS, xb, SC_LIMBS);
    sc_barrett(res, prod);
    sc_to_bytes(r->b, res);

    mw_memzero(xa, sizeof(xa)); mw_memzero(xb, sizeof(xb));
    mw_memzero(prod, sizeof(prod)); mw_memzero(res, sizeof(res));
}

void mw_sc_muladd(mw_scalar_t* r, const mw_scalar_t* a, const mw_scalar_t* b,
                  const mw_scalar_t* c) {
    mw_scalar_t t;
    mw_sc_mul(&t, a, b);
    mw_sc_add(r, &t, c);
    mw_memzero(&t, sizeof(t));
}

void mw_sc_mulsub(mw_scalar_t* r, const mw_scalar_t* a, const mw_scalar_t* b,
                  const mw_scalar_t* c) {
    mw_scalar_t t;
    mw_sc_mul(&t, a, b);
    mw_sc_sub(r, c, &t);
    mw_memzero(&t, sizeof(t));
}

void mw_sc_invert(mw_scalar_t* r, const mw_scalar_t* a) {
    // a^(l-2) mod l. The exponent is a public constant, so a plain
    // square-and-multiply ladder leaks nothing about `a`.
    static const uint8_t lm2[32] = {
        0xeb, 0xd3, 0xf5, 0x5c, 0x1a, 0x63, 0x12, 0x58,
        0xd6, 0x9c, 0xf7, 0xa2, 0xde, 0xf9, 0xde, 0x14,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x10
    };
    mw_scalar_t acc, base;
    mw_sc_1(&acc);
    base = *a;

    for (int i = 0; i < 253; ++i) {
        if ((lm2[i >> 3] >> (i & 7)) & 1) {
            mw_sc_mul(&acc, &acc, &base);
        }
        mw_sc_mul(&base, &base, &base);
    }
    *r = acc;
    mw_memzero(&acc, sizeof(acc));
    mw_memzero(&base, sizeof(base));
}

int mw_sc_is_zero(const mw_scalar_t* s) {
    return mw_ct_is_zero(s->b, 32);
}

int mw_sc_check(const mw_scalar_t* s) {
    uint32_t x[SC_LIMBS], t[SC_LIMBS];
    sc_from_bytes(x, s->b);
    uint32_t borrow = bn_sub(t, x, SC_L, SC_LIMBS);
    mw_memzero(x, sizeof(x));
    mw_memzero(t, sizeof(t));
    return (int)borrow;   // borrow == 1  <=>  s < l
}

int mw_sc_eq(const mw_scalar_t* a, const mw_scalar_t* b) {
    return mw_ct_equal(a->b, b->b, 32);
}

void mw_sc_0(mw_scalar_t* s) { memset(s->b, 0, 32); }

void mw_sc_1(mw_scalar_t* s) { memset(s->b, 0, 32); s->b[0] = 1; }

void mw_sc_random(mw_scalar_t* s) {
    for (;;) {
        mw_random_bytes(s->b, 32);
        s->b[31] &= 0x1f;           // keeps the rejection rate tiny
        if (mw_sc_check(s) && !mw_sc_is_zero(s)) {
            return;
        }
    }
}

void mw_hash_to_scalar(const uint8_t* data, size_t len, mw_scalar_t* out) {
    mw_keccak256(data, len, out->b);
    mw_sc_reduce32(out);
}

// ===========================================================================
// Byte-level helpers
// ===========================================================================

const mw_scalar_t MW_SC_ZERO = { { 0 } };
const mw_scalar_t MW_SC_ONE  = { { 1 } };
const mw_scalar_t MW_SC_L    = { {
    0xed, 0xd3, 0xf5, 0x5c, 0x1a, 0x63, 0x12, 0x58,
    0xd6, 0x9c, 0xf7, 0xa2, 0xde, 0xf9, 0xde, 0x14,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x10
} };
const mw_point_t MW_POINT_G = { {
    0x58, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66,
    0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66,
    0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66,
    0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66
} };
const mw_point_t MW_POINT_IDENTITY = { { 1, 0 } };

int mw_point_add(mw_point_t* r, const mw_point_t* a, const mw_point_t* b) {
    mw_ge_p3     pa, pb, res;
    mw_ge_cached cb;
    mw_ge_p1p1   t;

    if (mw_ge_frombytes_vartime(&pa, a) != 0) { return -1; }
    if (mw_ge_frombytes_vartime(&pb, b) != 0) { return -1; }
    mw_ge_p3_to_cached(&cb, &pb);
    mw_ge_add(&t, &pa, &cb);
    mw_ge_p1p1_to_p3(&res, &t);
    mw_ge_p3_tobytes(r, &res);
    return 0;
}

int mw_point_sub(mw_point_t* r, const mw_point_t* a, const mw_point_t* b) {
    mw_ge_p3     pa, pb, res;
    mw_ge_cached cb;
    mw_ge_p1p1   t;

    if (mw_ge_frombytes_vartime(&pa, a) != 0) { return -1; }
    if (mw_ge_frombytes_vartime(&pb, b) != 0) { return -1; }
    mw_ge_p3_to_cached(&cb, &pb);
    mw_ge_sub(&t, &pa, &cb);
    mw_ge_p1p1_to_p3(&res, &t);
    mw_ge_p3_tobytes(r, &res);
    return 0;
}

int mw_point_scalarmult(mw_point_t* r, const mw_scalar_t* a, const mw_point_t* p) {
    mw_ge_p3 pp, res;
    if (mw_ge_frombytes_vartime(&pp, p) != 0) { return -1; }
    mw_ge_scalarmult(&res, a, &pp);
    mw_ge_p3_tobytes(r, &res);
    mw_memzero(&res, sizeof(res));
    return 0;
}

void mw_point_scalarmult_base(mw_point_t* r, const mw_scalar_t* a) {
    mw_ge_p3 res;
    mw_ge_scalarmult_base(&res, a);
    mw_ge_p3_tobytes(r, &res);
    mw_memzero(&res, sizeof(res));
}

int mw_point_is_identity(const mw_point_t* p) {
    return mw_ct_equal(p->b, MW_POINT_IDENTITY.b, 32);
}

int mw_point_eq(const mw_point_t* a, const mw_point_t* b) {
    return mw_ct_equal(a->b, b->b, 32);
}

int mw_point_is_valid(const mw_point_t* p) {
    mw_ge_p3 t;
    return mw_ge_frombytes_vartime(&t, p) == 0;
}

int mw_point_in_main_subgroup(const mw_point_t* p) {
    mw_ge_p3   pp;
    mw_ge_p2   res;
    mw_point_t out;

    if (mw_ge_frombytes_vartime(&pp, p) != 0) { return 0; }
    // l * P must be the identity. The point is public (it arrived from outside
    // the device), so the variable-time ladder is fine here and much cheaper.
    // MW_SC_L is deliberately not reduced; the ladder uses its raw bits.
    mw_ge_double_scalarmult_base_vartime(&res, &MW_SC_L, &pp, &MW_SC_ZERO);
    mw_ge_p2_tobytes(&out, &res);
    return mw_point_is_identity(&out);
}

int mw_point_check_public(const mw_point_t* p) {
    // The identity decodes fine and trivially satisfies l*P == 0, but it is
    // never a legitimate public key, commitment or key image: reject it here
    // so callers cannot be tricked into a degenerate group element.
    if (mw_point_is_identity(p)) { return 0; }
    return mw_point_is_valid(p) && mw_point_in_main_subgroup(p);
}

// Exposed for monero_curve.c
int mw_fe_eq_internal(const mw_fe a, const mw_fe b) { return fe_eq(a, b); }
