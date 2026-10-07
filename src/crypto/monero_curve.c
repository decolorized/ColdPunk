// Monero-specific curve operations layered on top of the ref10 primitives in
// ed25519.c:
//
//   * ge_fromfe_frombytes_vartime - the Elligator-style map Monero uses for
//     hash_to_point / key images. Bit-for-bit identical to Monero's
//     src/crypto/crypto-ops.c; a mismatch here produces wrong key images and
//     unspendable outputs.
//   * MW_POINT_H / MW_GE_P3_H     - the second generator used for amounts.
//   * mw_commit / mw_scalarmult_H - Pedersen commitments.
//   * mw_bp_get_exponent          - Bulletproofs+ generator chain.
//   * subgroup validation         - TZ 8.3.
#include "ed25519.h"
#include "hash.h"
#include "memzero.h"

#include <string.h>

// ---------------------------------------------------------------------------
// Internals borrowed from ed25519.c / ed25519_tables.c
// ---------------------------------------------------------------------------
void mw_fe_0(mw_fe h);
void mw_fe_1(mw_fe h);
void mw_fe_copy(mw_fe h, const mw_fe f);
void mw_fe_add(mw_fe h, const mw_fe f, const mw_fe g);
void mw_fe_sub(mw_fe h, const mw_fe f, const mw_fe g);
void mw_fe_neg(mw_fe h, const mw_fe f);
void mw_fe_mul(mw_fe h, const mw_fe f, const mw_fe g);
void mw_fe_sq(mw_fe h, const mw_fe f);
void mw_fe_sq2(mw_fe h, const mw_fe f);
void mw_fe_invert(mw_fe out, const mw_fe z);
void mw_fe_pow22523(mw_fe out, const mw_fe z);
void mw_fe_frombytes_wide(mw_fe h, const uint8_t s[32]);
void mw_fe_tobytes(uint8_t s[32], const mw_fe h);
int  mw_fe_isnegative(const mw_fe f);
int  mw_fe_isnonzero(const mw_fe f);
void mw_ge_p3_to_p2(mw_ge_p2* r, const mw_ge_p3* p);

extern const mw_fe mw_fe_sqrtm1;
extern const mw_fe mw_fe_ma;      // -A
extern const mw_fe mw_fe_ma2;     // -A^2
extern const mw_fe mw_fe_fffb1;   // sqrt(-2 * A * (A + 2))
extern const mw_fe mw_fe_fffb2;   // sqrt( 2 * A * (A + 2))
extern const mw_fe mw_fe_fffb3;   // sqrt(-sqrt(-1) * A * (A + 2))
extern const mw_fe mw_fe_fffb4;   // sqrt( sqrt(-1) * A * (A + 2))

// ---------------------------------------------------------------------------
// Monero's second generator H.
//
// Monero hard-codes this constant (rct::H in src/ringct/rctTypes.h). Its
// comment claims H = toPoint(cn_fast_hash(G)); that is historically
// inaccurate - recomputing it from the base point yields a different point -
// so the constant itself is authoritative and is reproduced verbatim here.
// ---------------------------------------------------------------------------
const mw_point_t MW_POINT_H = { {
    0x8b, 0x65, 0x59, 0x70, 0x15, 0x37, 0x99, 0xaf,
    0x2a, 0xea, 0xdc, 0x9f, 0xf1, 0xad, 0xd0, 0xea,
    0x6c, 0x72, 0x51, 0xd5, 0x41, 0x54, 0xcf, 0xa9,
    0x2c, 0x17, 0x3a, 0x0d, 0xd3, 0x9c, 0x1f, 0x94
} };

// H in extended coordinates (Z = 1, T = X*Y), so amount commitments do not
// have to decompress it on every call.
// Limbs are in ref10's balanced (signed) form: fe_mul's 19*g term overflows
// int32 if a table constant is stored with maximal unsigned limbs and then
// fed through ge_p3_to_cached's Y+X.
const mw_ge_p3 MW_GE_P3_H = {
    { 7329926, -15101362, 31411471, 7614783, 27996851,
      -3197071, -11157635, -6878293, 466949, -7986503 },
    { 5858699, 5096796, 21321203, -7536921, -5553480,
      -11439507, -5627669, 15045946, 19977121, 5275251 },
    { 1, 0, 0, 0, 0, 0, 0, 0, 0, 0 },
    { 23443568, -5110398, -8776029, -4345135, 6889568,
      -14710814, 7474843, 3279062, 14550766, -7453428 }
};

// ---------------------------------------------------------------------------
// fe_divpowm1: r = (u / v)^((p + 3) / 8)
// ---------------------------------------------------------------------------
static void fe_divpowm1(mw_fe r, const mw_fe u, const mw_fe v) {
    mw_fe v3, uv7, t0;

    mw_fe_sq(v3, v);
    mw_fe_mul(v3, v3, v);        // v^3
    mw_fe_sq(uv7, v3);
    mw_fe_mul(uv7, uv7, v);
    mw_fe_mul(uv7, uv7, u);      // u * v^7

    mw_fe_pow22523(t0, uv7);     // (u*v^7)^((p-5)/8)
    mw_fe_mul(t0, t0, v3);
    mw_fe_mul(r, t0, u);         // u^(m+1) * v^-(m+1)

    mw_memzero(v3, sizeof(v3));
    mw_memzero(uv7, sizeof(uv7));
    mw_memzero(t0, sizeof(t0));
}

// ---------------------------------------------------------------------------
// ge_fromfe_frombytes_vartime - Monero's hash-to-curve map.
//
// The 32 input bytes are read as a FULL 256-bit little-endian integer (bit 255
// included, folded back as 2^255 == 19); Monero's fe_frombytes copy inside this
// function deliberately omits the usual top-bit mask.
// ---------------------------------------------------------------------------
void mw_ge_fromfe_frombytes_vartime(mw_ge_p2* r, const uint8_t s[32]) {
    mw_fe u, v, w, x, y, z;
    int   sign;

    mw_fe_frombytes_wide(u, s);

    mw_fe_sq2(v, u);              // v = 2 * u^2
    mw_fe_1(w);
    mw_fe_add(w, v, w);           // w = 2*u^2 + 1
    mw_fe_sq(x, w);               // w^2
    mw_fe_mul(y, mw_fe_ma2, v);   // -2 * A^2 * u^2
    mw_fe_add(x, x, y);           // x = w^2 - 2*A^2*u^2
    fe_divpowm1(r->X, w, x);      // (w / x)^(m + 1)
    mw_fe_sq(y, r->X);
    mw_fe_mul(x, y, x);
    mw_fe_sub(y, w, x);
    mw_fe_copy(z, mw_fe_ma);      // z = -A

    if (mw_fe_isnonzero(y)) {
        mw_fe_add(y, w, x);
        if (mw_fe_isnonzero(y)) {
            goto negative;
        }
        mw_fe_mul(r->X, r->X, mw_fe_fffb1);
    } else {
        mw_fe_mul(r->X, r->X, mw_fe_fffb2);
    }
    mw_fe_mul(r->X, r->X, u);     // u * sqrt(2 * A * (A + 2) * w / x)
    mw_fe_mul(z, z, v);           // z = -2 * A * u^2
    sign = 0;
    goto setsign;

negative:
    mw_fe_mul(x, x, mw_fe_sqrtm1);
    mw_fe_sub(y, w, x);
    if (mw_fe_isnonzero(y)) {
        mw_fe_mul(r->X, r->X, mw_fe_fffb3);
    } else {
        mw_fe_mul(r->X, r->X, mw_fe_fffb4);
    }
    // r->X = sqrt(A * (A + 2) * w / x); z stays -A
    sign = 1;

setsign:
    if (mw_fe_isnegative(r->X) != sign) {
        mw_fe_neg(r->X, r->X);
    }
    mw_fe_add(r->Z, z, w);
    mw_fe_sub(r->Y, z, w);
    mw_fe_mul(r->X, r->X, r->Z);

    mw_memzero(u, sizeof(u)); mw_memzero(v, sizeof(v));
    mw_memzero(w, sizeof(w)); mw_memzero(x, sizeof(x));
    mw_memzero(y, sizeof(y)); mw_memzero(z, sizeof(z));
}

// hash_to_ec: cn_fast_hash -> ge_fromfe_frombytes_vartime -> mul8
void mw_hash_to_ec(const uint8_t* data, size_t len, mw_ge_p3* out) {
    uint8_t    h[MW_KECCAK_DIGEST];
    mw_ge_p2   p2;
    mw_ge_p1p1 p1;

    mw_keccak256(data, len, h);
    mw_ge_fromfe_frombytes_vartime(&p2, h);
    mw_ge_mul8(&p1, &p2);
    mw_ge_p1p1_to_p3(out, &p1);

    mw_memzero(h, sizeof(h));
    mw_memzero(&p2, sizeof(p2));
    mw_memzero(&p1, sizeof(p1));
}

void mw_hash_to_point(const uint8_t* data, size_t len, mw_point_t* out) {
    mw_ge_p3 p;
    mw_hash_to_ec(data, len, &p);
    mw_ge_p3_tobytes(out, &p);
    mw_memzero(&p, sizeof(p));
}

// ---------------------------------------------------------------------------
// Pedersen commitments
// ---------------------------------------------------------------------------

void mw_scalarmult_H(mw_point_t* out, const mw_scalar_t* b) {
    mw_ge_p3 r;
    mw_ge_scalarmult(&r, b, &MW_GE_P3_H);
    mw_ge_p3_tobytes(out, &r);
    mw_memzero(&r, sizeof(r));
}

void mw_commit(mw_point_t* out, const mw_scalar_t* mask, const mw_scalar_t* amount) {
    mw_ge_p3     ag, bh, sum;
    mw_ge_cached c;
    mw_ge_p1p1   t;

    // Both scalars are secret, so both multiplications are constant time.
    mw_ge_scalarmult_base(&ag, mask);
    mw_ge_scalarmult(&bh, amount, &MW_GE_P3_H);
    mw_ge_p3_to_cached(&c, &bh);
    mw_ge_add(&t, &ag, &c);
    mw_ge_p1p1_to_p3(&sum, &t);
    mw_ge_p3_tobytes(out, &sum);

    mw_memzero(&ag, sizeof(ag)); mw_memzero(&bh, sizeof(bh));
    mw_memzero(&sum, sizeof(sum)); mw_memzero(&c, sizeof(c));
    mw_memzero(&t, sizeof(t));
}

// ---------------------------------------------------------------------------
// Bulletproofs+ generator chain
//
// Monero (src/ringct/bulletproofs_plus.cc):
//
//   get_exponent(base, idx) =
//       hash_to_p3( cn_fast_hash( base || "bulletproof_plus" || varint(idx) ) )
//
// and hash_to_p3(k) itself hashes again, so there are TWO Keccak passes:
//
//   out = mul8( fromfe( keccak( keccak(H || "bulletproof_plus" || varint) ) ) )
//
// NOTE: ed25519.h documents this as a single hash_to_point() over the domain
// separator "bulletproof". That describes the ORIGINAL Bulletproofs generator
// chain, not Bulletproofs+ (RCT type 6), which is what this project produces.
// Using the documented form would generate proofs the network rejects, so the
// Monero-compatible definition wins here.
// ---------------------------------------------------------------------------
static size_t varint_encode(uint64_t v, uint8_t* out) {
    size_t n = 0;
    while (v >= 0x80) {
        out[n++] = (uint8_t)((v & 0x7f) | 0x80);
        v >>= 7;
    }
    out[n++] = (uint8_t)v;
    return n;
}

void mw_bp_get_exponent(mw_point_t* out, uint32_t idx) {
    static const char sep[] = "bulletproof_plus";
    uint8_t buf[32 + sizeof(sep) - 1 + 10];
    uint8_t h[MW_KECCAK_DIGEST];
    size_t  n = 0;

    memcpy(buf, MW_POINT_H.b, 32);
    n = 32;
    memcpy(buf + n, sep, sizeof(sep) - 1);
    n += sizeof(sep) - 1;
    n += varint_encode(idx, buf + n);

    mw_keccak256(buf, n, h);
    // hash_to_point() applies the second Keccak pass.
    mw_hash_to_point(h, sizeof(h), out);

    mw_memzero(buf, sizeof(buf));
    mw_memzero(h, sizeof(h));
}
