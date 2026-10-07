// Ed25519 field/group/scalar arithmetic plus the Monero-specific curve layer.
//
// All Monero-facing values in this suite were cross-checked against the
// reference implementation in monero-project/monero (src/crypto/crypto-ops.c
// and src/ringct/bulletproofs_plus.cc).
#include "test_framework.h"
#include "crypto/ed25519.h"
#include "crypto/hash.h"
#include "crypto/random.h"
#include "crypto/memzero.h"

#include <string.h>

// Internal helper from ed25519.c; not part of the public header.
void mw_ge_p3_to_p2(mw_ge_p2* r, const mw_ge_p3* p);

static mw_scalar_t sc_from_hex(const char* h) {
    mw_scalar_t s;
    memset(s.b, 0, 32);
    mw_test_hex(h, s.b, 32);
    return s;
}

static mw_point_t pt_from_hex(const char* h) {
    mw_point_t p;
    memset(p.b, 0, 32);
    mw_test_hex(h, p.b, 32);
    return p;
}

// Small deterministic PRNG so the suite is reproducible.
static uint32_t rng_state = 0x12345678u;
static uint8_t rnd_byte(void) {
    rng_state = rng_state * 1664525u + 1013904223u;
    return (uint8_t)(rng_state >> 24);
}
static mw_scalar_t rnd_scalar(void) {
    mw_scalar_t s;
    for (int i = 0; i < 32; ++i) { s.b[i] = rnd_byte(); }
    mw_sc_reduce32(&s);
    return s;
}

// ===========================================================================
// Scalar arithmetic
// ===========================================================================

MW_TEST(test_sc_constants) {
    CHECK_EQ_INT(mw_sc_is_zero(&MW_SC_ZERO), 1);
    CHECK_EQ_INT(mw_sc_is_zero(&MW_SC_ONE), 0);
    CHECK_EQ_INT(mw_sc_check(&MW_SC_ZERO), 1);
    CHECK_EQ_INT(mw_sc_check(&MW_SC_ONE), 1);
    // l itself is NOT a canonical scalar.
    CHECK_EQ_INT(mw_sc_check(&MW_SC_L), 0);

    mw_scalar_t z, o;
    mw_sc_0(&z);
    mw_sc_1(&o);
    CHECK_EQ_INT(mw_sc_eq(&z, &MW_SC_ZERO), 1);
    CHECK_EQ_INT(mw_sc_eq(&o, &MW_SC_ONE), 1);
    CHECK_EQ_INT(mw_sc_eq(&z, &o), 0);

    // l reduces to zero.
    mw_scalar_t l = MW_SC_L;
    mw_sc_reduce32(&l);
    CHECK_EQ_INT(mw_sc_is_zero(&l), 1);

    // l - 1 is the largest canonical scalar.
    mw_scalar_t lm1;
    mw_sc_sub(&lm1, &MW_SC_ZERO, &MW_SC_ONE);
    CHECK_EQ_INT(mw_sc_check(&lm1), 1);
    mw_scalar_t back;
    mw_sc_add(&back, &lm1, &MW_SC_ONE);
    CHECK_EQ_INT(mw_sc_is_zero(&back), 1);
}

MW_TEST(test_sc_reduce_known) {
    // sc_reduce32 of 0xff..ff: 2^256-1 mod l, cross-checked with Python.
    mw_scalar_t s;
    memset(s.b, 0xff, 32);
    mw_sc_reduce32(&s);
    mw_scalar_t want = sc_from_hex(
        "1c95988d7431ecd670cf7d73f45befc6feffffffffffffffffffffffffffff0f");
    CHECK_EQ_MEM(s.b, want.b, 32);
    CHECK_EQ_INT(mw_sc_check(&s), 1);

    // sc_reduce64 of 0xff..ff (64 bytes) == (2^512 - 1) mod l.
    uint8_t wide[64];
    memset(wide, 0xff, sizeof(wide));
    mw_scalar_t r;
    mw_sc_reduce64(&r, wide);
    mw_scalar_t want64 = sc_from_hex(
        "000f9c44e31106a447938568a71b0ed065bef517d273ecce3d9a307c1b419903");
    CHECK_EQ_MEM(r.b, want64.b, 32);
    CHECK_EQ_INT(mw_sc_check(&r), 1);

    // A 64-byte value whose top half is zero must reduce like sc_reduce32.
    uint8_t narrow[64];
    memset(narrow, 0, sizeof(narrow));
    memset(narrow, 0xff, 32);
    mw_sc_reduce64(&r, narrow);
    mw_scalar_t want32 = sc_from_hex(
        "1c95988d7431ecd670cf7d73f45befc6feffffffffffffffffffffffffffff0f");
    CHECK_EQ_MEM(r.b, want32.b, 32);

    // Already-reduced values are left alone.
    mw_scalar_t small = sc_from_hex(
        "0700000000000000000000000000000000000000000000000000000000000000");
    mw_scalar_t copy = small;
    mw_sc_reduce32(&copy);
    CHECK_EQ_MEM(copy.b, small.b, 32);
}

MW_TEST(test_sc_identities) {
    for (int t = 0; t < 64; ++t) {
        mw_scalar_t a = rnd_scalar();
        mw_scalar_t b = rnd_scalar();
        mw_scalar_t c = rnd_scalar();
        mw_scalar_t x, y, z;

        CHECK_EQ_INT(mw_sc_check(&a), 1);

        // a + 0 == a, a * 1 == a
        mw_sc_add(&x, &a, &MW_SC_ZERO);
        CHECK_EQ_INT(mw_sc_eq(&x, &a), 1);
        mw_sc_mul(&x, &a, &MW_SC_ONE);
        CHECK_EQ_INT(mw_sc_eq(&x, &a), 1);
        mw_sc_mul(&x, &a, &MW_SC_ZERO);
        CHECK_EQ_INT(mw_sc_is_zero(&x), 1);

        // commutativity
        mw_sc_add(&x, &a, &b);
        mw_sc_add(&y, &b, &a);
        CHECK_EQ_INT(mw_sc_eq(&x, &y), 1);
        mw_sc_mul(&x, &a, &b);
        mw_sc_mul(&y, &b, &a);
        CHECK_EQ_INT(mw_sc_eq(&x, &y), 1);

        // (a + b) - b == a
        mw_sc_add(&x, &a, &b);
        mw_sc_sub(&y, &x, &b);
        CHECK_EQ_INT(mw_sc_eq(&y, &a), 1);

        // associativity of multiplication
        mw_sc_mul(&x, &a, &b);
        mw_sc_mul(&x, &x, &c);
        mw_sc_mul(&y, &b, &c);
        mw_sc_mul(&y, &a, &y);
        CHECK_EQ_INT(mw_sc_eq(&x, &y), 1);

        // distributivity: a*(b+c) == a*b + a*c
        mw_sc_add(&x, &b, &c);
        mw_sc_mul(&x, &a, &x);
        mw_sc_mul(&y, &a, &b);
        mw_sc_mul(&z, &a, &c);
        mw_sc_add(&y, &y, &z);
        CHECK_EQ_INT(mw_sc_eq(&x, &y), 1);

        // muladd / mulsub against the primitive operations
        mw_sc_muladd(&x, &a, &b, &c);
        mw_sc_mul(&y, &a, &b);
        mw_sc_add(&y, &y, &c);
        CHECK_EQ_INT(mw_sc_eq(&x, &y), 1);

        mw_sc_mulsub(&x, &a, &b, &c);
        mw_sc_mul(&y, &a, &b);
        mw_sc_sub(&y, &c, &y);
        CHECK_EQ_INT(mw_sc_eq(&x, &y), 1);

        // a * a^-1 == 1
        if (!mw_sc_is_zero(&a)) {
            mw_sc_invert(&x, &a);
            mw_sc_mul(&y, &a, &x);
            CHECK_EQ_INT(mw_sc_eq(&y, &MW_SC_ONE), 1);
        }

        // Every result must stay canonical.
        mw_sc_mul(&x, &a, &b);
        CHECK_EQ_INT(mw_sc_check(&x), 1);
        mw_sc_add(&x, &a, &b);
        CHECK_EQ_INT(mw_sc_check(&x), 1);
        mw_sc_sub(&x, &a, &b);
        CHECK_EQ_INT(mw_sc_check(&x), 1);
    }
}

MW_TEST(test_hash_to_scalar) {
    // hash_to_scalar == sc_reduce32(keccak256(data))
    const char* msg = "monero";
    mw_scalar_t s;
    mw_hash_to_scalar((const uint8_t*)msg, strlen(msg), &s);

    mw_scalar_t manual;
    mw_keccak256((const uint8_t*)msg, strlen(msg), manual.b);
    mw_sc_reduce32(&manual);
    CHECK_EQ_MEM(s.b, manual.b, 32);
    CHECK_EQ_INT(mw_sc_check(&s), 1);
}

MW_TEST(test_sc_random_is_canonical) {
    static const uint8_t seed[] = "mw-test-seed-for-sc-random";
    mw_random_set_test_source(seed, sizeof(seed) - 1);
    for (int i = 0; i < 32; ++i) {
        mw_scalar_t s;
        mw_sc_random(&s);
        CHECK_EQ_INT(mw_sc_check(&s), 1);
        CHECK_EQ_INT(mw_sc_is_zero(&s), 0);
    }
    mw_random_set_test_source(NULL, 0);
}

// ===========================================================================
// Group arithmetic
// ===========================================================================

MW_TEST(test_base_point_multiples) {
    // Independently known small multiples of the Ed25519 base point.
    mw_point_t p;
    mw_scalar_t k;

    mw_sc_1(&k);
    mw_point_scalarmult_base(&p, &k);
    CHECK_EQ_MEM(p.b, MW_POINT_G.b, 32);

    mw_sc_0(&k); k.b[0] = 2;
    mw_point_scalarmult_base(&p, &k);
    mw_point_t want2 = pt_from_hex(
        "c9a3f86aae465f0e56513864510f3997561fa2c9e85ea21dc2292309f3cd6022");
    CHECK_EQ_MEM(p.b, want2.b, 32);

    mw_sc_0(&k); k.b[0] = 5;
    mw_point_scalarmult_base(&p, &k);
    mw_point_t want5 = pt_from_hex(
        "edc876d6831fd2105d0b4389ca2e283166469289146e2ce06faefe98b22548df");
    CHECK_EQ_MEM(p.b, want5.b, 32);

    mw_sc_0(&k); k.b[0] = 8;
    mw_point_scalarmult_base(&p, &k);
    mw_point_t want8 = pt_from_hex(
        "b4b937fca95b2f1e93e41e62fc3c78818ff38a66096fad6e7973e5c90006d321");
    CHECK_EQ_MEM(p.b, want8.b, 32);

    // 0*G is the identity.
    mw_sc_0(&k);
    mw_point_scalarmult_base(&p, &k);
    CHECK_EQ_INT(mw_point_is_identity(&p), 1);
    CHECK_EQ_MEM(p.b, MW_POINT_IDENTITY.b, 32);
}

MW_TEST(test_point_encode_decode_roundtrip) {
    for (int t = 0; t < 32; ++t) {
        mw_scalar_t k = rnd_scalar();
        mw_point_t  p, q;
        mw_ge_p3    e;

        mw_point_scalarmult_base(&p, &k);
        CHECK_EQ_INT(mw_ge_frombytes_vartime(&e, &p), 0);
        mw_ge_p3_tobytes(&q, &e);
        CHECK_EQ_MEM(p.b, q.b, 32);

        // The p2 form must encode identically.
        mw_ge_p2 e2;
        mw_ge_p3_to_p2(&e2, &e);
        mw_ge_p2_tobytes(&q, &e2);
        CHECK_EQ_MEM(p.b, q.b, 32);
    }
}

MW_TEST(test_point_add_sub_dbl_consistency) {
    for (int t = 0; t < 24; ++t) {
        mw_scalar_t a = rnd_scalar();
        mw_scalar_t b = rnd_scalar();
        mw_scalar_t s;
        mw_point_t  A, B, sum, diff, want;

        mw_point_scalarmult_base(&A, &a);
        mw_point_scalarmult_base(&B, &b);

        // (a*G) + (b*G) == (a+b)*G
        CHECK_EQ_INT(mw_point_add(&sum, &A, &B), 0);
        mw_sc_add(&s, &a, &b);
        mw_point_scalarmult_base(&want, &s);
        CHECK_EQ_MEM(sum.b, want.b, 32);

        // (a*G) - (b*G) == (a-b)*G
        CHECK_EQ_INT(mw_point_sub(&diff, &A, &B), 0);
        mw_sc_sub(&s, &a, &b);
        mw_point_scalarmult_base(&want, &s);
        CHECK_EQ_MEM(diff.b, want.b, 32);

        // A + A == 2A == doubling
        mw_point_t dbl_add, dbl_ge;
        CHECK_EQ_INT(mw_point_add(&dbl_add, &A, &A), 0);
        {
            mw_ge_p3   pa, pr;
            mw_ge_p1p1 t1;
            CHECK_EQ_INT(mw_ge_frombytes_vartime(&pa, &A), 0);
            mw_ge_p3_dbl(&t1, &pa);
            mw_ge_p1p1_to_p3(&pr, &t1);
            mw_ge_p3_tobytes(&dbl_ge, &pr);
        }
        CHECK_EQ_MEM(dbl_add.b, dbl_ge.b, 32);

        // A - A == identity, A + identity == A
        CHECK_EQ_INT(mw_point_sub(&diff, &A, &A), 0);
        CHECK_EQ_INT(mw_point_is_identity(&diff), 1);
        CHECK_EQ_INT(mw_point_add(&sum, &A, &MW_POINT_IDENTITY), 0);
        CHECK_EQ_MEM(sum.b, A.b, 32);
    }
}

MW_TEST(test_scalarmult_base_matches_scalarmult_G) {
    for (int t = 0; t < 24; ++t) {
        mw_scalar_t a = rnd_scalar();
        mw_point_t  viabase, viapoint;

        mw_point_scalarmult_base(&viabase, &a);
        CHECK_EQ_INT(mw_point_scalarmult(&viapoint, &a, &MW_POINT_G), 0);
        CHECK_EQ_MEM(viabase.b, viapoint.b, 32);
    }
}

MW_TEST(test_scalarmult_homomorphism) {
    for (int t = 0; t < 16; ++t) {
        mw_scalar_t a = rnd_scalar();
        mw_scalar_t b = rnd_scalar();
        mw_scalar_t ab;
        mw_point_t  P, Q, R;

        mw_point_scalarmult_base(&P, &a);
        // b*(a*G) == (a*b)*G
        CHECK_EQ_INT(mw_point_scalarmult(&Q, &b, &P), 0);
        mw_sc_mul(&ab, &a, &b);
        mw_point_scalarmult_base(&R, &ab);
        CHECK_EQ_MEM(Q.b, R.b, 32);

        // 0*P == identity, 1*P == P
        CHECK_EQ_INT(mw_point_scalarmult(&Q, &MW_SC_ZERO, &P), 0);
        CHECK_EQ_INT(mw_point_is_identity(&Q), 1);
        CHECK_EQ_INT(mw_point_scalarmult(&Q, &MW_SC_ONE, &P), 0);
        CHECK_EQ_MEM(Q.b, P.b, 32);
    }
}

MW_TEST(test_ge_mul8) {
    // mul8(P) must equal 8*P.
    for (int t = 0; t < 8; ++t) {
        mw_scalar_t a = rnd_scalar();
        mw_point_t  P, viamul8, via_scalar;
        mw_ge_p3    pp, pr;
        mw_ge_p2    p2;
        mw_ge_p1p1  t1;

        mw_point_scalarmult_base(&P, &a);
        CHECK_EQ_INT(mw_ge_frombytes_vartime(&pp, &P), 0);
        mw_ge_p3_to_p2(&p2, &pp);
        mw_ge_mul8(&t1, &p2);
        mw_ge_p1p1_to_p3(&pr, &t1);
        mw_ge_p3_tobytes(&viamul8, &pr);

        mw_scalar_t eight;
        mw_sc_0(&eight); eight.b[0] = 8;
        mw_sc_mul(&eight, &eight, &a);
        mw_point_scalarmult_base(&via_scalar, &eight);
        CHECK_EQ_MEM(viamul8.b, via_scalar.b, 32);
    }
}

MW_TEST(test_double_scalarmult_vartime) {
    for (int t = 0; t < 16; ++t) {
        mw_scalar_t a = rnd_scalar();
        mw_scalar_t b = rnd_scalar();
        mw_scalar_t c = rnd_scalar();
        mw_point_t  P, Q, got, want, tmp1, tmp2;
        mw_ge_p3    pp, qq;
        mw_ge_p2    r;

        mw_point_scalarmult_base(&P, &a);
        mw_point_scalarmult_base(&Q, &c);
        CHECK_EQ_INT(mw_ge_frombytes_vartime(&pp, &P), 0);
        CHECK_EQ_INT(mw_ge_frombytes_vartime(&qq, &Q), 0);

        // b*P + c*G
        mw_ge_double_scalarmult_base_vartime(&r, &b, &pp, &c);
        mw_ge_p2_tobytes(&got, &r);
        CHECK_EQ_INT(mw_point_scalarmult(&tmp1, &b, &P), 0);
        mw_point_scalarmult_base(&tmp2, &c);
        CHECK_EQ_INT(mw_point_add(&want, &tmp1, &tmp2), 0);
        CHECK_EQ_MEM(got.b, want.b, 32);

        // b*P + c*Q
        mw_ge_double_scalarmult_vartime(&r, &b, &pp, &c, &qq);
        mw_ge_p2_tobytes(&got, &r);
        CHECK_EQ_INT(mw_point_scalarmult(&tmp1, &b, &P), 0);
        CHECK_EQ_INT(mw_point_scalarmult(&tmp2, &c, &Q), 0);
        CHECK_EQ_INT(mw_point_add(&want, &tmp1, &tmp2), 0);
        CHECK_EQ_MEM(got.b, want.b, 32);

        // Zero scalars degrade gracefully.
        mw_ge_double_scalarmult_base_vartime(&r, &MW_SC_ZERO, &pp, &MW_SC_ZERO);
        mw_ge_p2_tobytes(&got, &r);
        CHECK_EQ_INT(mw_point_is_identity(&got), 1);
    }
}

// ===========================================================================
// Validation / subgroup checks (TZ 8.3)
// ===========================================================================

MW_TEST(test_subgroup_rejects_low_order_points) {
    // Order-1 point (the identity). It is in the main subgroup by definition,
    // but is never an acceptable public key.
    mw_point_t identity = pt_from_hex(
        "0100000000000000000000000000000000000000000000000000000000000000");
    CHECK_EQ_INT(mw_point_is_valid(&identity), 1);
    CHECK_EQ_INT(mw_point_in_main_subgroup(&identity), 1);
    CHECK_EQ_INT(mw_point_check_public(&identity), 0);

    // Order-8 point: on the curve but outside the prime-order subgroup.
    mw_point_t lo8 = pt_from_hex(
        "c7176a703d4dd84fba3c0b760d10670f2a2053fa2c39ccc64ec7fd7792ac03fa");
    CHECK_EQ_INT(mw_point_is_valid(&lo8), 1);
    CHECK_EQ_INT(mw_point_in_main_subgroup(&lo8), 0);
    CHECK_EQ_INT(mw_point_check_public(&lo8), 0);

    // Order-2 point (y = -1).
    mw_point_t lo2 = pt_from_hex(
        "ecffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff7f");
    CHECK_EQ_INT(mw_point_in_main_subgroup(&lo2), 0);
    CHECK_EQ_INT(mw_point_check_public(&lo2), 0);

    // Order-4 point.
    mw_point_t lo4 = pt_from_hex(
        "0000000000000000000000000000000000000000000000000000000000000080");
    CHECK_EQ_INT(mw_point_in_main_subgroup(&lo4), 0);
    CHECK_EQ_INT(mw_point_check_public(&lo4), 0);

    // Genuine public keys must pass everything.
    for (int t = 0; t < 8; ++t) {
        mw_scalar_t a = rnd_scalar();
        mw_point_t  P;
        mw_point_scalarmult_base(&P, &a);
        CHECK_EQ_INT(mw_point_is_valid(&P), 1);
        CHECK_EQ_INT(mw_point_in_main_subgroup(&P), 1);
        CHECK_EQ_INT(mw_point_check_public(&P), 1);
    }
}

MW_TEST(test_invalid_encodings_rejected) {
    // y values that are not x-coordinates of any curve point.
    mw_point_t bad = pt_from_hex(
        "0200000000000000000000000000000000000000000000000000000000000000");
    CHECK_EQ_INT(mw_point_is_valid(&bad), 0);
    CHECK_EQ_INT(mw_point_check_public(&bad), 0);

    mw_ge_p3 e;
    CHECK(mw_ge_frombytes_vartime(&e, &bad) != 0);

    // mw_point_add / _sub / _scalarmult must report the failure.
    mw_point_t out;
    CHECK(mw_point_add(&out, &bad, &MW_POINT_G) != 0);
    CHECK(mw_point_sub(&out, &MW_POINT_G, &bad) != 0);
    CHECK(mw_point_scalarmult(&out, &MW_SC_ONE, &bad) != 0);
}

MW_TEST(test_point_eq) {
    mw_point_t a = MW_POINT_G;
    mw_point_t b = MW_POINT_G;
    CHECK_EQ_INT(mw_point_eq(&a, &b), 1);
    b.b[0] ^= 1;
    CHECK_EQ_INT(mw_point_eq(&a, &b), 0);
}

// ===========================================================================
// Monero-specific curve layer
// ===========================================================================

MW_TEST(test_monero_H) {
    // Monero's second generator (rct::H).
    mw_point_t want = pt_from_hex(
        "8b655970153799af2aeadc9ff1add0ea6c7251d54154cfa92c173a0dd39c1f94");
    CHECK_EQ_MEM(MW_POINT_H.b, want.b, 32);

    // The expanded form must encode back to the same bytes.
    mw_point_t enc;
    mw_ge_p3_tobytes(&enc, &MW_GE_P3_H);
    CHECK_EQ_MEM(enc.b, want.b, 32);

    // H is a valid, torsion-free, non-identity point.
    CHECK_EQ_INT(mw_point_is_valid(&MW_POINT_H), 1);
    CHECK_EQ_INT(mw_point_in_main_subgroup(&MW_POINT_H), 1);
    CHECK_EQ_INT(mw_point_check_public(&MW_POINT_H), 1);

    // H must not be a small multiple of G.
    mw_scalar_t k;
    for (int i = 1; i <= 16; ++i) {
        mw_point_t p;
        mw_sc_0(&k); k.b[0] = (uint8_t)i;
        mw_point_scalarmult_base(&p, &k);
        CHECK_EQ_INT(mw_point_eq(&p, &MW_POINT_H), 0);
    }
}

MW_TEST(test_hash_to_point_vectors) {
    // Cross-checked byte for byte against Monero's
    // ge_fromfe_frombytes_vartime + ge_mul8 (crypto::hash_to_ec).
    struct { const char* in; const char* out; } v[] = {
        { "", "d6d7d783ab18e1be65586adb7902a4175b737ef0b902875e1d1d5c5cf0478c0b" },
        { "a", "998900b6db6baab2b537b057de5725649ebcf4540f115c169b3d73a489967bbf" },
        { "hello world",
          "3602ae2ba137336e563976e6db82cb6ba16e0ec49263c7b1e2010956c70352ba" },
        { "The quick brown fox jumps over the lazy dog",
          "8f99cf1475e7e59a428c56a54cb00c2a0c58d77a6ae2332674df09d96b89cb00" }
    };

    for (size_t i = 0; i < sizeof(v) / sizeof(v[0]); ++i) {
        mw_point_t got;
        mw_hash_to_point((const uint8_t*)v[i].in, strlen(v[i].in), &got);
        mw_point_t want = pt_from_hex(v[i].out);
        CHECK_EQ_MEM(got.b, want.b, 32);

        // Because of the mul8 the result is always torsion free.
        CHECK_EQ_INT(mw_point_in_main_subgroup(&got), 1);

        // mw_hash_to_ec must agree with mw_hash_to_point.
        mw_ge_p3 e;
        mw_point_t enc;
        mw_hash_to_ec((const uint8_t*)v[i].in, strlen(v[i].in), &e);
        mw_ge_p3_tobytes(&enc, &e);
        CHECK_EQ_MEM(enc.b, got.b, 32);
    }
}

MW_TEST(test_commitments) {
    // C = a*G + b*H
    for (int t = 0; t < 8; ++t) {
        mw_scalar_t mask   = rnd_scalar();
        mw_scalar_t amount = rnd_scalar();
        mw_point_t  c, ag, bh, want;

        mw_commit(&c, &mask, &amount);
        mw_point_scalarmult_base(&ag, &mask);
        mw_scalarmult_H(&bh, &amount);
        CHECK_EQ_INT(mw_point_add(&want, &ag, &bh), 0);
        CHECK_EQ_MEM(c.b, want.b, 32);

        // Commitments are additively homomorphic.
        mw_scalar_t mask2 = rnd_scalar();
        mw_scalar_t amt2  = rnd_scalar();
        mw_point_t  c2, sum, csum;
        mw_scalar_t ms, as;
        mw_commit(&c2, &mask2, &amt2);
        CHECK_EQ_INT(mw_point_add(&sum, &c, &c2), 0);
        mw_sc_add(&ms, &mask, &mask2);
        mw_sc_add(&as, &amount, &amt2);
        mw_commit(&csum, &ms, &as);
        CHECK_EQ_MEM(sum.b, csum.b, 32);
    }

    // commit(0, 0) is the identity.
    mw_point_t zero;
    mw_commit(&zero, &MW_SC_ZERO, &MW_SC_ZERO);
    CHECK_EQ_INT(mw_point_is_identity(&zero), 1);

    // scalarmult_H(1) == H
    mw_point_t h1;
    mw_scalarmult_H(&h1, &MW_SC_ONE);
    CHECK_EQ_MEM(h1.b, MW_POINT_H.b, 32);
}

MW_TEST(test_bp_get_exponent) {
    // Bulletproofs+ generator chain, cross-checked against Monero's
    // bulletproofs_plus.cc get_exponent(rct::H, idx).
    struct { uint32_t idx; const char* out; } v[] = {
        { 0,    "48628df380a5016d25451aaa501731a11b72bf66dc41d81f719abd35ce92b0ed" },
        { 1,    "38c5d4db53aeb86f5a80def9be4953f2288ed5a44c66af723f463d0170829010" },
        { 2,    "110d2b61f8c7c10861c3e4ffe7774faba632af94854aa29538517aefe6a39e48" },
        { 3,    "8a6c817dabe90fdb50cc38677b23ffa7d64efeb00bbd53febe62e077de0db593" },
        { 127,  "46e9e2d3586dfd893745c0957bfab3cc005a1a6c51ce25f065815603eab1160c" },
        { 1023, "473ade5847b041d8234657c136e687b5fe8e28fec13cb2e84c987bc4fc2cdf30" }
    };

    for (size_t i = 0; i < sizeof(v) / sizeof(v[0]); ++i) {
        mw_point_t got;
        mw_bp_get_exponent(&got, v[i].idx);
        mw_point_t want = pt_from_hex(v[i].out);
        CHECK_EQ_MEM(got.b, want.b, 32);
        // A generator must never be the point at infinity.
        CHECK_EQ_INT(mw_point_is_identity(&got), 0);
        CHECK_EQ_INT(mw_point_in_main_subgroup(&got), 1);
    }

    // Generators must be distinct.
    mw_point_t a, b;
    mw_bp_get_exponent(&a, 10);
    mw_bp_get_exponent(&b, 11);
    CHECK_EQ_INT(mw_point_eq(&a, &b), 0);
}

// ===========================================================================
// RNG layer
// ===========================================================================

MW_TEST(test_random_selftest_and_determinism) {
    static const uint8_t seed[] = "deterministic-test-entropy";

    CHECK_EQ_INT(mw_random_init(), MW_RNG_OK);
    CHECK_EQ_INT(mw_random_selftest(), MW_RNG_OK);

    uint8_t a[64], b[64];
    mw_random_set_test_source(seed, sizeof(seed) - 1);
    mw_random_bytes(a, sizeof(a));
    mw_random_set_test_source(seed, sizeof(seed) - 1);
    mw_random_bytes(b, sizeof(b));
    CHECK_EQ_MEM(a, b, sizeof(a));

    // Successive draws differ.
    mw_random_bytes(b, sizeof(b));
    CHECK_EQ_INT(memcmp(a, b, sizeof(a)) != 0, 1);

    // The deterministic source must still pass the health tests.
    CHECK_EQ_INT(mw_random_selftest(), MW_RNG_OK);

    // A different seed gives a different stream.
    static const uint8_t seed2[] = "deterministic-test-entropX";
    mw_random_set_test_source(seed2, sizeof(seed2) - 1);
    mw_random_bytes(b, sizeof(b));
    CHECK_EQ_INT(memcmp(a, b, sizeof(a)) != 0, 1);

    mw_random_set_test_source(NULL, 0);
}

MW_TEST(test_hedged_scalar) {
    static const uint8_t seed[] = "hedge-seed";
    static const uint8_t ctx1[] = "context-one";
    static const uint8_t ctx2[] = "context-two";

    mw_scalar_t k1, k2, k3;

    mw_random_set_test_source(seed, sizeof(seed) - 1);
    mw_random_hedged_scalar(&k1, ctx1, sizeof(ctx1) - 1);
    mw_random_set_test_source(seed, sizeof(seed) - 1);
    mw_random_hedged_scalar(&k2, ctx1, sizeof(ctx1) - 1);
    // Same entropy + same context -> reproducible nonce.
    CHECK_EQ_MEM(k1.b, k2.b, 32);
    CHECK_EQ_INT(mw_sc_check(&k1), 1);

    // Same entropy, different context -> different nonce.
    mw_random_set_test_source(seed, sizeof(seed) - 1);
    mw_random_hedged_scalar(&k3, ctx2, sizeof(ctx2) - 1);
    CHECK_EQ_INT(memcmp(k1.b, k3.b, 32) != 0, 1);

    // Different entropy, same context -> different nonce.
    static const uint8_t seed2[] = "hedge-seeD";
    mw_random_set_test_source(seed2, sizeof(seed2) - 1);
    mw_random_hedged_scalar(&k3, ctx1, sizeof(ctx1) - 1);
    CHECK_EQ_INT(memcmp(k1.b, k3.b, 32) != 0, 1);

    // A NULL context must be accepted.
    mw_random_set_test_source(seed, sizeof(seed) - 1);
    mw_random_hedged_scalar(&k3, NULL, 0);
    CHECK_EQ_INT(mw_sc_check(&k3), 1);

    mw_random_set_test_source(NULL, 0);
}

int main(void) {
    printf("== test_ed25519 ==\n");
    RUN_TEST(test_sc_constants);
    RUN_TEST(test_sc_reduce_known);
    RUN_TEST(test_sc_identities);
    RUN_TEST(test_hash_to_scalar);
    RUN_TEST(test_sc_random_is_canonical);
    RUN_TEST(test_base_point_multiples);
    RUN_TEST(test_point_encode_decode_roundtrip);
    RUN_TEST(test_point_add_sub_dbl_consistency);
    RUN_TEST(test_scalarmult_base_matches_scalarmult_G);
    RUN_TEST(test_scalarmult_homomorphism);
    RUN_TEST(test_ge_mul8);
    RUN_TEST(test_double_scalarmult_vartime);
    RUN_TEST(test_subgroup_rejects_low_order_points);
    RUN_TEST(test_invalid_encodings_rejected);
    RUN_TEST(test_point_eq);
    RUN_TEST(test_monero_H);
    RUN_TEST(test_hash_to_point_vectors);
    RUN_TEST(test_commitments);
    RUN_TEST(test_bp_get_exponent);
    RUN_TEST(test_random_selftest_and_determinism);
    RUN_TEST(test_hedged_scalar);
    return mw_test_summary();
}
