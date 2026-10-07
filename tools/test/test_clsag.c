// CLSAG signing / verification round trips.
//
// The setup mirrors what proveRctCLSAGSimple() is handed for one input:
// a ring of (one-time key, commitment) pairs, our secret at `real_idx`, a
// pseudo-out commitment C_offset with its own mask, and z = real_mask -
// pseudo_mask so that C_real - C_offset = z*G.
#include "test_framework.h"

#include "monero/clsag.h"
#include "monero/key_image.h"
#include "crypto/ed25519.h"
#include "crypto/random.h"

typedef struct {
    mw_ctkey_t    ring[MW_MAX_RING_SIZE];
    uint8_t       n;
    uint8_t       real_idx;
    mw_seckey_t   p;            // one-time secret of the real member
    mw_scalar_t   z;            // real_mask - pseudo_mask
    mw_point_t    C_offset;     // pseudo-out commitment
    mw_keyimage_t I;
    uint8_t       message[32];
} ring_ctx_t;

static void amount_scalar(uint64_t v, mw_scalar_t* s)
{
    mw_sc_0(s);
    for (int i = 0; i < 8; ++i) {
        s->b[i] = (uint8_t)((v >> (8 * i)) & 0xff);
    }
}

// Builds a ring where member `real_idx` is ours and everything balances.
static int make_ring(ring_ctx_t* c, uint8_t n, uint8_t real_idx, uint64_t amount)
{
    memset(c, 0, sizeof(*c));
    c->n = n;
    c->real_idx = real_idx;
    mw_random_bytes(c->message, sizeof(c->message));

    for (uint8_t i = 0; i < n; ++i) {
        mw_scalar_t s, m, a;
        mw_sc_random(&s);
        mw_sc_random(&m);
        amount_scalar(1000 + i, &a);
        mw_point_scalarmult_base(&c->ring[i].dest, &s);
        mw_commit(&c->ring[i].mask, &m, &a);
    }

    // Our member: we know both the one-time secret and the mask.
    mw_scalar_t real_mask, pseudo_mask, amt;
    mw_sc_random(&c->p);
    mw_sc_random(&real_mask);
    mw_sc_random(&pseudo_mask);
    amount_scalar(amount, &amt);
    mw_point_scalarmult_base(&c->ring[real_idx].dest, &c->p);
    mw_commit(&c->ring[real_idx].mask, &real_mask, &amt);
    mw_commit(&c->C_offset, &pseudo_mask, &amt);
    mw_sc_sub(&c->z, &real_mask, &pseudo_mask);

    return mw_generate_key_image(&c->ring[real_idx].dest, &c->p, &c->I) == MW_OK;
}

static int sign_and_verify(ring_ctx_t* c, mw_clsag_t* sig)
{
    mw_err_t err = mw_clsag_sign(c->message, c->ring, c->n, c->real_idx, &c->p,
                                 &c->z, &c->C_offset, &c->I, sig);
    if (err != MW_OK) {
        return 0;
    }
    return mw_clsag_verify(c->message, c->ring, c->n, &c->C_offset, &c->I, sig) ==
           MW_OK;
}

MW_TEST(test_sign_verify_every_index)
{
    // The real index must not change what the verifier sees.
    for (uint8_t n = 1; n <= 8; ++n) {
        for (uint8_t idx = 0; idx < n; ++idx) {
            ring_ctx_t c;
            CHECK(make_ring(&c, n, idx, 42));
            mw_clsag_t sig;
            CHECK(sign_and_verify(&c, &sig));
            CHECK_EQ_INT(sig.n, n);
        }
    }
}

MW_TEST(test_full_ring_size)
{
    ring_ctx_t c;
    CHECK(make_ring(&c, MW_RING_SIZE, 11, 1000000000000ULL));   // 1 XMR
    mw_clsag_t sig;
    CHECK(sign_and_verify(&c, &sig));

    ring_ctx_t big;
    CHECK(make_ring(&big, MW_MAX_RING_SIZE, MW_MAX_RING_SIZE - 1, 7));
    CHECK(sign_and_verify(&big, &sig));
}

MW_TEST(test_signature_shape)
{
    ring_ctx_t c;
    CHECK(make_ring(&c, MW_RING_SIZE, 3, 5));
    mw_clsag_t sig;
    CHECK(sign_and_verify(&c, &sig));

    // Every scalar must be canonical and c1 non-zero.
    CHECK(mw_sc_check(&sig.c1));
    CHECK(!mw_sc_is_zero(&sig.c1));
    for (uint8_t i = 0; i < sig.n; ++i) {
        CHECK(mw_sc_check(&sig.s[i]));
    }
    // D is the /8 form and must still be a valid main-subgroup point.
    CHECK(mw_point_check_public(&sig.D));
    CHECK_EQ_MEM(sig.I.b, c.I.b, 32);

    // Signing twice must not produce the same signature (fresh nonce).
    mw_clsag_t sig2;
    CHECK(sign_and_verify(&c, &sig2));
    CHECK(memcmp(sig.c1.b, sig2.c1.b, 32) != 0);
}

MW_TEST(test_tampering_is_rejected)
{
    ring_ctx_t c;
    CHECK(make_ring(&c, MW_RING_SIZE, 5, 123456));
    mw_clsag_t good;
    CHECK(sign_and_verify(&c, &good));

    mw_clsag_t sig = good;
    sig.c1.b[0] ^= 1;
    CHECK(mw_clsag_verify(c.message, c.ring, c.n, &c.C_offset, &c.I, &sig) != MW_OK);

    sig = good;
    sig.s[7].b[5] ^= 0x20;
    CHECK(mw_clsag_verify(c.message, c.ring, c.n, &c.C_offset, &c.I, &sig) != MW_OK);

    sig = good;
    sig.D.b[1] ^= 1;
    CHECK(mw_clsag_verify(c.message, c.ring, c.n, &c.C_offset, &c.I, &sig) != MW_OK);

    // A different message must not verify (this is what binds the signature
    // to the transaction).
    uint8_t other[32];
    memcpy(other, c.message, 32);
    other[31] ^= 1;
    CHECK(mw_clsag_verify(other, c.ring, c.n, &c.C_offset, &c.I, &good) != MW_OK);

    // A swapped ring member, a different pseudo-out and a foreign key image
    // must all fail.
    mw_ctkey_t ring2[MW_MAX_RING_SIZE];
    memcpy(ring2, c.ring, sizeof(ring2));
    ring2[0].dest.b[0] ^= 1;
    CHECK(mw_clsag_verify(c.message, ring2, c.n, &c.C_offset, &c.I, &good) != MW_OK);

    mw_point_t other_offset = c.C_offset;
    other_offset.b[0] ^= 1;
    CHECK(mw_clsag_verify(c.message, c.ring, c.n, &other_offset, &c.I, &good) !=
          MW_OK);

    mw_keyimage_t other_image = c.I;
    other_image.b[3] ^= 1;
    CHECK(mw_clsag_verify(c.message, c.ring, c.n, &c.C_offset, &other_image,
                          &good) != MW_OK);

    // Claiming a different ring size than the one that was signed.
    sig = good;
    sig.n = (uint8_t)(c.n - 1);
    CHECK(mw_clsag_verify(c.message, c.ring, c.n, &c.C_offset, &c.I, &sig) != MW_OK);
}

MW_TEST(test_unbalanced_z_is_rejected)
{
    // z must really be real_mask - pseudo_mask; a wrong z cannot produce a
    // signature that verifies (mw_clsag_sign self-verifies, so it fails).
    ring_ctx_t c;
    CHECK(make_ring(&c, MW_RING_SIZE, 2, 99));
    mw_sc_random(&c.z);
    mw_clsag_t sig;
    CHECK(mw_clsag_sign(c.message, c.ring, c.n, c.real_idx, &c.p, &c.z,
                        &c.C_offset, &c.I, &sig) != MW_OK);
}

MW_TEST(test_wrong_key_image_is_rejected)
{
    // The image must be x*Hp(P) for the real member.
    ring_ctx_t c;
    CHECK(make_ring(&c, 8, 1, 7));
    mw_scalar_t other;
    mw_sc_random(&other);
    mw_point_t other_pub;
    mw_point_scalarmult_base(&other_pub, &other);
    mw_keyimage_t bad;
    CHECK_EQ_INT(mw_generate_key_image(&other_pub, &other, &bad), MW_OK);

    mw_clsag_t sig;
    CHECK(mw_clsag_sign(c.message, c.ring, c.n, c.real_idx, &c.p, &c.z,
                        &c.C_offset, &bad, &sig) != MW_OK);
}

MW_TEST(test_bad_arguments)
{
    ring_ctx_t c;
    CHECK(make_ring(&c, 4, 0, 1));
    mw_clsag_t sig;
    CHECK_EQ_INT(mw_clsag_sign(c.message, c.ring, 0, 0, &c.p, &c.z, &c.C_offset,
                               &c.I, &sig), MW_ERR_TOO_MANY);
    CHECK_EQ_INT(mw_clsag_sign(c.message, c.ring, MW_MAX_RING_SIZE + 1, 0, &c.p,
                               &c.z, &c.C_offset, &c.I, &sig), MW_ERR_TOO_MANY);
    CHECK_EQ_INT(mw_clsag_sign(c.message, c.ring, 4, 4, &c.p, &c.z, &c.C_offset,
                               &c.I, &sig), MW_ERR_INVALID_ARG);
    CHECK_EQ_INT(mw_clsag_sign(NULL, c.ring, 4, 0, &c.p, &c.z, &c.C_offset, &c.I,
                               &sig), MW_ERR_INVALID_ARG);

    // A ring member that is not a valid curve point must be rejected, not
    // crash the verifier.
    mw_ctkey_t ring2[MW_MAX_RING_SIZE];
    memcpy(ring2, c.ring, sizeof(ring2));
    memset(ring2[2].dest.b, 0xff, 32);
    CHECK(mw_clsag_sign(c.message, ring2, 4, 0, &c.p, &c.z, &c.C_offset, &c.I,
                        &sig) != MW_OK);
}

// ------------------------------------------------------------------ reference
// Independent verifier with the flat hash buffers rctSigs.cpp uses. It pins
// the transcript layout of the incremental hashing in clsag.c byte for byte.
static void ref_add(mw_ge_p3* r, const mw_ge_p3* a, const mw_ge_p3* b, int sub)
{
    mw_ge_cached cb;
    mw_ge_p3_to_cached(&cb, b);
    mw_ge_p1p1 t;
    if (sub) {
        mw_ge_sub(&t, a, &cb);
    } else {
        mw_ge_add(&t, a, &cb);
    }
    mw_ge_p1p1_to_p3(r, &t);
}

static size_t ref_prefix(uint8_t* buf, const char* dom, const mw_ctkey_t* ring, uint8_t n)
{
    memset(buf, 0, 32);
    memcpy(buf, dom, strlen(dom));
    size_t off = 32;
    for (uint8_t i = 0; i < n; ++i, off += 32) memcpy(buf + off, ring[i].dest.b, 32);
    for (uint8_t i = 0; i < n; ++i, off += 32) memcpy(buf + off, ring[i].mask.b, 32);
    return off;
}

static int ref_verify(const ring_ctx_t* c, const mw_clsag_t* sig)
{
    static uint8_t buf[(2 * MW_MAX_RING_SIZE + 5) * 32];
    const uint8_t n = c->n;
    mw_scalar_t mu_P, mu_C;
    size_t off = ref_prefix(buf, "CLSAG_agg_0", c->ring, n);
    memcpy(buf + off, c->I.b, 32);
    memcpy(buf + off + 32, sig->D.b, 32);
    memcpy(buf + off + 64, c->C_offset.b, 32);
    mw_hash_to_scalar(buf, off + 96, &mu_P);
    memset(buf, 0, 32);
    memcpy(buf, "CLSAG_agg_1", 11);
    mw_hash_to_scalar(buf, off + 96, &mu_C);

    mw_ge_p3 I3, D3, O3;
    if (mw_ge_frombytes_vartime(&I3, &c->I) != 0 ||
        mw_ge_frombytes_vartime(&O3, &c->C_offset) != 0) {
        return 0;
    }
    mw_scalar_t eight;
    mw_sc_0(&eight);
    eight.b[0] = 8;
    mw_point_t D;
    if (mw_point_scalarmult(&D, &eight, &sig->D) != 0 ||
        mw_ge_frombytes_vartime(&D3, &D) != 0) {
        return 0;
    }

    off = ref_prefix(buf, "CLSAG_round", c->ring, n);
    memcpy(buf + off, c->C_offset.b, 32);
    memcpy(buf + off + 32, c->message, 32);
    mw_scalar_t ch = sig->c1;
    for (uint8_t i = 0; i < n; ++i) {
        mw_scalar_t cp, cc;
        mw_sc_mul(&cp, &mu_P, &ch);
        mw_sc_mul(&cc, &mu_C, &ch);
        mw_ge_p3 P, M, C, t1, t2, t3, acc, H;
        if (mw_ge_frombytes_vartime(&P, &c->ring[i].dest) != 0 ||
            mw_ge_frombytes_vartime(&M, &c->ring[i].mask) != 0) {
            return 0;
        }
        ref_add(&C, &M, &O3, 1);
        mw_ge_scalarmult_base(&t1, &sig->s[i]);
        mw_ge_scalarmult(&t2, &cp, &P);
        mw_ge_scalarmult(&t3, &cc, &C);
        ref_add(&acc, &t1, &t2, 0);
        ref_add(&acc, &acc, &t3, 0);
        mw_point_t L, R;
        mw_ge_p3_tobytes(&L, &acc);
        mw_hash_to_ec(c->ring[i].dest.b, 32, &H);
        mw_ge_scalarmult(&t1, &sig->s[i], &H);
        mw_ge_scalarmult(&t2, &cp, &I3);
        mw_ge_scalarmult(&t3, &cc, &D3);
        ref_add(&acc, &t1, &t2, 0);
        ref_add(&acc, &acc, &t3, 0);
        mw_ge_p3_tobytes(&R, &acc);
        memcpy(buf + off + 64, L.b, 32);
        memcpy(buf + off + 96, R.b, 32);
        mw_hash_to_scalar(buf, off + 128, &ch);
    }
    return memcmp(ch.b, sig->c1.b, 32) == 0;
}

MW_TEST(test_matches_flat_transcript)
{
    static const uint8_t sizes[] = { 1, 2, 11, 16, MW_MAX_RING_SIZE };
    for (size_t k = 0; k < sizeof(sizes); ++k) {
        ring_ctx_t c;
        uint8_t n = sizes[k];
        CHECK(make_ring(&c, n, (uint8_t)(n / 2), 77));
        mw_clsag_t sig;
        CHECK(sign_and_verify(&c, &sig));
        CHECK(ref_verify(&c, &sig));
        sig.s[0].b[0] ^= 1;
        CHECK(!ref_verify(&c, &sig));
    }
}

MW_TEST(test_ring_32)
{
    static const uint8_t idx[] = { 0, 1, 15, 16, MW_MAX_RING_SIZE - 1 };
    for (size_t k = 0; k < sizeof(idx); ++k) {
        ring_ctx_t c;
        CHECK(make_ring(&c, MW_MAX_RING_SIZE, idx[k], 5000));
        mw_clsag_t sig;
        CHECK(sign_and_verify(&c, &sig));
        CHECK_EQ_INT(sig.n, MW_MAX_RING_SIZE);
    }
}

// Fills p with 32 bytes that mw_ge_frombytes_vartime refuses.
static void not_a_point(mw_point_t* p)
{
    mw_ge_p3 t;
    do {
        mw_random_bytes(p->b, 32);
        p->b[31] &= 0x7f;
    } while (mw_ge_frombytes_vartime(&t, p) == 0);
}

MW_TEST(test_undecodable_member_is_format_error)
{
    ring_ctx_t c;
    CHECK(make_ring(&c, MW_RING_SIZE, 4, 9));
    for (int which = 0; which < 2; ++which) {
        for (uint8_t pos = 0; pos < c.n; pos = (uint8_t)(pos + 5)) {
            ring_ctx_t bad = c;
            if (pos == c.real_idx) {
                continue;
            }
            not_a_point(which == 0 ? &bad.ring[pos].dest : &bad.ring[pos].mask);
            mw_clsag_t sig;
            memset(&sig, 0x5a, sizeof(sig));
            CHECK_EQ_INT(mw_clsag_sign(bad.message, bad.ring, bad.n, bad.real_idx,
                                       &bad.p, &bad.z, &bad.C_offset, &bad.I, &sig),
                         MW_ERR_FORMAT);
            static const mw_clsag_t zero;
            CHECK(memcmp(&sig, &zero, sizeof(sig)) == 0);
        }
    }
}

int main(void)
{
    mw_random_init();

    RUN_TEST(test_sign_verify_every_index);
    RUN_TEST(test_full_ring_size);
    RUN_TEST(test_signature_shape);
    RUN_TEST(test_tampering_is_rejected);
    RUN_TEST(test_unbalanced_z_is_rejected);
    RUN_TEST(test_wrong_key_image_is_rejected);
    RUN_TEST(test_bad_arguments);
    RUN_TEST(test_matches_flat_transcript);
    RUN_TEST(test_ring_32);
    RUN_TEST(test_undecodable_member_is_format_error);

    return mw_test_summary();
}
