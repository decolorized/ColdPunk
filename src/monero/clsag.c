// CLSAG ring signatures, byte-for-byte compatible with monero-project/monero
// rct::CLSAG_Gen() / rct::CLSAG_Ver() as called from proveRctCLSAGSimple() and
// verRctCLSAGSimple() (src/ringct/rctSigs.cpp, Monero 0.18.x).
//
// Domain separators (src/cryptonote_config.h):
//     HASH_KEY_CLSAG_AGG_0  = "CLSAG_agg_0"   -> mu_P
//     HASH_KEY_CLSAG_AGG_1  = "CLSAG_agg_1"   -> mu_C
//     HASH_KEY_CLSAG_ROUND  = "CLSAG_round"   -> the challenge chain
// Each one is written into a 32-byte slot that was first zeroed, i.e. the
// 11 ASCII bytes followed by 21 zero bytes.
//
//     mu_P = Hs("CLSAG_agg_0" || P_0..P_{n-1} || C_0..C_{n-1} || I || D_8 || C_offset)
//     mu_C = Hs("CLSAG_agg_1" || same tail)
//     c_{i+1} = Hs("CLSAG_round" || P_0..P_{n-1} || C_0..C_{n-1} || C_offset
//                                || message || L_i || R_i)
//
// C_j above is the *non-offset* commitment of ring member j (pubs[j].mask);
// the offset commitment C_j - C_offset only appears inside L_i.
//
// D is the auxiliary key image z*Hp(P_l). What gets serialized is D_8 = D/8
// (rct::INV_EIGHT), and the verifier multiplies it by 8 again; the aggregation
// hashes use the serialized D_8, while L/R use the full D.
//
// Constant time with respect to the secret index: the challenge loop always
// runs exactly n-1 iterations, never branches on real_idx, and captures c1
// through a constant-time conditional move. The order in which public ring
// members are visited depends on real_idx, which is inherent to the
// algorithm; each round decompresses and hashes its member with variable-time
// code (mw_ge_frombytes_vartime, mw_hash_to_ec) on public ring data only.
//
// Stack: the signer keeps no per-member point tables and hashes incrementally,
// and the self-verification runs after the signing frame has returned, so the
// whole call stays well inside the crypto task's stack (see test_stack.c).
#include "clsag.h"

#include <string.h>

#include "../crypto/hash.h"
#include "../crypto/memzero.h"
#include "../crypto/random.h"

#define CLSAG_DOMAIN_AGG_0 "CLSAG_agg_0"
#define CLSAG_DOMAIN_AGG_1 "CLSAG_agg_1"
#define CLSAG_DOMAIN_ROUND "CLSAG_round"

#if defined(__GNUC__) || defined(__clang__)
#define MW_NOINLINE __attribute__((noinline))
#else
#define MW_NOINLINE
#endif

// ------------------------------------------------------------------ helpers
static void p3_add(mw_ge_p3* r, const mw_ge_p3* a, const mw_ge_p3* b)
{
    mw_ge_cached cached;
    mw_ge_p3_to_cached(&cached, b);
    mw_ge_p1p1 t;
    mw_ge_add(&t, a, &cached);
    mw_ge_p1p1_to_p3(r, &t);
}

static void p3_sub(mw_ge_p3* r, const mw_ge_p3* a, const mw_ge_p3* b)
{
    mw_ge_cached cached;
    mw_ge_p3_to_cached(&cached, b);
    mw_ge_p1p1 t;
    mw_ge_sub(&t, a, &cached);
    mw_ge_p1p1_to_p3(r, &t);
}

// Writes an 11-character domain separator into a zeroed 32-byte slot.
static void domain_slot(uint8_t out[32], const char* domain)
{
    memset(out, 0, 32);
    memcpy(out, domain, strlen(domain));
}

// dst = src when mask == 0xff, unchanged when mask == 0x00.
static void ct_copy32(uint8_t* dst, const uint8_t* src, uint8_t mask)
{
    for (int i = 0; i < 32; ++i) {
        dst[i] = (uint8_t)((dst[i] & (uint8_t)~mask) | (src[i] & mask));
    }
}

// 0xff when v == 0, 0x00 otherwise, without branching on v.
static uint8_t ct_is_zero_u32(uint32_t v)
{
    uint32_t nz = (v | (uint32_t)(-(int32_t)v)) >> 31;   // 1 when v != 0
    return (uint8_t)(nz - 1u);
}

// 1/8 mod l, computed once so a typo in a hard-coded constant cannot hide.
static void inv_eight(mw_scalar_t* out)
{
    mw_scalar_t eight;
    mw_sc_0(&eight);
    eight.b[0] = 8;
    mw_sc_invert(out, &eight);
}

// Starts a hash over [domain][P_0..P_{n-1}][C_0..C_{n-1}]; the caller
// absorbs the tail.
static void absorb_ring(mw_keccak_ctx* k, const char* domain, const mw_ctkey_t* ring,
                        uint8_t n)
{
    uint8_t slot[32];
    domain_slot(slot, domain);
    mw_keccak_init(k);
    mw_keccak_update(k, slot, 32);
    for (uint8_t i = 0; i < n; ++i) {
        mw_keccak_update(k, ring[i].dest.b, 32);
    }
    for (uint8_t i = 0; i < n; ++i) {
        mw_keccak_update(k, ring[i].mask.b, 32);
    }
}

// Both aggregation coefficients share everything but the domain separator.
static void aggregation_coeffs(const mw_ctkey_t* ring, uint8_t n,
                               const mw_keyimage_t* I, const mw_point_t* D_8,
                               const mw_point_t* C_offset,
                               mw_scalar_t* mu_P, mw_scalar_t* mu_C)
{
    mw_keccak_ctx k;
    for (int pass = 0; pass < 2; ++pass) {
        absorb_ring(&k, pass == 0 ? CLSAG_DOMAIN_AGG_0 : CLSAG_DOMAIN_AGG_1, ring, n);
        mw_keccak_update(&k, I->b, 32);
        mw_keccak_update(&k, D_8->b, 32);
        mw_keccak_update(&k, C_offset->b, 32);
        mw_scalar_t* out = pass == 0 ? mu_P : mu_C;
        mw_keccak_final(&k, out->b);
        mw_sc_reduce32(out);
    }
    mw_memzero(&k, sizeof(k));
}

// Round hash prefix: [domain][P..][C..][C_offset][message].
static void round_prefix(mw_keccak_ctx* k, const mw_ctkey_t* ring, uint8_t n,
                         const mw_point_t* C_offset, const uint8_t message[32])
{
    absorb_ring(k, CLSAG_DOMAIN_ROUND, ring, n);
    mw_keccak_update(k, C_offset->b, 32);
    mw_keccak_update(k, message, 32);
}

// c = Hs(prefix || L || R); the prefix context is left untouched.
static void round_hash(const mw_keccak_ctx* prefix, const mw_point_t* L,
                       const mw_point_t* R, mw_scalar_t* c)
{
    mw_keccak_ctx k = *prefix;
    mw_keccak_update(&k, L->b, 32);
    mw_keccak_update(&k, R->b, 32);
    mw_keccak_final(&k, c->b);
    mw_sc_reduce32(c);
    mw_memzero(&k, sizeof(k));
}

// ------------------------------------------------------------------ signing
// Everything up to s_l. Kept out of line so that the self-verification in
// mw_clsag_sign() does not nest under this frame.
static MW_NOINLINE mw_err_t clsag_sign_core(const uint8_t message[32],
                                            const mw_ctkey_t* ring, uint8_t n,
                                            uint8_t real_idx, const mw_seckey_t* p,
                                            const mw_scalar_t* z,
                                            const mw_point_t* C_offset,
                                            const mw_keyimage_t* I, mw_clsag_t* sig_out)
{
    memset(sig_out, 0, sizeof(*sig_out));
    sig_out->n = n;
    sig_out->I = *I;

    // Reject a ring that does not decompress before any secret is touched.
    // The rounds decompress each (public) member again when they need it.
    mw_ge_p3 offset_p3;
    if (mw_ge_frombytes_vartime(&offset_p3, C_offset) != 0) {
        return MW_ERR_FORMAT;
    }
    for (uint8_t i = 0; i < n; ++i) {
        mw_ge_p3 t;
        if (mw_ge_frombytes_vartime(&t, &ring[i].dest) != 0 ||
            mw_ge_frombytes_vartime(&t, &ring[i].mask) != 0) {
            return MW_ERR_FORMAT;
        }
    }

    mw_ge_p3 I_p3;
    if (mw_ge_frombytes_vartime(&I_p3, I) != 0) {
        return MW_ERR_FORMAT;
    }

    // H = Hp(P_l), D = z*H, and the serialized D_8 = D/8.
    mw_ge_p3 H_real;
    mw_hash_to_ec(ring[real_idx].dest.b, 32, &H_real);
    mw_ge_p3 D_p3;
    mw_ge_scalarmult(&D_p3, z, &H_real);
    mw_scalar_t inv8;
    inv_eight(&inv8);
    mw_ge_p3 D8_p3;
    mw_ge_scalarmult(&D8_p3, &inv8, &D_p3);
    mw_ge_p3_tobytes(&sig_out->D, &D8_p3);

    mw_scalar_t mu_P, mu_C;
    aggregation_coeffs(ring, n, I, &sig_out->D, C_offset, &mu_P, &mu_C);

    // Hedged nonce a (TZ 8.2). The deterministic context binds the message,
    // the secret key and the key image so a repeated nonce is impossible
    // unless both entropy sources fail at once.
    uint8_t ctx[32 * 4];
    memcpy(ctx, message, 32);
    memcpy(ctx + 32, p->b, 32);
    memcpy(ctx + 64, z->b, 32);
    memcpy(ctx + 96, I->b, 32);
    mw_scalar_t a;
    mw_random_hedged_scalar(&a, ctx, sizeof(ctx));
    mw_memzero(ctx, sizeof(ctx));

    // Fill the whole s vector with randomness first: the entry for the real
    // index is overwritten at the end, but the RNG is driven identically no
    // matter which index that is.
    for (uint8_t i = 0; i < n; ++i) {
        mw_sc_random(&sig_out->s[i]);
    }

    mw_keccak_ctx prefix;
    round_prefix(&prefix, ring, n, C_offset, message);

    mw_point_t L, R;
    // Initial commitment: L = a*G, R = a*Hp(P_l).
    {
        mw_ge_p3 aG, aH;
        mw_ge_scalarmult_base(&aG, &a);
        mw_ge_scalarmult(&aH, &a, &H_real);
        mw_ge_p3_tobytes(&L, &aG);
        mw_ge_p3_tobytes(&R, &aH);
        mw_memzero(&aG, sizeof(aG));
        mw_memzero(&aH, sizeof(aH));
    }

    mw_scalar_t c;
    round_hash(&prefix, &L, &R, &c);

    uint32_t i = (uint32_t)(real_idx + 1u) % n;
    ct_copy32(sig_out->c1.b, c.b, ct_is_zero_u32(i));

    for (uint8_t step = 0; step + 1u < n; ++step) {
        mw_scalar_t c_p, c_c;
        mw_sc_mul(&c_p, &mu_P, &c);
        mw_sc_mul(&c_c, &mu_C, &c);

        mw_ge_p3 Pi, Ci, mask_p3;
        (void)mw_ge_frombytes_vartime(&Pi, &ring[i].dest);      // checked above
        (void)mw_ge_frombytes_vartime(&mask_p3, &ring[i].mask);
        p3_sub(&Ci, &mask_p3, &offset_p3);

        // L = s_i*G + c_p*P_i + c_c*(C_i - C_offset)
        mw_ge_p3 t1, t2, t3, acc;
        mw_ge_scalarmult_base(&t1, &sig_out->s[i]);
        mw_ge_scalarmult(&t2, &c_p, &Pi);
        mw_ge_scalarmult(&t3, &c_c, &Ci);
        p3_add(&acc, &t1, &t2);
        p3_add(&acc, &acc, &t3);
        mw_ge_p3_tobytes(&L, &acc);

        // R = s_i*Hp(P_i) + c_p*I + c_c*D
        mw_ge_p3 Hi;
        mw_hash_to_ec(ring[i].dest.b, 32, &Hi);
        mw_ge_scalarmult(&t1, &sig_out->s[i], &Hi);
        mw_ge_scalarmult(&t2, &c_p, &I_p3);
        mw_ge_scalarmult(&t3, &c_c, &D_p3);
        p3_add(&acc, &t1, &t2);
        p3_add(&acc, &acc, &t3);
        mw_ge_p3_tobytes(&R, &acc);

        round_hash(&prefix, &L, &R, &c);

        i = (i + 1u) % n;
        ct_copy32(sig_out->c1.b, c.b, ct_is_zero_u32(i));
    }

    // s_l = a - c*(mu_P*p + mu_C*z)
    {
        mw_scalar_t t, u;
        mw_sc_mul(&t, &mu_P, p);
        mw_sc_muladd(&u, &mu_C, z, &t);
        mw_sc_mulsub(&sig_out->s[real_idx], &c, &u, &a);
        mw_memzero(&t, sizeof(t));
        mw_memzero(&u, sizeof(u));
    }

    mw_memzero(&a, sizeof(a));
    mw_memzero(&c, sizeof(c));
    mw_memzero(&mu_P, sizeof(mu_P));
    mw_memzero(&mu_C, sizeof(mu_C));
    mw_memzero(&D_p3, sizeof(D_p3));
    mw_memzero(&D8_p3, sizeof(D8_p3));
    mw_memzero(&H_real, sizeof(H_real));
    mw_memzero(&L, sizeof(L));
    mw_memzero(&R, sizeof(R));
    mw_memzero(&prefix, sizeof(prefix));
    return MW_OK;
}

mw_err_t mw_clsag_sign(const uint8_t message[32], const mw_ctkey_t* ring, uint8_t n,
                       uint8_t real_idx, const mw_seckey_t* p, const mw_scalar_t* z,
                       const mw_point_t* C_offset, const mw_keyimage_t* I,
                       mw_clsag_t* sig_out)
{
    if (message == NULL || ring == NULL || p == NULL || z == NULL ||
        C_offset == NULL || I == NULL || sig_out == NULL) {
        return MW_ERR_INVALID_ARG;
    }
    if (n == 0 || n > MW_MAX_RING_SIZE) {
        return MW_ERR_TOO_MANY;
    }
    if (real_idx >= n) {
        return MW_ERR_INVALID_ARG;
    }
    if (!mw_sc_check(p) || !mw_sc_check(z) || mw_sc_is_zero(p)) {
        return MW_ERR_INVALID_ARG;
    }

    mw_err_t err = clsag_sign_core(message, ring, n, real_idx, p, z, C_offset, I, sig_out);
    // Fault-injection defence: never hand out a signature we did not verify.
    if (err == MW_OK) {
        err = mw_clsag_verify(message, ring, n, C_offset, I, sig_out);
    }
    if (err != MW_OK) {
        mw_memzero(sig_out, sizeof(*sig_out));
    }
    return err;
}

// ------------------------------------------------------------- verification
mw_err_t mw_clsag_verify(const uint8_t message[32], const mw_ctkey_t* ring, uint8_t n,
                         const mw_point_t* C_offset, const mw_keyimage_t* I,
                         const mw_clsag_t* sig)
{
    if (message == NULL || ring == NULL || C_offset == NULL || I == NULL ||
        sig == NULL) {
        return MW_ERR_INVALID_ARG;
    }
    if (n == 0 || n > MW_MAX_RING_SIZE || sig->n != n) {
        return MW_ERR_INVALID_ARG;
    }
    for (uint8_t i = 0; i < n; ++i) {
        if (!mw_sc_check(&sig->s[i])) {
            return MW_ERR_SIGNATURE;
        }
    }
    if (!mw_sc_check(&sig->c1) || mw_sc_is_zero(&sig->c1)) {
        return MW_ERR_SIGNATURE;
    }
    // TZ 8.3: every point that reaches the verifier is validated.
    if (!mw_point_check_public(I) || !mw_point_check_public(&sig->D) ||
        !mw_point_check_public(C_offset)) {
        return MW_ERR_SUBGROUP;
    }
    for (uint8_t i = 0; i < n; ++i) {
        if (!mw_point_check_public(&ring[i].dest) ||
            !mw_point_check_public(&ring[i].mask)) {
            return MW_ERR_SUBGROUP;
        }
    }

    mw_ge_p3 I_p3, D8_p3, offset_p3;
    if (mw_ge_frombytes_vartime(&I_p3, I) != 0 ||
        mw_ge_frombytes_vartime(&D8_p3, &sig->D) != 0 ||
        mw_ge_frombytes_vartime(&offset_p3, C_offset) != 0) {
        return MW_ERR_FORMAT;
    }

    // D = 8 * D_8
    mw_ge_p3 D_p3;
    {
        mw_ge_p2 p2;
        memcpy(p2.X, D8_p3.X, sizeof(mw_fe));
        memcpy(p2.Y, D8_p3.Y, sizeof(mw_fe));
        memcpy(p2.Z, D8_p3.Z, sizeof(mw_fe));
        mw_ge_p1p1 t;
        mw_ge_mul8(&t, &p2);
        mw_ge_p1p1_to_p3(&D_p3, &t);
    }

    mw_scalar_t mu_P, mu_C;
    aggregation_coeffs(ring, n, I, &sig->D, C_offset, &mu_P, &mu_C);

    mw_keccak_ctx prefix;
    round_prefix(&prefix, ring, n, C_offset, message);
    mw_point_t L, R;

    mw_scalar_t c = sig->c1;
    for (uint8_t i = 0; i < n; ++i) {
        mw_scalar_t c_p, c_c;
        mw_sc_mul(&c_p, &mu_P, &c);
        mw_sc_mul(&c_c, &mu_C, &c);

        mw_ge_p3 P_p3, mask_p3, C_p3;
        if (mw_ge_frombytes_vartime(&P_p3, &ring[i].dest) != 0 ||
            mw_ge_frombytes_vartime(&mask_p3, &ring[i].mask) != 0) {
            return MW_ERR_FORMAT;
        }
        p3_sub(&C_p3, &mask_p3, &offset_p3);

        mw_ge_p3 t1, t2, t3, acc;
        mw_ge_scalarmult_base(&t1, &sig->s[i]);
        mw_ge_scalarmult(&t2, &c_p, &P_p3);
        mw_ge_scalarmult(&t3, &c_c, &C_p3);
        p3_add(&acc, &t1, &t2);
        p3_add(&acc, &acc, &t3);
        mw_ge_p3_tobytes(&L, &acc);

        mw_ge_p3 Hi;
        mw_hash_to_ec(ring[i].dest.b, 32, &Hi);
        mw_ge_scalarmult(&t1, &sig->s[i], &Hi);
        mw_ge_scalarmult(&t2, &c_p, &I_p3);
        mw_ge_scalarmult(&t3, &c_c, &D_p3);
        p3_add(&acc, &t1, &t2);
        p3_add(&acc, &acc, &t3);
        mw_ge_p3_tobytes(&R, &acc);

        round_hash(&prefix, &L, &R, &c);
    }

    mw_scalar_t diff;
    mw_sc_sub(&diff, &c, &sig->c1);
    return mw_sc_is_zero(&diff) ? MW_OK : MW_ERR_SIGNATURE;
}
