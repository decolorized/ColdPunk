// Bulletproofs+ aggregate range proofs (RCT type 6), following
// monero-project/monero src/ringct/bulletproofs_plus.cc (0.18.x).
//
// ---------------------------------------------------------------- overview
// For M padded outputs of N = 64 bits each (MN = M*N):
//
//   V_i   = (1/8) * (gamma_i*G + v_i*H)                         (commitments)
//   aL    = the bit decomposition of every v_i, aR = aL - 1
//   A     = (1/8) * (<aL,Gi> + <aR,Hi> + alpha*G)
//   y     = Hs(transcript || A),  z = Hs(y)
//   a'    = aL - z,  b' = aR + z + d .* y^{MN-i}
//   d_{j*N+k} = z^{2(j+1)} * 2^k
//
// followed by log2(MN) rounds of the weighted inner product argument, each
// emitting L_r, R_r (both stored divided by 8), and a final (A1, B, r1, s1, d1)
// tuple. The verifier re-derives every challenge from the Fiat-Shamir
// transcript and checks a single multi-exponentiation against the identity;
// the equation implemented in bpp_verify_inner() below is derived from the
// prover step by step, and both directions are exercised by test_bpp.c.
//
// ------------------------------------------------------- domain separators
//   generators: hash_to_point(H || "bulletproof_plus" || varint(idx))
//               Gi[i] = exponent(2i+1), Hi[i] = exponent(2i)
//   transcript seed: hash_to_p3(cn_fast_hash("bulletproof_plus_transcript"))
//                    (a point encoding, not Hs(...))
//
// The generator chain comes from the crypto layer's mw_bp_get_exponent(), which
// reproduces Monero's
//     hash_to_p3( cn_fast_hash( H || "bulletproof_plus" || varint(idx) ) )
// - note the *two* Keccak passes: the explicit cn_fast_hash turns the variable
// length string into a 32-byte key, and rct::hash_to_p3() hashes that key again
// before ge_fromfe_frombytes_vartime + mul8 (the same hash_to_p3 that produces
// Hp(P) for key images, which is why it must hash its input). The salt is
// config::HASH_KEY_BULLETPROOF_PLUS_EXPONENT, *not* the plain-Bulletproofs
// "bulletproof" the ed25519.h comment mentions - the implementation is right
// and that header comment is stale.
//
// MW_BPP_USE_CRYPTO_GET_EXPONENT=0 switches to the local single-hash variant;
// it is kept only to make the difference explicit and produces generators that
// Monero does NOT accept.
//
// --------------------------------------------------------------- memory
// The working set is 2*MN scalars plus 2*MN expanded points; for the maximum
// of 16 outputs that is ~390 KiB, which on the ESP32-S3 must come from PSRAM.
// Everything is allocated per proof through bpp_alloc() and freed (and wiped)
// before returning, so nothing large stays resident between signatures.
#include "bulletproof_plus.h"

#include <stdlib.h>
#include <string.h>

#include "serialize.h"
#include "../crypto/hash.h"
#include "../crypto/memzero.h"
#include "../crypto/random.h"

#ifndef MW_BPP_USE_CRYPTO_GET_EXPONENT
#define MW_BPP_USE_CRYPTO_GET_EXPONENT 1
#endif

#define BPP_N       MW_BPP_N            // 64 bits per range
#define BPP_LOG_N   6

static const char BPP_TRANSCRIPT[] = "bulletproof_plus_transcript";

// ------------------------------------------------------------- scalar util
static void sc_pow_u64(mw_scalar_t* out, const mw_scalar_t* base, uint64_t e)
{
    mw_scalar_t r, b;
    mw_sc_1(&r);
    b = *base;
    while (e != 0) {
        if ((e & 1u) != 0) {
            mw_sc_mul(&r, &r, &b);
        }
        mw_sc_mul(&b, &b, &b);
        e >>= 1;
    }
    *out = r;
}

static void sc_from_u64(mw_scalar_t* out, uint64_t v)
{
    mw_sc_0(out);
    for (int i = 0; i < 8; ++i) {
        out->b[i] = (uint8_t)((v >> (8 * i)) & 0xff);
    }
}

static void sc_inv8(mw_scalar_t* out)
{
    mw_scalar_t eight;
    mw_sc_0(&eight);
    eight.b[0] = 8;
    mw_sc_invert(out, &eight);
}

// ------------------------------------------------------------- point util
static void p3_add(mw_ge_p3* r, const mw_ge_p3* a, const mw_ge_p3* b)
{
    mw_ge_cached cached;
    mw_ge_p3_to_cached(&cached, b);
    mw_ge_p1p1 t;
    mw_ge_add(&t, a, &cached);
    mw_ge_p1p1_to_p3(r, &t);
}

static void p3_neg(mw_ge_p3* r, const mw_ge_p3* a)
{
    for (int i = 0; i < 10; ++i) {
        r->X[i] = -a->X[i];
        r->Y[i] = a->Y[i];
        r->Z[i] = a->Z[i];
        r->T[i] = -a->T[i];
    }
}

// r = (mask == 0xff) ? a : b, without branching on `mask`.
static void p3_cmov(mw_ge_p3* r, const mw_ge_p3* a, const mw_ge_p3* b, uint8_t mask)
{
    const int32_t m = -(int32_t)(mask & 1u);   // 0 or -1, branch free
    for (int i = 0; i < 10; ++i) {
        r->X[i] = (a->X[i] & m) | (b->X[i] & ~m);
        r->Y[i] = (a->Y[i] & m) | (b->Y[i] & ~m);
        r->Z[i] = (a->Z[i] & m) | (b->Z[i] & ~m);
        r->T[i] = (a->T[i] & m) | (b->T[i] & ~m);
    }
}

// acc += s*P
static void p3_addmul(mw_ge_p3* acc, const mw_scalar_t* s, const mw_ge_p3* p)
{
    mw_ge_p3 t;
    mw_ge_scalarmult(&t, s, p);
    p3_add(acc, acc, &t);
    mw_memzero(&t, sizeof(t));
}

// acc += s*P for a compressed P (returns non-zero when P does not decode)
static int p3_addmul_bytes(mw_ge_p3* acc, const mw_scalar_t* s, const mw_point_t* p)
{
    mw_ge_p3 pp;
    if (mw_ge_frombytes_vartime(&pp, p) != 0) {
        return -1;
    }
    p3_addmul(acc, s, &pp);
    return 0;
}

// --------------------------------------------------------------- progress
static mw_progress_cb g_progress_cb = NULL;
static void* g_progress_user = NULL;

void mw_bpp_set_progress_cb(mw_progress_cb cb, void* user)
{
    g_progress_cb = cb;
    g_progress_user = user;
}

static void progress(int permille)
{
    if (g_progress_cb != NULL) {
        if (permille < 0) {
            permille = 0;
        }
        if (permille > 1000) {
            permille = 1000;
        }
        g_progress_cb(permille, g_progress_user);
    }
}

// ------------------------------------------------------------- generators
static mw_point_t* g_gi = NULL;      // Gi[i] = exponent(2i+1)
static mw_point_t* g_hi = NULL;      // Hi[i] = exponent(2i)
static uint32_t g_gens_ready = 0;    // how many indices are filled

static void bpp_get_exponent(mw_point_t* out, uint32_t idx)
{
#if MW_BPP_USE_CRYPTO_GET_EXPONENT
    mw_bp_get_exponent(out, idx);
#else
    static const char salt[] = "bulletproof_plus";
    uint8_t buf[32 + sizeof(salt) - 1 + 10];
    memcpy(buf, MW_POINT_H.b, 32);
    memcpy(buf + 32, salt, sizeof(salt) - 1);
    size_t len = 32 + sizeof(salt) - 1;
    len += mw_varint_encode(idx, buf + len);
    mw_hash_to_point(buf, len, out);
#endif
}

mw_err_t mw_bpp_init(void)
{
    if (g_gi == NULL) {
        g_gi = (mw_point_t*)calloc(MW_BPP_MAX_MN, sizeof(mw_point_t));
        g_hi = (mw_point_t*)calloc(MW_BPP_MAX_MN, sizeof(mw_point_t));
        if (g_gi == NULL || g_hi == NULL) {
            mw_bpp_free();
            return MW_ERR_MEMORY;
        }
        g_gens_ready = 0;
    }
    return MW_OK;
}

void mw_bpp_free(void)
{
    free(g_gi);
    free(g_hi);
    g_gi = NULL;
    g_hi = NULL;
    g_gens_ready = 0;
}

// Fills the generator cache up to `count` entries (idempotent, incremental).
static mw_err_t ensure_generators(uint32_t count)
{
    if (count > MW_BPP_MAX_MN) {
        return MW_ERR_TOO_MANY;
    }
    mw_err_t err = mw_bpp_init();
    if (err != MW_OK) {
        return err;
    }
    for (uint32_t i = g_gens_ready; i < count; ++i) {
        bpp_get_exponent(&g_gi[i], 2 * i + 1);
        bpp_get_exponent(&g_hi[i], 2 * i);
        if (mw_point_is_identity(&g_gi[i]) || mw_point_is_identity(&g_hi[i])) {
            return MW_ERR_FORMAT;                // "exponent is point at infinity"
        }
        if (((i + 1) & 0x3f) == 0) {
            progress((int)(20 * (i + 1) / (count == 0 ? 1 : count)));
        }
    }
    if (count > g_gens_ready) {
        g_gens_ready = count;
    }
    return MW_OK;
}

// ------------------------------------------------------------- transcript
// Monero: initial_transcript = hash_to_p3(cn_fast_hash(domain_separator)),
// i.e. a compressed POINT (keccak twice, then fromfe + mul8), NOT a scalar
// Hs(domain_separator). The 32 point bytes are used as the transcript value.
static void transcript_init(mw_scalar_t* t)
{
    uint8_t h[MW_KECCAK_DIGEST];
    mw_point_t p;
    mw_keccak256((const uint8_t*)BPP_TRANSCRIPT, sizeof(BPP_TRANSCRIPT) - 1, h);
    mw_hash_to_point(h, sizeof(h), &p);   // applies the second Keccak pass
    memcpy(t->b, p.b, 32);
}

static void transcript_update_scalar(mw_scalar_t* t, const mw_scalar_t* v)
{
    uint8_t buf[64];
    memcpy(buf, t->b, 32);
    memcpy(buf + 32, v->b, 32);
    mw_hash_to_scalar(buf, sizeof(buf), t);
}

static void transcript_update1(mw_scalar_t* t, const mw_point_t* a)
{
    uint8_t buf[64];
    memcpy(buf, t->b, 32);
    memcpy(buf + 32, a->b, 32);
    mw_hash_to_scalar(buf, sizeof(buf), t);
}

static void transcript_update2(mw_scalar_t* t, const mw_point_t* a,
                               const mw_point_t* b)
{
    uint8_t buf[96];
    memcpy(buf, t->b, 32);
    memcpy(buf + 32, a->b, 32);
    memcpy(buf + 64, b->b, 32);
    mw_hash_to_scalar(buf, sizeof(buf), t);
}

// Hs(V[0] || ... || V[n-1])
static void hash_commitments(const mw_point_t* V, uint8_t n, mw_scalar_t* out)
{
    uint8_t buf[MW_BPP_MAX_OUTPUTS * 32];
    for (uint8_t i = 0; i < n; ++i) {
        memcpy(buf + 32u * i, V[i].b, 32);
    }
    mw_hash_to_scalar(buf, 32u * n, out);
}

// Replays the whole Fiat-Shamir transcript of a finished proof.
static mw_err_t replay_transcript(const mw_bpp_proof_t* p, mw_scalar_t* y_out,
                                  mw_scalar_t* z_out, mw_scalar_t* e_out,
                                  mw_scalar_t* challenges /* [n_lr] */)
{
    mw_scalar_t t, hv;
    transcript_init(&t);
    hash_commitments(p->V, p->n_v, &hv);
    transcript_update_scalar(&t, &hv);

    transcript_update1(&t, &p->A);
    if (mw_sc_is_zero(&t)) {
        return MW_ERR_SIGNATURE;
    }
    *y_out = t;
    mw_hash_to_scalar(t.b, 32, &t);              // z = Hs(y)
    if (mw_sc_is_zero(&t)) {
        return MW_ERR_SIGNATURE;
    }
    *z_out = t;

    for (uint8_t r = 0; r < p->n_lr; ++r) {
        transcript_update2(&t, &p->L[r], &p->R[r]);
        if (mw_sc_is_zero(&t)) {
            return MW_ERR_SIGNATURE;
        }
        challenges[r] = t;
    }
    transcript_update2(&t, &p->A1, &p->B);
    if (mw_sc_is_zero(&t)) {
        return MW_ERR_SIGNATURE;
    }
    *e_out = t;
    return MW_OK;
}

// ------------------------------------------------------------- dimensions
// M = smallest power of two >= n (Monero's loop in bulletproof_plus_PROVE).
static mw_err_t dimensions(uint8_t n, uint32_t* M_out, uint8_t* logM_out)
{
    if (n == 0 || n > MW_BPP_MAX_OUTPUTS) {
        return (n == 0) ? MW_ERR_INVALID_ARG : MW_ERR_TOO_MANY;
    }
    uint8_t logM = 0;
    uint32_t M = 1;
    while (M < n) {
        M <<= 1;
        ++logM;
    }
    if (M > MW_BPP_MAX_M) {
        return MW_ERR_TOO_MANY;
    }
    *M_out = M;
    *logM_out = logM;
    return MW_OK;
}

// ------------------------------------------------------------------ prover
typedef struct {
    mw_scalar_t* a;          // aprime, MN entries
    mw_scalar_t* b;          // bprime, MN entries
    mw_ge_p3*    Gp;         // Gprime,  MN entries
    mw_ge_p3*    Hp;         // Hprime,  MN entries
} bpp_work_t;

static void work_free(bpp_work_t* w, uint32_t mn)
{
    if (w->a != NULL) {
        mw_memzero(w->a, mn * sizeof(mw_scalar_t));
        free(w->a);
    }
    if (w->b != NULL) {
        mw_memzero(w->b, mn * sizeof(mw_scalar_t));
        free(w->b);
    }
    free(w->Gp);
    free(w->Hp);
    memset(w, 0, sizeof(*w));
}

static mw_err_t work_alloc(bpp_work_t* w, uint32_t mn)
{
    memset(w, 0, sizeof(*w));
    w->a = (mw_scalar_t*)calloc(mn, sizeof(mw_scalar_t));
    w->b = (mw_scalar_t*)calloc(mn, sizeof(mw_scalar_t));
    w->Gp = (mw_ge_p3*)calloc(mn, sizeof(mw_ge_p3));
    w->Hp = (mw_ge_p3*)calloc(mn, sizeof(mw_ge_p3));
    if (w->a == NULL || w->b == NULL || w->Gp == NULL || w->Hp == NULL) {
        work_free(w, mn);
        return MW_ERR_MEMORY;
    }
    return MW_OK;
}

// res = sum_i a[i]*b[i]*y^(i+1)
static void weighted_inner_product(mw_scalar_t* res, const mw_scalar_t* a,
                                   const mw_scalar_t* b, const mw_scalar_t* y,
                                   uint32_t n)
{
    mw_scalar_t acc, ypow, t;
    mw_sc_0(&acc);
    mw_sc_1(&ypow);
    for (uint32_t i = 0; i < n; ++i) {
        mw_sc_mul(&t, &a[i], &b[i]);
        mw_sc_mul(&ypow, &ypow, y);
        mw_sc_muladd(&acc, &t, &ypow, &acc);
    }
    *res = acc;
    mw_memzero(&t, sizeof(t));
    mw_memzero(&acc, sizeof(acc));
}

mw_err_t mw_bpp_prove(const uint64_t* amounts, const mw_scalar_t* masks,
                      uint8_t n, mw_bpp_proof_t* proof_out)
{
    if (amounts == NULL || masks == NULL || proof_out == NULL) {
        return MW_ERR_INVALID_ARG;
    }
    uint32_t M;
    uint8_t logM;
    mw_err_t err = dimensions(n, &M, &logM);
    if (err != MW_OK) {
        return err;
    }
    const uint32_t MN = M * BPP_N;
    const uint8_t logMN = (uint8_t)(logM + BPP_LOG_N);

    err = ensure_generators(MN);
    if (err != MW_OK) {
        return err;
    }

    bpp_work_t w;
    err = work_alloc(&w, MN);
    if (err != MW_OK) {
        return err;
    }

    memset(proof_out, 0, sizeof(*proof_out));
    proof_out->n_v = n;
    proof_out->n_lr = logMN;

    mw_scalar_t inv8, one, two;
    sc_inv8(&inv8);
    mw_sc_1(&one);
    mw_sc_0(&two);
    two.b[0] = 2;

    // ---- V_i = (1/8)*(gamma_i*G + v_i*H)
    for (uint8_t i = 0; i < n; ++i) {
        mw_scalar_t g8, v8, v;
        if (!mw_sc_check(&masks[i])) {
            work_free(&w, MN);
            return MW_ERR_INVALID_ARG;
        }
        mw_sc_mul(&g8, &masks[i], &inv8);
        sc_from_u64(&v, amounts[i]);
        mw_sc_mul(&v8, &v, &inv8);
        mw_commit(&proof_out->V[i], &g8, &v8);
        mw_memzero(&g8, sizeof(g8));
        mw_memzero(&v8, sizeof(v8));
    }

    // ---- expanded generators
    for (uint32_t i = 0; i < MN; ++i) {
        if (mw_ge_frombytes_vartime(&w.Gp[i], &g_gi[i]) != 0 ||
            mw_ge_frombytes_vartime(&w.Hp[i], &g_hi[i]) != 0) {
            work_free(&w, MN);
            return MW_ERR_FORMAT;
        }
    }
    progress(60);

    mw_scalar_t transcript, hv;
    transcript_init(&transcript);
    hash_commitments(proof_out->V, n, &hv);
    transcript_update_scalar(&transcript, &hv);

    // ---- A = (1/8)*(<aL,Gi> + <aR,Hi> + alpha*G)
    // aL_i is a bit of an amount, aR_i = aL_i - 1, so every term is either
    // +Gi[i] (bit set) or -Hi[i] (bit clear). The selection is done with a
    // constant-time conditional move so the timing does not leak the amounts.
    mw_scalar_t alpha;
    {
        uint8_t ctx[8 + MW_BPP_MAX_OUTPUTS * 32];
        size_t ctx_len = 0;
        for (uint8_t i = 0; i < n; ++i) {
            memcpy(ctx + ctx_len, masks[i].b, 32);
            ctx_len += 32;
        }
        mw_random_hedged_scalar(&alpha, ctx, ctx_len);
        mw_memzero(ctx, sizeof(ctx));
    }

    mw_ge_p3 acc;
    mw_ge_p3_0(&acc);
    for (uint32_t i = 0; i < MN; ++i) {
        const uint32_t j = i / BPP_N;
        const uint32_t k = i % BPP_N;
        const uint64_t v = (j < n) ? amounts[j] : 0;
        const uint8_t bit = (uint8_t)((v >> k) & 1u);
        mw_ge_p3 neg, sel;
        p3_neg(&neg, &w.Hp[i]);
        p3_cmov(&sel, &w.Gp[i], &neg, bit);
        p3_add(&acc, &acc, &sel);
    }
    {
        mw_ge_p3 scaled, alpha_g;
        mw_scalar_t a8;
        mw_ge_scalarmult(&scaled, &inv8, &acc);
        mw_sc_mul(&a8, &alpha, &inv8);
        mw_ge_scalarmult_base(&alpha_g, &a8);
        p3_add(&scaled, &scaled, &alpha_g);
        mw_ge_p3_tobytes(&proof_out->A, &scaled);
        mw_memzero(&a8, sizeof(a8));
        mw_memzero(&scaled, sizeof(scaled));
        mw_memzero(&alpha_g, sizeof(alpha_g));
    }
    mw_memzero(&acc, sizeof(acc));
    progress(80);

    // ---- challenges y, z
    mw_scalar_t y, z, z_sq;
    transcript_update1(&transcript, &proof_out->A);
    y = transcript;
    if (mw_sc_is_zero(&y)) {
        work_free(&w, MN);
        return MW_ERR_SIGNATURE;
    }
    mw_hash_to_scalar(y.b, 32, &transcript);
    z = transcript;
    if (mw_sc_is_zero(&z)) {
        work_free(&w, MN);
        return MW_ERR_SIGNATURE;
    }
    mw_sc_mul(&z_sq, &z, &z);

    mw_scalar_t yinv, y_mn, y_mn1;
    mw_sc_invert(&yinv, &y);
    sc_pow_u64(&y_mn, &y, MN);
    mw_sc_mul(&y_mn1, &y_mn, &y);

    // ---- a' = aL - z,  b' = aR + z + d_i*y^{MN-i}
    {
        mw_scalar_t y_desc = y_mn;               // y^(MN-i), i = 0
        mw_scalar_t z2j;                         // z^(2*(j+1))
        mw_sc_0(&z2j);
        mw_scalar_t d;
        mw_sc_0(&d);
        for (uint32_t i = 0; i < MN; ++i) {
            const uint32_t j = i / BPP_N;
            const uint32_t k = i % BPP_N;
            if (k == 0) {
                if (j == 0) {
                    z2j = z_sq;
                } else {
                    mw_sc_mul(&z2j, &z2j, &z_sq);
                }
                d = z2j;
            } else {
                mw_sc_mul(&d, &d, &two);
            }

            const uint64_t v = (j < n) ? amounts[j] : 0;
            mw_scalar_t bit;
            mw_sc_0(&bit);
            bit.b[0] = (uint8_t)((v >> k) & 1u);

            mw_sc_sub(&w.a[i], &bit, &z);        // aL - z

            mw_scalar_t t;
            mw_sc_mul(&t, &d, &y_desc);
            mw_sc_sub(&w.b[i], &bit, &one);      // aR = aL - 1
            mw_sc_add(&w.b[i], &w.b[i], &z);
            mw_sc_add(&w.b[i], &w.b[i], &t);

            mw_sc_mul(&y_desc, &y_desc, &yinv);  // y^(MN-i-1)
            mw_memzero(&t, sizeof(t));
        }
        mw_memzero(&d, sizeof(d));
        mw_memzero(&z2j, sizeof(z2j));
    }

    // ---- alpha1 = alpha + sum_j y^(MN+1) * z^(2*(j+1)) * gamma_j
    mw_scalar_t alpha1 = alpha;
    {
        mw_scalar_t zpow;
        mw_sc_1(&zpow);
        for (uint8_t j = 0; j < n; ++j) {
            mw_scalar_t t;
            mw_sc_mul(&zpow, &zpow, &z_sq);
            mw_sc_mul(&t, &y_mn1, &zpow);
            mw_sc_muladd(&alpha1, &t, &masks[j], &alpha1);
            mw_memzero(&t, sizeof(t));
        }
        mw_memzero(&zpow, sizeof(zpow));
    }

    // ---- inner product rounds
    uint32_t nprime = MN;
    uint8_t round = 0;
    while (nprime > 1) {
        nprime /= 2;

        mw_scalar_t cL, cR;
        weighted_inner_product(&cL, w.a, w.b + nprime, &y, nprime);
        {
            // cR = <a[n':] * y^n', b[:n']>_y
            mw_scalar_t ynp;
            sc_pow_u64(&ynp, &y, nprime);
            mw_scalar_t acc2, t, ypow;
            mw_sc_0(&acc2);
            mw_sc_1(&ypow);
            for (uint32_t i = 0; i < nprime; ++i) {
                mw_sc_mul(&t, &w.a[i + nprime], &ynp);
                mw_sc_mul(&t, &t, &w.b[i]);
                mw_sc_mul(&ypow, &ypow, &y);
                mw_sc_muladd(&acc2, &t, &ypow, &acc2);
            }
            cR = acc2;
            mw_memzero(&t, sizeof(t));
            mw_memzero(&acc2, sizeof(acc2));
        }

        mw_scalar_t dL, dR;
        mw_sc_random(&dL);
        mw_sc_random(&dR);

        mw_scalar_t ynp, yinv_np;
        sc_pow_u64(&ynp, &y, nprime);
        sc_pow_u64(&yinv_np, &yinv, nprime);

        // L = (1/8)*( sum a[i]*y^-n' * G'[i+n'] + sum b[i+n'] * H'[i]
        //             + cL*H + dL*G )
        {
            mw_ge_p3 sum;
            mw_ge_p3_0(&sum);
            for (uint32_t i = 0; i < nprime; ++i) {
                mw_scalar_t t;
                mw_sc_mul(&t, &w.a[i], &yinv_np);
                p3_addmul(&sum, &t, &w.Gp[i + nprime]);
                p3_addmul(&sum, &w.b[i + nprime], &w.Hp[i]);
                mw_memzero(&t, sizeof(t));
            }
            mw_ge_p3 tp;
            if (p3_addmul_bytes(&sum, &cL, &MW_POINT_H) != 0) {
                work_free(&w, MN);
                return MW_ERR_FORMAT;
            }
            mw_ge_scalarmult_base(&tp, &dL);
            p3_add(&sum, &sum, &tp);
            mw_ge_scalarmult(&tp, &inv8, &sum);
            mw_ge_p3_tobytes(&proof_out->L[round], &tp);
            mw_memzero(&sum, sizeof(sum));
            mw_memzero(&tp, sizeof(tp));
        }
        // R = (1/8)*( sum a[i+n']*y^n' * G'[i] + sum b[i] * H'[i+n']
        //             + cR*H + dR*G )
        {
            mw_ge_p3 sum;
            mw_ge_p3_0(&sum);
            for (uint32_t i = 0; i < nprime; ++i) {
                mw_scalar_t t;
                mw_sc_mul(&t, &w.a[i + nprime], &ynp);
                p3_addmul(&sum, &t, &w.Gp[i]);
                p3_addmul(&sum, &w.b[i], &w.Hp[i + nprime]);
                mw_memzero(&t, sizeof(t));
            }
            mw_ge_p3 tp;
            if (p3_addmul_bytes(&sum, &cR, &MW_POINT_H) != 0) {
                work_free(&w, MN);
                return MW_ERR_FORMAT;
            }
            mw_ge_scalarmult_base(&tp, &dR);
            p3_add(&sum, &sum, &tp);
            mw_ge_scalarmult(&tp, &inv8, &sum);
            mw_ge_p3_tobytes(&proof_out->R[round], &tp);
            mw_memzero(&sum, sizeof(sum));
            mw_memzero(&tp, sizeof(tp));
        }

        transcript_update2(&transcript, &proof_out->L[round], &proof_out->R[round]);
        mw_scalar_t e = transcript;
        if (mw_sc_is_zero(&e)) {
            work_free(&w, MN);
            return MW_ERR_SIGNATURE;
        }
        mw_scalar_t einv;
        mw_sc_invert(&einv, &e);

        // fold the generators: G'[i] = e^-1*G'[i] + (y^-n' * e)*G'[i+n']
        //                      H'[i] = e   *H'[i] + e^-1     *H'[i+n']
        mw_scalar_t gmix;
        mw_sc_mul(&gmix, &yinv_np, &e);
        for (uint32_t i = 0; i < nprime; ++i) {
            mw_ge_p3 t1, t2;
            mw_ge_scalarmult(&t1, &einv, &w.Gp[i]);
            mw_ge_scalarmult(&t2, &gmix, &w.Gp[i + nprime]);
            p3_add(&w.Gp[i], &t1, &t2);
            mw_ge_scalarmult(&t1, &e, &w.Hp[i]);
            mw_ge_scalarmult(&t2, &einv, &w.Hp[i + nprime]);
            p3_add(&w.Hp[i], &t1, &t2);
        }

        // fold the vectors
        mw_scalar_t amix;
        mw_sc_mul(&amix, &einv, &ynp);
        for (uint32_t i = 0; i < nprime; ++i) {
            mw_scalar_t t1, t2;
            mw_sc_mul(&t1, &w.a[i], &e);
            mw_sc_mul(&t2, &w.a[i + nprime], &amix);
            mw_sc_add(&w.a[i], &t1, &t2);
            mw_sc_mul(&t1, &w.b[i], &einv);
            mw_sc_mul(&t2, &w.b[i + nprime], &e);
            mw_sc_add(&w.b[i], &t1, &t2);
            mw_memzero(&t1, sizeof(t1));
            mw_memzero(&t2, sizeof(t2));
        }

        // alpha1 += dL*e^2 + dR*e^-2
        {
            mw_scalar_t e2, ei2;
            mw_sc_mul(&e2, &e, &e);
            mw_sc_mul(&ei2, &einv, &einv);
            mw_sc_muladd(&alpha1, &dL, &e2, &alpha1);
            mw_sc_muladd(&alpha1, &dR, &ei2, &alpha1);
        }

        mw_memzero(&dL, sizeof(dL));
        mw_memzero(&dR, sizeof(dR));
        mw_memzero(&cL, sizeof(cL));
        mw_memzero(&cR, sizeof(cR));

        ++round;
        progress(80 + (int)(700u * round / (logMN == 0 ? 1 : logMN)));
    }

    // ---- final (A1, B) and the responses
    mw_scalar_t r, s, dd, eta;
    mw_sc_random(&r);
    mw_sc_random(&s);
    mw_sc_random(&dd);
    mw_sc_random(&eta);

    {
        mw_ge_p3 sum, tp;
        mw_ge_p3_0(&sum);
        p3_addmul(&sum, &r, &w.Gp[0]);
        p3_addmul(&sum, &s, &w.Hp[0]);
        mw_ge_scalarmult_base(&tp, &dd);
        p3_add(&sum, &sum, &tp);
        mw_scalar_t t1, t2;
        mw_sc_mul(&t1, &r, &y);
        mw_sc_mul(&t1, &t1, &w.b[0]);
        mw_sc_mul(&t2, &s, &y);
        mw_sc_mul(&t2, &t2, &w.a[0]);
        mw_sc_add(&t1, &t1, &t2);
        if (p3_addmul_bytes(&sum, &t1, &MW_POINT_H) != 0) {
            work_free(&w, MN);
            return MW_ERR_FORMAT;
        }
        mw_ge_scalarmult(&tp, &inv8, &sum);
        mw_ge_p3_tobytes(&proof_out->A1, &tp);
        mw_memzero(&t1, sizeof(t1));
        mw_memzero(&t2, sizeof(t2));
        mw_memzero(&sum, sizeof(sum));
        mw_memzero(&tp, sizeof(tp));
    }
    {
        mw_scalar_t t, e8;
        mw_sc_mul(&t, &r, &y);
        mw_sc_mul(&t, &t, &s);
        mw_sc_mul(&t, &t, &inv8);
        mw_sc_mul(&e8, &eta, &inv8);
        mw_commit(&proof_out->B, &e8, &t);       // eta/8*G + (r*y*s)/8*H
        mw_memzero(&t, sizeof(t));
        mw_memzero(&e8, sizeof(e8));
    }

    transcript_update2(&transcript, &proof_out->A1, &proof_out->B);
    mw_scalar_t e = transcript;
    if (mw_sc_is_zero(&e)) {
        work_free(&w, MN);
        return MW_ERR_SIGNATURE;
    }
    mw_scalar_t e_sq;
    mw_sc_mul(&e_sq, &e, &e);

    mw_sc_muladd(&proof_out->r1, &w.a[0], &e, &r);
    mw_sc_muladd(&proof_out->s1, &w.b[0], &e, &s);
    mw_sc_muladd(&proof_out->d1, &dd, &e, &eta);
    mw_sc_muladd(&proof_out->d1, &alpha1, &e_sq, &proof_out->d1);

    mw_memzero(&r, sizeof(r));
    mw_memzero(&s, sizeof(s));
    mw_memzero(&dd, sizeof(dd));
    mw_memzero(&eta, sizeof(eta));
    mw_memzero(&alpha, sizeof(alpha));
    mw_memzero(&alpha1, sizeof(alpha1));
    work_free(&w, MN);
    progress(900);

    // Fault-injection defence: verify our own proof before it leaves.
    err = mw_bpp_verify(proof_out);
    if (err != MW_OK) {
        mw_memzero(proof_out, sizeof(*proof_out));
    }
    progress(1000);
    return err;
}

// ---------------------------------------------------------------- verifier
//
// Checks (all terms on one side, must sum to the identity):
//
//   8e^2*A + sum_j 8e^2*w_j*V_j + sum_r 8e^2*(e_r^2*L_r + e_r^-2*R_r)
//     + 8e*A1 + 8*B
//     + sum_i [ -e^2*z - r1*e*g_i ] * Gi_i
//     + sum_i [  e^2*(z + d_i*y^(MN-i)) - s1*e*h_i ] * Hi_i
//     + [ e^2*((z - z^2)*sum_y - z*y^(MN+1)*sum_d) - r1*y*s1 ] * H
//     + [ -d1 ] * G
//   == identity
//
// with w_j = y^(MN+1) * z^(2(j+1)),
//      g_i = y^-i * prod_r (e_r if bit_r(i) else e_r^-1),
//      h_i =        prod_r (e_r^-1 if bit_r(i) else e_r),
// where bit_r(i) is the bit of i with weight MN >> (r+1).
mw_err_t mw_bpp_verify(const mw_bpp_proof_t* p)
{
    if (p == NULL) {
        return MW_ERR_INVALID_ARG;
    }
    if (p->n_v == 0 || p->n_v > MW_BPP_MAX_OUTPUTS) {
        return (p->n_v == 0) ? MW_ERR_INVALID_ARG : MW_ERR_TOO_MANY;
    }
    if (p->n_lr < BPP_LOG_N || p->n_lr > MW_BPP_MAX_LOG_MN) {
        return MW_ERR_FORMAT;
    }
    const uint32_t MN = 1u << p->n_lr;
    const uint32_t M = MN / BPP_N;
    if (M < p->n_v || (M > 1 && M / 2 >= p->n_v)) {
        return MW_ERR_FORMAT;                    // wrong padding for n_v
    }
    if (!mw_sc_check(&p->r1) || !mw_sc_check(&p->s1) || !mw_sc_check(&p->d1)) {
        return MW_ERR_FORMAT;
    }
    // TZ 8.3: validate every point taken from the proof.
    if (!mw_point_check_public(&p->A) || !mw_point_check_public(&p->A1) ||
        !mw_point_check_public(&p->B)) {
        return MW_ERR_SUBGROUP;
    }
    for (uint8_t i = 0; i < p->n_v; ++i) {
        if (!mw_point_check_public(&p->V[i])) {
            return MW_ERR_SUBGROUP;
        }
    }
    for (uint8_t r = 0; r < p->n_lr; ++r) {
        if (!mw_point_check_public(&p->L[r]) || !mw_point_check_public(&p->R[r])) {
            return MW_ERR_SUBGROUP;
        }
    }

    mw_err_t err = ensure_generators(MN);
    if (err != MW_OK) {
        return err;
    }

    mw_scalar_t y, z, e, chal[MW_BPP_MAX_LOG_MN], chal_inv[MW_BPP_MAX_LOG_MN];
    err = replay_transcript(p, &y, &z, &e, chal);
    if (err != MW_OK) {
        return err;
    }
    for (uint8_t r = 0; r < p->n_lr; ++r) {
        mw_sc_invert(&chal_inv[r], &chal[r]);
    }

    mw_scalar_t two, zero, z_sq, e_sq, yinv, y_mn, y_mn1, eight;
    mw_sc_0(&zero);
    mw_sc_0(&two);
    two.b[0] = 2;
    mw_sc_0(&eight);
    eight.b[0] = 8;
    mw_sc_mul(&z_sq, &z, &z);
    mw_sc_mul(&e_sq, &e, &e);
    mw_sc_invert(&yinv, &y);
    sc_pow_u64(&y_mn, &y, MN);
    mw_sc_mul(&y_mn1, &y_mn, &y);

    mw_ge_p3 total;
    mw_ge_p3_0(&total);

    mw_scalar_t e2_8;                            // 8*e^2
    mw_sc_mul(&e2_8, &e_sq, &eight);

    // A, A1, B
    if (p3_addmul_bytes(&total, &e2_8, &p->A) != 0) {
        return MW_ERR_FORMAT;
    }
    {
        mw_scalar_t t;
        mw_sc_mul(&t, &e, &eight);
        if (p3_addmul_bytes(&total, &t, &p->A1) != 0) {
            return MW_ERR_FORMAT;
        }
        if (p3_addmul_bytes(&total, &eight, &p->B) != 0) {
            return MW_ERR_FORMAT;
        }
    }

    // V_j
    {
        mw_scalar_t zpow;
        mw_sc_1(&zpow);
        for (uint8_t j = 0; j < p->n_v; ++j) {
            mw_scalar_t t;
            mw_sc_mul(&zpow, &zpow, &z_sq);
            mw_sc_mul(&t, &y_mn1, &zpow);
            mw_sc_mul(&t, &t, &e2_8);
            if (p3_addmul_bytes(&total, &t, &p->V[j]) != 0) {
                return MW_ERR_FORMAT;
            }
        }
    }

    // L_r, R_r
    for (uint8_t r = 0; r < p->n_lr; ++r) {
        mw_scalar_t t;
        mw_sc_mul(&t, &chal[r], &chal[r]);
        mw_sc_mul(&t, &t, &e2_8);
        if (p3_addmul_bytes(&total, &t, &p->L[r]) != 0) {
            return MW_ERR_FORMAT;
        }
        mw_sc_mul(&t, &chal_inv[r], &chal_inv[r]);
        mw_sc_mul(&t, &t, &e2_8);
        if (p3_addmul_bytes(&total, &t, &p->R[r]) != 0) {
            return MW_ERR_FORMAT;
        }
    }

    // Gi / Hi, plus the running sums needed for the H coefficient.
    mw_scalar_t sum_y, sum_d;
    mw_sc_0(&sum_y);
    mw_sc_0(&sum_d);
    {
        mw_scalar_t yinv_i, ypow_i, d, z2j, e2z;
        mw_sc_1(&yinv_i);                        // y^-i
        ypow_i = y;                              // y^(i+1)
        mw_sc_0(&d);
        mw_sc_0(&z2j);
        mw_sc_mul(&e2z, &e_sq, &z);

        for (uint32_t i = 0; i < MN; ++i) {
            const uint32_t k = i % BPP_N;
            if (k == 0) {
                if (i == 0) {
                    z2j = z_sq;
                } else {
                    mw_sc_mul(&z2j, &z2j, &z_sq);
                }
                d = z2j;
            } else {
                mw_sc_mul(&d, &d, &two);
            }
            mw_sc_add(&sum_d, &sum_d, &d);
            mw_sc_add(&sum_y, &sum_y, &ypow_i);

            // folding coefficients
            mw_scalar_t g_i = yinv_i, h_i;
            mw_sc_1(&h_i);
            for (uint8_t r = 0; r < p->n_lr; ++r) {
                const uint32_t weight = MN >> (r + 1);
                if ((i & weight) != 0) {
                    mw_sc_mul(&g_i, &g_i, &chal[r]);
                    mw_sc_mul(&h_i, &h_i, &chal_inv[r]);
                } else {
                    mw_sc_mul(&g_i, &g_i, &chal_inv[r]);
                    mw_sc_mul(&h_i, &h_i, &chal[r]);
                }
            }

            // Gi coefficient: -e^2*z - r1*e*g_i
            mw_scalar_t t, coeff;
            mw_sc_mul(&t, &p->r1, &e);
            mw_sc_mul(&t, &t, &g_i);
            mw_sc_add(&t, &t, &e2z);
            mw_sc_sub(&coeff, &zero, &t);
            if (p3_addmul_bytes(&total, &coeff, &g_gi[i]) != 0) {
                return MW_ERR_FORMAT;
            }

            // Hi coefficient: e^2*(z + d_i*y^(MN-i)) - s1*e*h_i
            mw_scalar_t y_desc;
            mw_sc_mul(&y_desc, &y_mn, &yinv_i);  // y^(MN-i)
            mw_sc_mul(&t, &d, &y_desc);
            mw_sc_add(&t, &t, &z);
            mw_sc_mul(&coeff, &t, &e_sq);
            mw_sc_mul(&t, &p->s1, &e);
            mw_sc_mul(&t, &t, &h_i);
            mw_sc_sub(&coeff, &coeff, &t);
            if (p3_addmul_bytes(&total, &coeff, &g_hi[i]) != 0) {
                return MW_ERR_FORMAT;
            }

            mw_sc_mul(&yinv_i, &yinv_i, &yinv);
            mw_sc_mul(&ypow_i, &ypow_i, &y);

            if (((i + 1) & 0x3f) == 0) {
                progress((int)(1000u * (i + 1) / MN));
            }
        }
    }

    // H coefficient: e^2*((z - z^2)*sum_y - z*y^(MN+1)*sum_d) - r1*y*s1
    {
        mw_scalar_t t, u, coeff;
        mw_sc_sub(&t, &z, &z_sq);
        mw_sc_mul(&coeff, &t, &sum_y);
        mw_sc_mul(&t, &z, &y_mn1);
        mw_sc_mul(&t, &t, &sum_d);
        mw_sc_sub(&coeff, &coeff, &t);
        mw_sc_mul(&coeff, &coeff, &e_sq);
        mw_sc_mul(&u, &p->r1, &y);
        mw_sc_mul(&u, &u, &p->s1);
        mw_sc_sub(&coeff, &coeff, &u);
        if (p3_addmul_bytes(&total, &coeff, &MW_POINT_H) != 0) {
            return MW_ERR_FORMAT;
        }
    }

    // G coefficient: -d1
    {
        mw_scalar_t coeff;
        mw_sc_sub(&coeff, &zero, &p->d1);
        mw_ge_p3 t;
        mw_ge_scalarmult_base(&t, &coeff);
        p3_add(&total, &total, &t);
    }

    mw_point_t result;
    mw_ge_p3_tobytes(&result, &total);
    return mw_point_is_identity(&result) ? MW_OK : MW_ERR_SIGNATURE;
}

// -------------------------------------------------------------- utilities
mw_err_t mw_bpp_check_commitments(const mw_bpp_proof_t* proof,
                                  const mw_point_t* out_commitments, uint8_t n)
{
    if (proof == NULL || out_commitments == NULL) {
        return MW_ERR_INVALID_ARG;
    }
    if (proof->n_v != n || n == 0 || n > MW_BPP_MAX_OUTPUTS) {
        return MW_ERR_INVALID_ARG;
    }
    for (uint8_t i = 0; i < n; ++i) {
        mw_ge_p3 v;
        if (mw_ge_frombytes_vartime(&v, &proof->V[i]) != 0) {
            return MW_ERR_FORMAT;
        }
        mw_ge_p2 p2;
        memcpy(p2.X, v.X, sizeof(mw_fe));
        memcpy(p2.Y, v.Y, sizeof(mw_fe));
        memcpy(p2.Z, v.Z, sizeof(mw_fe));
        mw_ge_p1p1 t;
        mw_ge_mul8(&t, &p2);
        mw_ge_p2 r2;
        mw_ge_p1p1_to_p2(&r2, &t);
        mw_point_t got;
        mw_ge_p2_tobytes(&got, &r2);
        if (!mw_point_eq(&got, &out_commitments[i])) {
            return MW_ERR_BALANCE;
        }
    }
    return MW_OK;
}

// Wire format (rct::BulletproofPlus::serialize, V is restored from outPk):
//   A || A1 || B || r1 || s1 || d1 || varint(|L|) || L... || varint(|R|) || R...
size_t mw_bpp_serialize(const mw_bpp_proof_t* p, uint8_t* out, size_t out_len)
{
    if (p == NULL || p->n_lr > MW_BPP_MAX_LOG_MN) {
        return 0;
    }
    mw_writer_t w;
    mw_writer_init(&w, out, out_len);
    mw_write_point(&w, &p->A);
    mw_write_point(&w, &p->A1);
    mw_write_point(&w, &p->B);
    mw_write_scalar(&w, &p->r1);
    mw_write_scalar(&w, &p->s1);
    mw_write_scalar(&w, &p->d1);
    mw_write_varint(&w, p->n_lr);
    for (uint8_t i = 0; i < p->n_lr; ++i) {
        mw_write_point(&w, &p->L[i]);
    }
    mw_write_varint(&w, p->n_lr);
    for (uint8_t i = 0; i < p->n_lr; ++i) {
        mw_write_point(&w, &p->R[i]);
    }
    return w.overflow ? 0 : w.pos;
}

mw_err_t mw_bpp_deserialize(const uint8_t* in, size_t len, mw_bpp_proof_t* out)
{
    if (in == NULL || out == NULL) {
        return MW_ERR_INVALID_ARG;
    }
    memset(out, 0, sizeof(*out));
    mw_reader_t r;
    mw_reader_init(&r, in, len);
    if (!mw_read_point(&r, &out->A) || !mw_read_point(&r, &out->A1) ||
        !mw_read_point(&r, &out->B) || !mw_read_scalar(&r, &out->r1) ||
        !mw_read_scalar(&r, &out->s1) || !mw_read_scalar(&r, &out->d1)) {
        return MW_ERR_FORMAT;
    }
    uint64_t nl = 0, nr = 0;
    if (!mw_read_varint(&r, &nl)) {
        return MW_ERR_FORMAT;
    }
    if (nl < BPP_LOG_N || nl > MW_BPP_MAX_LOG_MN) {
        return MW_ERR_TOO_MANY;
    }
    for (uint64_t i = 0; i < nl; ++i) {
        if (!mw_read_point(&r, &out->L[i])) {
            return MW_ERR_FORMAT;
        }
    }
    if (!mw_read_varint(&r, &nr) || nr != nl) {
        return MW_ERR_FORMAT;
    }
    for (uint64_t i = 0; i < nr; ++i) {
        if (!mw_read_point(&r, &out->R[i])) {
            return MW_ERR_FORMAT;
        }
    }
    out->n_lr = (uint8_t)nl;
    // V is not on the wire; the caller restores it from outPk before verifying.
    out->n_v = 0;
    return r.overflow ? MW_ERR_FORMAT : MW_OK;
}
