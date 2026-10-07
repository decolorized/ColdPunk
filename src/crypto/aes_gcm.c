// Portable AES-256-GCM.  See aes_gcm.h for the design notes.
//
// References:
//   FIPS-197  (AES)
//   NIST SP 800-38D (GCM/GMAC)
//   McGrew & Viega, "The Galois/Counter Mode of Operation (GCM)" - the source
//   of the classic test cases 13..18 used by the unit tests.

#include "aes_gcm.h"
#include "memzero.h"

#include <string.h>

#if defined(MW_AES_GCM_USE_MBEDTLS)
#include "mbedtls/gcm.h"
#endif

// ---------------------------------------------------------------------------
// GF(2^8) arithmetic - branch-free, table-free
// ---------------------------------------------------------------------------

// Multiply in GF(2^8) modulo the AES polynomial x^8 + x^4 + x^3 + x + 1.
// Every step is a mask/shift; no data-dependent branch, no memory lookup.
static uint8_t gf_mul(uint8_t a, uint8_t b)
{
    uint8_t r = 0;
    for (int i = 0; i < 8; i++) {
        uint8_t bit  = (uint8_t)(b & 1u);
        uint8_t bmsk = (uint8_t)(0u - (unsigned)bit);      // 0x00 or 0xff
        r ^= (uint8_t)(bmsk & a);

        uint8_t hi   = (uint8_t)((a >> 7) & 1u);
        uint8_t hmsk = (uint8_t)(0u - (unsigned)hi);
        a = (uint8_t)(a << 1);
        a ^= (uint8_t)(hmsk & 0x1bu);

        b = (uint8_t)(b >> 1);
    }
    return r;
}

// a^254 == a^-1 in GF(2^8) (and 0 -> 0, exactly what AES wants).
// Addition chain: 2,3,6,12,15,30,60,63,126,127,254.
static uint8_t gf_inv(uint8_t a)
{
    uint8_t x2   = gf_mul(a, a);
    uint8_t x3   = gf_mul(x2, a);
    uint8_t x6   = gf_mul(x3, x3);
    uint8_t x12  = gf_mul(x6, x6);
    uint8_t x15  = gf_mul(x12, x3);
    uint8_t x30  = gf_mul(x15, x15);
    uint8_t x60  = gf_mul(x30, x30);
    uint8_t x63  = gf_mul(x60, x3);
    uint8_t x126 = gf_mul(x63, x63);
    uint8_t x127 = gf_mul(x126, a);
    return gf_mul(x127, x127);   // x254
}

static uint8_t rotl8(uint8_t x, int n)
{
    return (uint8_t)((x << n) | (x >> (8 - n)));
}

// The AES S-box: multiplicative inverse followed by the FIPS-197 affine map.
static uint8_t aes_sbox(uint8_t a)
{
    uint8_t b = gf_inv(a);
    return (uint8_t)(b ^ rotl8(b, 1) ^ rotl8(b, 2) ^ rotl8(b, 3) ^ rotl8(b, 4) ^ 0x63u);
}

// ---------------------------------------------------------------------------
// AES-256 key schedule and block encryption
// ---------------------------------------------------------------------------

#define AES256_NK 8
#define AES256_NR 14
#define AES256_RK_WORDS (4 * (AES256_NR + 1))   // 60

typedef struct {
    uint8_t rk[AES256_RK_WORDS][4];
} aes256_ks_t;

// Rcon[i] for i = 1..7 (AES-256 only ever needs seven round constants).
static const uint8_t kRcon[8] = { 0x00, 0x01, 0x02, 0x04, 0x08, 0x10, 0x20, 0x40 };

static void aes256_key_expand(aes256_ks_t* ks, const uint8_t key[32])
{
    int i;
    for (i = 0; i < AES256_NK; i++) {
        ks->rk[i][0] = key[4 * i + 0];
        ks->rk[i][1] = key[4 * i + 1];
        ks->rk[i][2] = key[4 * i + 2];
        ks->rk[i][3] = key[4 * i + 3];
    }
    for (; i < AES256_RK_WORDS; i++) {
        uint8_t t[4];
        t[0] = ks->rk[i - 1][0];
        t[1] = ks->rk[i - 1][1];
        t[2] = ks->rk[i - 1][2];
        t[3] = ks->rk[i - 1][3];

        // The two branches below depend only on `i`, never on key material.
        if ((i % AES256_NK) == 0) {
            uint8_t tmp = t[0];
            t[0] = (uint8_t)(aes_sbox(t[1]) ^ kRcon[i / AES256_NK]);
            t[1] = aes_sbox(t[2]);
            t[2] = aes_sbox(t[3]);
            t[3] = aes_sbox(tmp);
        } else if ((i % AES256_NK) == 4) {
            t[0] = aes_sbox(t[0]);
            t[1] = aes_sbox(t[1]);
            t[2] = aes_sbox(t[2]);
            t[3] = aes_sbox(t[3]);
        }
        ks->rk[i][0] = (uint8_t)(ks->rk[i - AES256_NK][0] ^ t[0]);
        ks->rk[i][1] = (uint8_t)(ks->rk[i - AES256_NK][1] ^ t[1]);
        ks->rk[i][2] = (uint8_t)(ks->rk[i - AES256_NK][2] ^ t[2]);
        ks->rk[i][3] = (uint8_t)(ks->rk[i - AES256_NK][3] ^ t[3]);
    }
}

// state[i] holds row (i % 4), column (i / 4) - the FIPS-197 column-major order.
static void add_round_key(uint8_t st[16], const aes256_ks_t* ks, int round)
{
    for (int c = 0; c < 4; c++)
        for (int r = 0; r < 4; r++)
            st[4 * c + r] ^= ks->rk[4 * round + c][r];
}

static void sub_bytes(uint8_t st[16])
{
    for (int i = 0; i < 16; i++) st[i] = aes_sbox(st[i]);
}

static void shift_rows(uint8_t st[16])
{
    uint8_t t[16];
    for (int r = 0; r < 4; r++)
        for (int c = 0; c < 4; c++)
            t[4 * c + r] = st[4 * ((c + r) & 3) + r];
    memcpy(st, t, 16);
}

static void mix_columns(uint8_t st[16])
{
    for (int c = 0; c < 4; c++) {
        uint8_t a0 = st[4 * c + 0], a1 = st[4 * c + 1];
        uint8_t a2 = st[4 * c + 2], a3 = st[4 * c + 3];
        st[4 * c + 0] = (uint8_t)(gf_mul(a0, 2) ^ gf_mul(a1, 3) ^ a2 ^ a3);
        st[4 * c + 1] = (uint8_t)(a0 ^ gf_mul(a1, 2) ^ gf_mul(a2, 3) ^ a3);
        st[4 * c + 2] = (uint8_t)(a0 ^ a1 ^ gf_mul(a2, 2) ^ gf_mul(a3, 3));
        st[4 * c + 3] = (uint8_t)(gf_mul(a0, 3) ^ a1 ^ a2 ^ gf_mul(a3, 2));
    }
}

static void aes256_encrypt_ks(const aes256_ks_t* ks, const uint8_t in[16], uint8_t out[16])
{
    uint8_t st[16];
    memcpy(st, in, 16);
    add_round_key(st, ks, 0);
    for (int round = 1; round < AES256_NR; round++) {
        sub_bytes(st);
        shift_rows(st);
        mix_columns(st);
        add_round_key(st, ks, round);
    }
    sub_bytes(st);
    shift_rows(st);
    add_round_key(st, ks, AES256_NR);
    memcpy(out, st, 16);
    mw_memzero(st, sizeof st);
}

void mw_aes256_encrypt_block(const uint8_t key[32], const uint8_t in[16], uint8_t out[16])
{
    aes256_ks_t ks;
    aes256_key_expand(&ks, key);
    aes256_encrypt_ks(&ks, in, out);
    mw_memzero(&ks, sizeof ks);
}

// ---------------------------------------------------------------------------
// GHASH - multiplication in GF(2^128), bitwise and branch-free
// ---------------------------------------------------------------------------

// z = x * y in GF(2^128) with the GCM bit ordering (R = 0xe1 || 0^120).
static void gf128_mul(uint8_t z[16], const uint8_t x[16], const uint8_t y[16])
{
    uint8_t v[16], acc[16];
    memcpy(v, y, 16);
    memset(acc, 0, 16);

    for (int i = 0; i < 128; i++) {
        uint8_t bit  = (uint8_t)((x[i >> 3] >> (7 - (i & 7))) & 1u);
        uint8_t bmsk = (uint8_t)(0u - (unsigned)bit);
        for (int j = 0; j < 16; j++) acc[j] ^= (uint8_t)(bmsk & v[j]);

        uint8_t lsb  = (uint8_t)(v[15] & 1u);
        uint8_t lmsk = (uint8_t)(0u - (unsigned)lsb);
        for (int j = 15; j > 0; j--)
            v[j] = (uint8_t)((v[j] >> 1) | (uint8_t)(v[j - 1] << 7));
        v[0] = (uint8_t)(v[0] >> 1);
        v[0] ^= (uint8_t)(lmsk & 0xe1u);
    }
    memcpy(z, acc, 16);
    mw_memzero(v, sizeof v);
    mw_memzero(acc, sizeof acc);
}

typedef struct {
    uint8_t h[16];     // hash subkey
    uint8_t y[16];     // running state
} ghash_ctx;

static void ghash_init(ghash_ctx* g, const uint8_t h[16])
{
    memcpy(g->h, h, 16);
    memset(g->y, 0, 16);
}

// Absorbs `len` bytes, zero-padding the final partial block.
static void ghash_update(ghash_ctx* g, const uint8_t* data, size_t len)
{
    uint8_t blk[16];
    while (len > 0) {
        size_t n = (len < 16) ? len : 16;
        memset(blk, 0, 16);
        memcpy(blk, data, n);
        for (int i = 0; i < 16; i++) g->y[i] ^= blk[i];
        gf128_mul(g->y, g->y, g->h);
        data += n;
        len  -= n;
    }
    mw_memzero(blk, sizeof blk);
}

static void put_be64(uint8_t out[8], uint64_t v)
{
    for (int i = 0; i < 8; i++) out[i] = (uint8_t)(v >> (56 - 8 * i));
}

static void ghash_lengths(ghash_ctx* g, uint64_t aad_len, uint64_t txt_len)
{
    uint8_t blk[16];
    put_be64(blk,     aad_len * 8u);
    put_be64(blk + 8, txt_len * 8u);
    for (int i = 0; i < 16; i++) g->y[i] ^= blk[i];
    gf128_mul(g->y, g->y, g->h);
}

static void inc32(uint8_t ctr[16])
{
    for (int i = 15; i >= 12; i--) {
        ctr[i] = (uint8_t)(ctr[i] + 1u);
        if (ctr[i] != 0) break;
    }
}

// ---------------------------------------------------------------------------
// GCM core
// ---------------------------------------------------------------------------

// Shared by encrypt and decrypt.  GHASH always consumes the CIPHERTEXT, so the
// absorb happens before the XOR when decrypting and after it when encrypting -
// that way `in` and `out` may safely alias each other.
static int gcm_core(const uint8_t key[32],
                    const uint8_t* iv, size_t iv_len,
                    const uint8_t* aad, size_t aad_len,
                    const uint8_t* in, size_t len, uint8_t* out,
                    int decrypting,
                    uint8_t tag[16])
{
    aes256_ks_t ks;
    ghash_ctx   gh;
    uint8_t     h[16], j0[16], ctr[16], ks_blk[16], zero[16];
    size_t      off;

    memset(zero, 0, sizeof zero);
    aes256_key_expand(&ks, key);
    aes256_encrypt_ks(&ks, zero, h);          // H = E_K(0^128)

    if (iv_len == 12) {
        memcpy(j0, iv, 12);
        j0[12] = 0; j0[13] = 0; j0[14] = 0; j0[15] = 1;
    } else {
        ghash_ctx gj;
        ghash_init(&gj, h);
        ghash_update(&gj, iv, iv_len);
        ghash_lengths(&gj, 0, iv_len);
        memcpy(j0, gj.y, 16);
        mw_memzero(&gj, sizeof gj);
    }

    // S = GHASH_H(A || pad || C || pad || [len(A)]64 || [len(C)]64)
    ghash_init(&gh, h);
    ghash_update(&gh, aad, aad_len);

    // GCTR over the payload, starting at inc32(J0).
    memcpy(ctr, j0, 16);
    for (off = 0; off < len; off += 16) {
        size_t n = (len - off < 16) ? (len - off) : 16;
        if (decrypting) ghash_update(&gh, in + off, n);
        inc32(ctr);
        aes256_encrypt_ks(&ks, ctr, ks_blk);
        for (size_t i = 0; i < n; i++) out[off + i] = (uint8_t)(in[off + i] ^ ks_blk[i]);
        if (!decrypting) ghash_update(&gh, out + off, n);
    }

    ghash_lengths(&gh, (uint64_t)aad_len, (uint64_t)len);

    // T = MSB_128(GCTR_K(J0, S))
    aes256_encrypt_ks(&ks, j0, ks_blk);
    for (int i = 0; i < 16; i++) tag[i] = (uint8_t)(gh.y[i] ^ ks_blk[i]);

    mw_memzero(&ks, sizeof ks);
    mw_memzero(&gh, sizeof gh);
    mw_memzero(h, sizeof h);
    mw_memzero(j0, sizeof j0);
    mw_memzero(ctr, sizeof ctr);
    mw_memzero(ks_blk, sizeof ks_blk);
    return MW_AES_GCM_OK;
}

static int gcm_args_ok(const uint8_t* key, const uint8_t* iv, size_t iv_len,
                       const uint8_t* aad, size_t aad_len,
                       const uint8_t* data, size_t len, const uint8_t* out)
{
    if (!key || !iv || iv_len == 0) return 0;
    if (aad_len > 0 && !aad) return 0;
    if (len > 0 && (!data || !out)) return 0;
    // GCM caps the plaintext at 2^39 - 256 bits; we are far below that but the
    // check keeps the length arithmetic honest on 64-bit hosts.
    if (len > (size_t)((1ULL << 36) - 32)) return 0;
    return 1;
}

int mw_aes256_gcm_encrypt(const uint8_t key[32],
                          const uint8_t* iv, size_t iv_len,
                          const uint8_t* aad, size_t aad_len,
                          const uint8_t* pt, size_t pt_len,
                          uint8_t* ct, uint8_t tag[16])
{
    if (!tag) return MW_AES_GCM_BAD_ARG;
    if (!gcm_args_ok(key, iv, iv_len, aad, aad_len, pt, pt_len, ct))
        return MW_AES_GCM_BAD_ARG;

#if defined(MW_AES_GCM_USE_MBEDTLS)
    {
        mbedtls_gcm_context c;
        int rc;
        mbedtls_gcm_init(&c);
        rc = mbedtls_gcm_setkey(&c, MBEDTLS_CIPHER_ID_AES, key, 256);
        if (rc == 0)
            rc = mbedtls_gcm_crypt_and_tag(&c, MBEDTLS_GCM_ENCRYPT, pt_len,
                                           iv, iv_len, aad, aad_len,
                                           pt, ct, MW_GCM_TAG_BYTES, tag);
        mbedtls_gcm_free(&c);
        return (rc == 0) ? MW_AES_GCM_OK : MW_AES_GCM_BAD_ARG;
    }
#else
    return gcm_core(key, iv, iv_len, aad, aad_len, pt, pt_len, ct, 0, tag);
#endif
}

int mw_aes256_gcm_decrypt(const uint8_t key[32],
                          const uint8_t* iv, size_t iv_len,
                          const uint8_t* aad, size_t aad_len,
                          const uint8_t* ct, size_t ct_len,
                          const uint8_t tag[16], uint8_t* pt)
{
    if (!tag) return MW_AES_GCM_BAD_ARG;
    if (!gcm_args_ok(key, iv, iv_len, aad, aad_len, ct, ct_len, pt))
        return MW_AES_GCM_BAD_ARG;

#if defined(MW_AES_GCM_USE_MBEDTLS)
    {
        mbedtls_gcm_context c;
        int rc;
        mbedtls_gcm_init(&c);
        rc = mbedtls_gcm_setkey(&c, MBEDTLS_CIPHER_ID_AES, key, 256);
        if (rc == 0)
            rc = mbedtls_gcm_auth_decrypt(&c, ct_len, iv, iv_len, aad, aad_len,
                                          tag, MW_GCM_TAG_BYTES, ct, pt);
        mbedtls_gcm_free(&c);
        if (rc != 0) {
            if (ct_len) mw_memzero(pt, ct_len);
            return MW_AES_GCM_BAD_TAG;
        }
        return MW_AES_GCM_OK;
    }
#else
    {
        uint8_t computed[16];
        int ok;
        gcm_core(key, iv, iv_len, aad, aad_len, ct, ct_len, pt, 1, computed);
        ok = mw_ct_equal(computed, tag, MW_GCM_TAG_BYTES);
        mw_memzero(computed, sizeof computed);
        if (!ok) {
            if (ct_len) mw_memzero(pt, ct_len);
            return MW_AES_GCM_BAD_TAG;
        }
        return MW_AES_GCM_OK;
    }
#endif
}
