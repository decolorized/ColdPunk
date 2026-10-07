// Keccak-256 with the ORIGINAL Keccak padding (0x01), i.e. Monero's
// cn_fast_hash - NOT the FIPS-202 SHA3 padding (0x06).
//
//   mw_keccak256("") ==
//     c5d2460186f7233c927e7db2dcc703c0e500b653ca82273b7bfad8045d85a470
//
// Sponge parameters: b = 1600, capacity = 512, rate = 136 bytes.
#include "hash.h"
#include "memzero.h"

#include <string.h>

#define KECCAK_ROUNDS 24
#define KECCAK_RATE   136   // 200 - 2*32

static const uint64_t keccakf_rndc[KECCAK_ROUNDS] = {
    0x0000000000000001ULL, 0x0000000000008082ULL, 0x800000000000808aULL,
    0x8000000080008000ULL, 0x000000000000808bULL, 0x0000000080000001ULL,
    0x8000000080008081ULL, 0x8000000000008009ULL, 0x000000000000008aULL,
    0x0000000000000088ULL, 0x0000000080008009ULL, 0x000000008000000aULL,
    0x000000008000808bULL, 0x800000000000008bULL, 0x8000000000008089ULL,
    0x8000000000008003ULL, 0x8000000000008002ULL, 0x8000000000000080ULL,
    0x000000000000800aULL, 0x800000008000000aULL, 0x8000000080008081ULL,
    0x8000000000008080ULL, 0x0000000080000001ULL, 0x8000000080008008ULL
};

static const int keccakf_rotc[24] = {
     1,  3,  6, 10, 15, 21, 28, 36, 45, 55,  2, 14,
    27, 41, 56,  8, 25, 43, 62, 18, 39, 61, 20, 44
};

static const int keccakf_piln[24] = {
    10,  7, 11, 17, 18,  3,  5, 16,  8, 21, 24,  4,
    15, 23, 19, 13, 12,  2, 20, 14, 22,  9,  6,  1
};

static inline uint64_t rotl64(uint64_t x, int n) {
    return (x << n) | (x >> (64 - n));
}

static void keccakf(uint64_t st[25]) {
    uint64_t t, bc[5];

    for (int round = 0; round < KECCAK_ROUNDS; ++round) {
        // Theta
        for (int i = 0; i < 5; ++i) {
            bc[i] = st[i] ^ st[i + 5] ^ st[i + 10] ^ st[i + 15] ^ st[i + 20];
        }
        for (int i = 0; i < 5; ++i) {
            t = bc[(i + 4) % 5] ^ rotl64(bc[(i + 1) % 5], 1);
            for (int j = 0; j < 25; j += 5) {
                st[j + i] ^= t;
            }
        }

        // Rho and Pi
        t = st[1];
        for (int i = 0; i < 24; ++i) {
            int j = keccakf_piln[i];
            bc[0] = st[j];
            st[j] = rotl64(t, keccakf_rotc[i]);
            t = bc[0];
        }

        // Chi
        for (int j = 0; j < 25; j += 5) {
            for (int i = 0; i < 5; ++i) {
                bc[i] = st[j + i];
            }
            for (int i = 0; i < 5; ++i) {
                st[j + i] ^= (~bc[(i + 1) % 5]) & bc[(i + 2) % 5];
            }
        }

        // Iota
        st[0] ^= keccakf_rndc[round];
    }

    mw_memzero(bc, sizeof(bc));
    t = 0; (void)t;
}

static inline uint64_t load64_le(const uint8_t* p) {
    return (uint64_t)p[0]        | ((uint64_t)p[1] << 8)  |
           ((uint64_t)p[2] << 16) | ((uint64_t)p[3] << 24) |
           ((uint64_t)p[4] << 32) | ((uint64_t)p[5] << 40) |
           ((uint64_t)p[6] << 48) | ((uint64_t)p[7] << 56);
}

static inline void store64_le(uint8_t* p, uint64_t v) {
    for (int i = 0; i < 8; ++i) {
        p[i] = (uint8_t)(v >> (8 * i));
    }
}

// XORs one full rate-sized block into the state and permutes.
static void keccak_absorb_block(uint64_t st[25], const uint8_t block[KECCAK_RATE]) {
    for (int i = 0; i < KECCAK_RATE / 8; ++i) {
        st[i] ^= load64_le(block + 8 * i);
    }
    keccakf(st);
}

void mw_keccak_init(mw_keccak_ctx* ctx) {
    memset(ctx, 0, sizeof(*ctx));
}

void mw_keccak_update(mw_keccak_ctx* ctx, const uint8_t* data, size_t len) {
    if (len == 0 || data == NULL) {
        return;
    }
    if (ctx->buf_len > 0) {
        size_t want = KECCAK_RATE - ctx->buf_len;
        size_t take = (len < want) ? len : want;
        memcpy(ctx->buf + ctx->buf_len, data, take);
        ctx->buf_len += take;
        data += take;
        len  -= take;
        if (ctx->buf_len == KECCAK_RATE) {
            keccak_absorb_block(ctx->state, ctx->buf);
            ctx->buf_len = 0;
        }
    }
    while (len >= KECCAK_RATE) {
        keccak_absorb_block(ctx->state, data);
        data += KECCAK_RATE;
        len  -= KECCAK_RATE;
    }
    if (len > 0) {
        memcpy(ctx->buf, data, len);
        ctx->buf_len = len;
    }
}

// Applies the original Keccak pad10*1 rule and runs the final permutation.
static void keccak_pad_and_permute(mw_keccak_ctx* ctx) {
    uint8_t block[KECCAK_RATE];
    memcpy(block, ctx->buf, ctx->buf_len);
    memset(block + ctx->buf_len, 0, KECCAK_RATE - ctx->buf_len);
    block[ctx->buf_len]     |= 0x01;   // original Keccak domain byte
    block[KECCAK_RATE - 1]  |= 0x80;
    keccak_absorb_block(ctx->state, block);
    ctx->buf_len = 0;
    mw_memzero(block, sizeof(block));
}

void mw_keccak_final(mw_keccak_ctx* ctx, uint8_t out[MW_KECCAK_DIGEST]) {
    keccak_pad_and_permute(ctx);
    for (int i = 0; i < MW_KECCAK_DIGEST / 8; ++i) {
        store64_le(out + 8 * i, ctx->state[i]);
    }
    mw_memzero(ctx, sizeof(*ctx));
}

void mw_keccak256(const uint8_t* data, size_t len, uint8_t out[MW_KECCAK_DIGEST]) {
    mw_keccak_ctx ctx;
    mw_keccak_init(&ctx);
    mw_keccak_update(&ctx, data, len);
    mw_keccak_final(&ctx, out);
}

void mw_keccak_xof(const uint8_t* data, size_t len, uint8_t* out, size_t out_len) {
    mw_keccak_ctx ctx;
    uint8_t block[KECCAK_RATE];

    mw_keccak_init(&ctx);
    mw_keccak_update(&ctx, data, len);
    keccak_pad_and_permute(&ctx);

    while (out_len > 0) {
        for (int i = 0; i < KECCAK_RATE / 8; ++i) {
            store64_le(block + 8 * i, ctx.state[i]);
        }
        size_t take = (out_len < KECCAK_RATE) ? out_len : (size_t)KECCAK_RATE;
        memcpy(out, block, take);
        out     += take;
        out_len -= take;
        if (out_len > 0) {
            keccakf(ctx.state);
        }
    }

    mw_memzero(block, sizeof(block));
    mw_memzero(&ctx, sizeof(ctx));
}

// ---------------------------------------------------------------------------
// Raw sponge access, needed by CryptoNight (cn_slow_hash.c). These are not
// part of the public hash.h contract; cn_slow_hash.c declares them itself.
// ---------------------------------------------------------------------------

// The bare Keccak-f[1600] permutation over a 25-word state.
void mw_keccakf1600(uint64_t st[25]) {
    keccakf(st);
}

// Keccak with rate 136 that returns the FULL 200-byte state, which is what
// Monero's hash_process()/cn_slow_hash needs.
void mw_keccak1600(const uint8_t* data, size_t len, uint8_t out[200]) {
    mw_keccak_ctx ctx;
    mw_keccak_init(&ctx);
    mw_keccak_update(&ctx, data, len);
    keccak_pad_and_permute(&ctx);
    for (int i = 0; i < 25; ++i) {
        store64_le(out + 8 * i, ctx.state[i]);
    }
    mw_memzero(&ctx, sizeof(ctx));
}

// Applies Keccak-f[1600] in place to a 200-byte little-endian state buffer
// (Monero's hash_permutation()).
void mw_keccak_permute_bytes(uint8_t state[200]) {
    uint64_t st[25];
    for (int i = 0; i < 25; ++i) {
        st[i] = load64_le(state + 8 * i);
    }
    keccakf(st);
    for (int i = 0; i < 25; ++i) {
        store64_le(state + 8 * i, st[i]);
    }
    mw_memzero(st, sizeof(st));
}
