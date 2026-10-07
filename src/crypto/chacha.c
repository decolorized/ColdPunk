// ChaCha20 in Monero's flavour: 8-byte IV, 64-bit block counter starting at 0
// (the original Bernstein layout, not the RFC 8439 32-bit-counter variant).
//
// Plus generate_chacha_key(), which runs the key material through
// cn_slow_hash (CryptoNight v0) exactly like Monero does.
#include "chacha.h"
#include "memzero.h"

#include <string.h>

#define CHACHA_ROUNDS 20

static inline uint32_t rotl32(uint32_t v, int n) {
    return (v << n) | (v >> (32 - n));
}

static inline uint32_t load32_le(const uint8_t* p) {
    return (uint32_t)p[0] | ((uint32_t)p[1] << 8) |
           ((uint32_t)p[2] << 16) | ((uint32_t)p[3] << 24);
}

static inline void store32_le(uint8_t* p, uint32_t v) {
    p[0] = (uint8_t)v;
    p[1] = (uint8_t)(v >> 8);
    p[2] = (uint8_t)(v >> 16);
    p[3] = (uint8_t)(v >> 24);
}

#define QUARTERROUND(a, b, c, d)          \
    a += b; d ^= a; d = rotl32(d, 16);    \
    c += d; b ^= c; b = rotl32(b, 12);    \
    a += b; d ^= a; d = rotl32(d,  8);    \
    c += d; b ^= c; b = rotl32(b,  7);

static void chacha_block(uint32_t out[16], const uint32_t in[16]) {
    uint32_t x[16];
    memcpy(x, in, sizeof(x));

    for (int i = 0; i < CHACHA_ROUNDS; i += 2) {
        QUARTERROUND(x[0], x[4], x[ 8], x[12])
        QUARTERROUND(x[1], x[5], x[ 9], x[13])
        QUARTERROUND(x[2], x[6], x[10], x[14])
        QUARTERROUND(x[3], x[7], x[11], x[15])
        QUARTERROUND(x[0], x[5], x[10], x[15])
        QUARTERROUND(x[1], x[6], x[11], x[12])
        QUARTERROUND(x[2], x[7], x[ 8], x[13])
        QUARTERROUND(x[3], x[4], x[ 9], x[14])
    }
    for (int i = 0; i < 16; ++i) {
        out[i] = x[i] + in[i];
    }
    mw_memzero(x, sizeof(x));
}

void mw_chacha20(const void* in, size_t len, const mw_chacha_key* key,
                 const mw_chacha_iv* iv, void* out) {
    static const uint8_t sigma[16] = "expand 32-byte k";
    uint32_t       state[16];
    uint32_t       block[16];
    uint8_t        ks[64];
    const uint8_t* src = (const uint8_t*)in;
    uint8_t*       dst = (uint8_t*)out;

    for (int i = 0; i < 4; ++i) {
        state[i] = load32_le(sigma + 4 * i);
    }
    for (int i = 0; i < 8; ++i) {
        state[4 + i] = load32_le(key->data + 4 * i);
    }
    state[12] = 0;   // 64-bit counter, starts at zero
    state[13] = 0;
    state[14] = load32_le(iv->data);
    state[15] = load32_le(iv->data + 4);

    while (len > 0) {
        chacha_block(block, state);
        for (int i = 0; i < 16; ++i) {
            store32_le(ks + 4 * i, block[i]);
        }
        size_t take = (len < 64) ? len : 64;
        for (size_t i = 0; i < take; ++i) {
            dst[i] = (uint8_t)(src[i] ^ ks[i]);
        }
        src += take;
        dst += take;
        len -= take;

        // 64-bit little-endian counter increment
        state[12]++;
        if (state[12] == 0) {
            state[13]++;
        }
    }

    mw_memzero(state, sizeof(state));
    mw_memzero(block, sizeof(block));
    mw_memzero(ks, sizeof(ks));
}

void mw_generate_chacha_key(const void* data, size_t len,
                            mw_chacha_key* key, uint64_t iterations) {
    uint8_t pwd_hash[32];

    if (iterations == 0) {
        iterations = 1;
    }
    if (mw_cn_slow_hash(data, len, pwd_hash) != 0) {
        mw_memzero(key, sizeof(*key));
        return;
    }
    for (uint64_t n = 1; n < iterations; ++n) {
        (void)mw_cn_slow_hash(pwd_hash, sizeof(pwd_hash), pwd_hash);
    }
    memcpy(key->data, pwd_hash, MW_CHACHA_KEY_SIZE);
    mw_memzero(pwd_hash, sizeof(pwd_hash));
}
