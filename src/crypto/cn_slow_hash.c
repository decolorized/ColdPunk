// CryptoNight "slow hash", variant 0 - the key derivation Monero applies to
// wallet-file key material (generate_chacha_key).
//
// Reference: Monero src/crypto/slow-hash.c (portable path).
//
// Structure:
//   1. Keccak-f[1600] the input into a 200-byte state.
//   2. Expand state[64..192] into a 2 MiB scratchpad with AES-256 pseudo
//      rounds.
//   3. 524288 memory-hard double-iterations mixing AES rounds and 64x64->128 muls.
//   4. Fold the scratchpad back, permute, then run ONE of four finalizers
//      (Blake-256 / Groestl-256 / JH-256 / Skein-512-256) selected by
//      state[0] & 3.
//
// The four finalizers are compact re-implementations of the SHA-3 candidate
// specifications (BLAKE, Groestl, JH and Skein), whose reference code the
// designers placed in the public domain. Their round constants and initial
// values are algorithm constants and are reproduced here.
//
// Known answer:  cn_slow_hash("This is a test") ==
//                a084f01d1437a09c6985401b60d43554ae105802c5f5d8a9b3253649c0be6605
#include "chacha.h"
#include "memzero.h"

#include <stdlib.h>
#include <string.h>

#if !defined(MW_HOST_BUILD) && defined(ARDUINO)
#include "esp_heap_caps.h"
#endif

// Raw Keccak sponge helpers from keccak.c (not part of hash.h).
void mw_keccak1600(const uint8_t* data, size_t len, uint8_t out[200]);
void mw_keccak_permute_bytes(uint8_t state[200]);

#define CN_MEMORY        2097152u        // 2 MiB scratchpad
#define CN_ITER          1048576u        // ITER = 1 << 20; the loop runs ITER/2 times
#define CN_AES_BLOCK     16u
#define CN_INIT_SIZE_BLK 8u
#define CN_INIT_SIZE_BYTE (CN_INIT_SIZE_BLK * CN_AES_BLOCK)   // 128

// ===========================================================================
// AES (encryption direction only, no key whitening - CryptoNight style)
// ===========================================================================

static const uint8_t cn_sbox[256] = {
    0x63,0x7c,0x77,0x7b,0xf2,0x6b,0x6f,0xc5,0x30,0x01,0x67,0x2b,0xfe,0xd7,0xab,0x76,
    0xca,0x82,0xc9,0x7d,0xfa,0x59,0x47,0xf0,0xad,0xd4,0xa2,0xaf,0x9c,0xa4,0x72,0xc0,
    0xb7,0xfd,0x93,0x26,0x36,0x3f,0xf7,0xcc,0x34,0xa5,0xe5,0xf1,0x71,0xd8,0x31,0x15,
    0x04,0xc7,0x23,0xc3,0x18,0x96,0x05,0x9a,0x07,0x12,0x80,0xe2,0xeb,0x27,0xb2,0x75,
    0x09,0x83,0x2c,0x1a,0x1b,0x6e,0x5a,0xa0,0x52,0x3b,0xd6,0xb3,0x29,0xe3,0x2f,0x84,
    0x53,0xd1,0x00,0xed,0x20,0xfc,0xb1,0x5b,0x6a,0xcb,0xbe,0x39,0x4a,0x4c,0x58,0xcf,
    0xd0,0xef,0xaa,0xfb,0x43,0x4d,0x33,0x85,0x45,0xf9,0x02,0x7f,0x50,0x3c,0x9f,0xa8,
    0x51,0xa3,0x40,0x8f,0x92,0x9d,0x38,0xf5,0xbc,0xb6,0xda,0x21,0x10,0xff,0xf3,0xd2,
    0xcd,0x0c,0x13,0xec,0x5f,0x97,0x44,0x17,0xc4,0xa7,0x7e,0x3d,0x64,0x5d,0x19,0x73,
    0x60,0x81,0x4f,0xdc,0x22,0x2a,0x90,0x88,0x46,0xee,0xb8,0x14,0xde,0x5e,0x0b,0xdb,
    0xe0,0x32,0x3a,0x0a,0x49,0x06,0x24,0x5c,0xc2,0xd3,0xac,0x62,0x91,0x95,0xe4,0x79,
    0xe7,0xc8,0x37,0x6d,0x8d,0xd5,0x4e,0xa9,0x6c,0x56,0xf4,0xea,0x65,0x7a,0xae,0x08,
    0xba,0x78,0x25,0x2e,0x1c,0xa6,0xb4,0xc6,0xe8,0xdd,0x74,0x1f,0x4b,0xbd,0x8b,0x8a,
    0x70,0x3e,0xb5,0x66,0x48,0x03,0xf6,0x0e,0x61,0x35,0x57,0xb9,0x86,0xc1,0x1d,0x9e,
    0xe1,0xf8,0x98,0x11,0x69,0xd9,0x8e,0x94,0x9b,0x1e,0x87,0xe9,0xce,0x55,0x28,0xdf,
    0x8c,0xa1,0x89,0x0d,0xbf,0xe6,0x42,0x68,0x41,0x99,0x2d,0x0f,0xb0,0x54,0xbb,0x16
};

static inline uint8_t gmul2(uint8_t x) {
    return (uint8_t)((uint8_t)(x << 1) ^ (uint8_t)(0x1b & (uint8_t)(-(int)(x >> 7))));
}

// One AES round on a 16-byte block: SubBytes, ShiftRows, MixColumns, AddKey.
static void aes_round(uint8_t out[16], const uint8_t in[16], const uint8_t key[16]) {
    uint8_t t[16];
    // SubBytes + ShiftRows: byte at (row r, col c) comes from column (c + r).
    for (int c = 0; c < 4; ++c) {
        for (int r = 0; r < 4; ++r) {
            t[4 * c + r] = cn_sbox[in[4 * ((c + r) & 3) + r]];
        }
    }
    for (int c = 0; c < 4; ++c) {
        uint8_t a0 = t[4 * c], a1 = t[4 * c + 1], a2 = t[4 * c + 2], a3 = t[4 * c + 3];
        uint8_t m0 = gmul2(a0), m1 = gmul2(a1), m2 = gmul2(a2), m3 = gmul2(a3);
        out[4 * c + 0] = (uint8_t)(m0 ^ (m1 ^ a1) ^ a2 ^ a3) ^ key[4 * c + 0];
        out[4 * c + 1] = (uint8_t)(a0 ^ m1 ^ (m2 ^ a2) ^ a3) ^ key[4 * c + 1];
        out[4 * c + 2] = (uint8_t)(a0 ^ a1 ^ m2 ^ (m3 ^ a3)) ^ key[4 * c + 2];
        out[4 * c + 3] = (uint8_t)((m0 ^ a0) ^ a1 ^ a2 ^ m3) ^ key[4 * c + 3];
    }
    mw_memzero(t, sizeof(t));
}

// Standard AES-256 key expansion: 15 round keys, 240 bytes.
static void aes_expand_key_256(const uint8_t key[32], uint8_t exp[240]) {
    static const uint8_t rcon[7] = { 0x01, 0x02, 0x04, 0x08, 0x10, 0x20, 0x40 };
    memcpy(exp, key, 32);
    int rc = 0;
    for (int i = 8; i < 60; ++i) {
        uint8_t t[4];
        memcpy(t, exp + 4 * (i - 1), 4);
        if (i % 8 == 0) {
            uint8_t tmp = t[0];
            t[0] = (uint8_t)(cn_sbox[t[1]] ^ rcon[rc++]);
            t[1] = cn_sbox[t[2]];
            t[2] = cn_sbox[t[3]];
            t[3] = cn_sbox[tmp];
        } else if (i % 8 == 4) {
            for (int j = 0; j < 4; ++j) { t[j] = cn_sbox[t[j]]; }
        }
        for (int j = 0; j < 4; ++j) {
            exp[4 * i + j] = (uint8_t)(exp[4 * (i - 8) + j] ^ t[j]);
        }
    }
}

// Ten AES rounds using the first ten expanded round keys.
static void aes_pseudo_round(uint8_t block[16], const uint8_t exp[240]) {
    uint8_t tmp[16];
    for (int r = 0; r < 10; ++r) {
        aes_round(tmp, block, exp + 16 * r);
        memcpy(block, tmp, 16);
    }
    mw_memzero(tmp, sizeof(tmp));
}

// ===========================================================================
// BLAKE-256
// ===========================================================================

static const uint32_t blake_iv[8] = {
    0x6a09e667u, 0xbb67ae85u, 0x3c6ef372u, 0xa54ff53au,
    0x510e527fu, 0x9b05688cu, 0x1f83d9abu, 0x5be0cd19u
};

static const uint32_t blake_c[16] = {
    0x243f6a88u, 0x85a308d3u, 0x13198a2eu, 0x03707344u,
    0xa4093822u, 0x299f31d0u, 0x082efa98u, 0xec4e6c89u,
    0x452821e6u, 0x38d01377u, 0xbe5466cfu, 0x34e90c6cu,
    0xc0ac29b7u, 0xc97c50ddu, 0x3f84d5b5u, 0xb5470917u
};

static const uint8_t blake_sigma[10][16] = {
    {  0, 1, 2, 3, 4, 5, 6, 7, 8, 9,10,11,12,13,14,15 },
    { 14,10, 4, 8, 9,15,13, 6, 1,12, 0, 2,11, 7, 5, 3 },
    { 11, 8,12, 0, 5, 2,15,13,10,14, 3, 6, 7, 1, 9, 4 },
    {  7, 9, 3, 1,13,12,11,14, 2, 6, 5,10, 4, 0,15, 8 },
    {  9, 0, 5, 7, 2, 4,10,15,14, 1,11,12, 6, 8, 3,13 },
    {  2,12, 6,10, 0,11, 8, 3, 4,13, 7, 5,15,14, 1, 9 },
    { 12, 5, 1,15,14,13, 4,10, 0, 7, 6, 3, 9, 2, 8,11 },
    { 13,11, 7,14,12, 1, 3, 9, 5, 0,15, 4, 8, 6, 2,10 },
    {  6,15,14, 9,11, 3, 0, 8,12, 2,13, 7, 1, 4,10, 5 },
    { 10, 2, 8, 4, 7, 6, 1, 5,15,11, 9,14, 3,12,13, 0 }
};

static inline uint32_t rotr32c(uint32_t x, int n) {
    return (x >> n) | (x << (32 - n));
}

static void blake_compress(uint32_t h[8], const uint8_t block[64],
                           uint64_t t, int nullt) {
    uint32_t v[16], m[16];

    for (int i = 0; i < 16; ++i) {
        m[i] = ((uint32_t)block[4 * i] << 24) | ((uint32_t)block[4 * i + 1] << 16) |
               ((uint32_t)block[4 * i + 2] << 8) | (uint32_t)block[4 * i + 3];
    }
    for (int i = 0; i < 8; ++i)  { v[i] = h[i]; }
    for (int i = 0; i < 8; ++i)  { v[8 + i] = blake_c[i]; }
    if (!nullt) {
        v[12] ^= (uint32_t)t;
        v[13] ^= (uint32_t)t;
        v[14] ^= (uint32_t)(t >> 32);
        v[15] ^= (uint32_t)(t >> 32);
    }

    for (int r = 0; r < 14; ++r) {
        const uint8_t* s = blake_sigma[r % 10];
        static const uint8_t idx[8][4] = {
            { 0, 4,  8, 12 }, { 1, 5,  9, 13 }, { 2, 6, 10, 14 }, { 3, 7, 11, 15 },
            { 0, 5, 10, 15 }, { 1, 6, 11, 12 }, { 2, 7,  8, 13 }, { 3, 4,  9, 14 }
        };
        for (int g = 0; g < 8; ++g) {
            int a = idx[g][0], b = idx[g][1], c = idx[g][2], d = idx[g][3];
            int e = 2 * g;
            v[a] = v[a] + (m[s[e]] ^ blake_c[s[e + 1]]) + v[b];
            v[d] = rotr32c(v[d] ^ v[a], 16);
            v[c] = v[c] + v[d];
            v[b] = rotr32c(v[b] ^ v[c], 12);
            v[a] = v[a] + (m[s[e + 1]] ^ blake_c[s[e]]) + v[b];
            v[d] = rotr32c(v[d] ^ v[a], 8);
            v[c] = v[c] + v[d];
            v[b] = rotr32c(v[b] ^ v[c], 7);
        }
    }
    for (int i = 0; i < 16; ++i) {
        h[i % 8] ^= v[i];
    }
    mw_memzero(v, sizeof(v));
    mw_memzero(m, sizeof(m));
}

static void blake256(const uint8_t* data, size_t len, uint8_t out[32]) {
    uint32_t h[8];
    uint8_t  buf[128];
    size_t   pad_start, total, k;

    memcpy(h, blake_iv, sizeof(h));

    // Full 64-byte message blocks first.
    size_t full = len / 64;
    for (size_t i = 0; i < full; ++i) {
        blake_compress(h, data + 64 * i, (uint64_t)(64 * (i + 1)) * 8u, 0);
    }
    size_t rem = len - 64 * full;

    // Padding: 0x80, zeros, 0x01, 64-bit big-endian bit length.
    memset(buf, 0, sizeof(buf));
    memcpy(buf, data + 64 * full, rem);
    pad_start = rem;
    k = 64 - ((rem + 8) % 64);
    if (k == 0) { k = 64; }
    total = rem + k + 8;
    buf[pad_start] = 0x80;
    buf[pad_start + k - 1] |= 0x01;
    {
        uint64_t bits = (uint64_t)len * 8u;
        for (int i = 0; i < 8; ++i) {
            buf[total - 1 - i] = (uint8_t)(bits >> (8 * i));
        }
    }
    for (size_t off = 0; off < total; off += 64) {
        size_t msg_in_block = (rem > off) ? (rem - off) : 0;
        if (msg_in_block > 64) { msg_in_block = 64; }
        uint64_t t = ((uint64_t)(64 * full + off + msg_in_block)) * 8u;
        int nullt = (msg_in_block == 0);
        blake_compress(h, buf + off, t, nullt);
    }

    for (int i = 0; i < 8; ++i) {
        out[4 * i]     = (uint8_t)(h[i] >> 24);
        out[4 * i + 1] = (uint8_t)(h[i] >> 16);
        out[4 * i + 2] = (uint8_t)(h[i] >> 8);
        out[4 * i + 3] = (uint8_t)(h[i]);
    }
    mw_memzero(h, sizeof(h));
    mw_memzero(buf, sizeof(buf));
}

// ===========================================================================
// Groestl-256 (512-bit state)
// ===========================================================================

// The state is a byte matrix a[row][col], stored column-major in 64 bytes:
// byte index = 8*col + row.
static void groestl_round(uint8_t s[64], int is_q, int r) {
    static const int shift_p[8] = { 0, 1, 2, 3, 4, 5, 6, 7 };
    static const int shift_q[8] = { 1, 3, 5, 7, 0, 2, 4, 6 };
    uint8_t t[64];

    // AddRoundConstant
    if (!is_q) {
        for (int j = 0; j < 8; ++j) {
            s[8 * j + 0] ^= (uint8_t)((j << 4) ^ r);
        }
    } else {
        for (int j = 0; j < 8; ++j) {
            for (int i = 0; i < 7; ++i) { s[8 * j + i] ^= 0xff; }
            s[8 * j + 7] ^= (uint8_t)(0xff ^ (j << 4) ^ r);
        }
    }

    // SubBytes + ShiftBytes
    const int* sh = is_q ? shift_q : shift_p;
    for (int i = 0; i < 8; ++i) {
        for (int j = 0; j < 8; ++j) {
            t[8 * j + i] = cn_sbox[s[8 * ((j + sh[i]) & 7) + i]];
        }
    }

    // MixBytes: circulant(02,02,03,04,05,03,05,07) applied to each column.
    static const uint8_t mm[8] = { 2, 2, 3, 4, 5, 3, 5, 7 };
    for (int j = 0; j < 8; ++j) {
        const uint8_t* col = t + 8 * j;
        for (int i = 0; i < 8; ++i) {
            uint8_t acc = 0;
            for (int k = 0; k < 8; ++k) {
                uint8_t x = col[(i + k) & 7];
                uint8_t c = mm[k];
                uint8_t p = 0;
                while (c) {
                    if (c & 1) { p ^= x; }
                    x = gmul2(x);
                    c = (uint8_t)(c >> 1);
                }
                acc ^= p;
            }
            s[8 * j + i] = acc;
        }
    }
    mw_memzero(t, sizeof(t));
}

static void groestl_perm(uint8_t s[64], int is_q) {
    for (int r = 0; r < 10; ++r) {
        groestl_round(s, is_q, r);
    }
}

static void groestl_compress(uint8_t h[64], const uint8_t m[64]) {
    uint8_t p[64], q[64];
    for (int i = 0; i < 64; ++i) {
        p[i] = (uint8_t)(h[i] ^ m[i]);
        q[i] = m[i];
    }
    groestl_perm(p, 0);
    groestl_perm(q, 1);
    for (int i = 0; i < 64; ++i) {
        h[i] ^= (uint8_t)(p[i] ^ q[i]);
    }
    mw_memzero(p, sizeof(p));
    mw_memzero(q, sizeof(q));
}

static void groestl256(const uint8_t* data, size_t len, uint8_t out[32]) {
    uint8_t h[64];
    uint8_t block[128];

    memset(h, 0, sizeof(h));
    h[62] = 0x01;   // IV = 512-bit big-endian value 256

    uint64_t nblocks = 0;
    size_t full = len / 64;
    for (size_t i = 0; i < full; ++i) {
        groestl_compress(h, data + 64 * i);
        nblocks++;
    }
    size_t rem = len - 64 * full;

    // Padding: 0x80, zeros, 64-bit big-endian total block count.
    memset(block, 0, sizeof(block));
    memcpy(block, data + 64 * full, rem);
    block[rem] = 0x80;
    size_t total = (rem + 1 + 8 <= 64) ? 64 : 128;
    uint64_t nb = nblocks + total / 64;
    for (int i = 0; i < 8; ++i) {
        block[total - 1 - i] = (uint8_t)(nb >> (8 * i));
    }
    for (size_t off = 0; off < total; off += 64) {
        groestl_compress(h, block + off);
    }

    // Output transform: trunc_256(P(h) XOR h)
    {
        uint8_t p[64];
        memcpy(p, h, 64);
        groestl_perm(p, 0);
        for (int i = 0; i < 64; ++i) { p[i] ^= h[i]; }
        memcpy(out, p + 32, 32);
        mw_memzero(p, sizeof(p));
    }
    mw_memzero(h, sizeof(h));
    mw_memzero(block, sizeof(block));
}

// ===========================================================================
// JH-256 (bitslice E8, 42 rounds)
// ===========================================================================

// JH-256 initial hash value H(0) (algorithm constant), 16 LE words.
static const uint64_t jh256_h0[16] = {
    0xebd3202c41a398ebULL, 0xc145b29c7bbecd92ULL,
    0xfac7d4609151931cULL, 0x038a507ed6820026ULL,
    0x45b92677269e23a4ULL, 0x77941ad4481afbe0ULL,
    0x7a176b0226abb5cdULL, 0xa82fff0f4224f056ULL,
    0x754d2e7f8996a371ULL, 0x62e27df70849141dULL,
    0x948f2476f7957627ULL, 0x6c29804757b6d587ULL,
    0x6c0d8eac2d275e5cULL, 0x0f7a0557c6508451ULL,
    0xea12247067d3e47bULL, 0x69d71cd313abe389ULL
};

// The 42 E8 bitslice round constants (algorithm constants), 4 LE words each.
static const uint64_t jh_rc[42][4] = {
    { 0x67f815dfa2ded572ULL, 0x571523b70a15847bULL, 0xf6875a4d90d6ab81ULL, 0x402bd1c3c54f9f4eULL },
    { 0x9cfa455ce03a98eaULL, 0x9a99b26699d2c503ULL, 0x8a53bbf2b4960266ULL, 0x31a2db881a1456b5ULL },
    { 0xdb0e199a5c5aa303ULL, 0x1044c1870ab23f40ULL, 0x1d959e848019051cULL, 0xdccde75eadeb336fULL },
    { 0x416bbf029213ba10ULL, 0xd027bbf7156578dcULL, 0x5078aa3739812c0aULL, 0xd3910041d2bf1a3fULL },
    { 0x907eccf60d5a2d42ULL, 0xce97c0929c9f62ddULL, 0xac442bc70ba75c18ULL, 0x23fcc663d665dfd1ULL },
    { 0x1ab8e09e036c6e97ULL, 0xa8ec6c447e450521ULL, 0xfa618e5dbb03f1eeULL, 0x97818394b29796fdULL },
    { 0x2f3003db37858e4aULL, 0x956a9ffb2d8d672aULL, 0x6c69b8f88173fe8aULL, 0x14427fc04672c78aULL },
    { 0xc45ec7bd8f15f4c5ULL, 0x80bb118fa76f4475ULL, 0xbc88e4aeb775de52ULL, 0xf4a3a6981e00b882ULL },
    { 0x1563a3a9338ff48eULL, 0x89f9b7d524565faaULL, 0xfde05a7c20edf1b6ULL, 0x362c42065ae9ca36ULL },
    { 0x3d98fe4e433529ceULL, 0xa74b9a7374f93a53ULL, 0x86814e6f591ff5d0ULL, 0x9f5ad8af81ad9d0eULL },
    { 0x6a6234ee670605a7ULL, 0x2717b96ebe280b8bULL, 0x3f1080c626077447ULL, 0x7b487ec66f7ea0e0ULL },
    { 0xc0a4f84aa50a550dULL, 0x9ef18e979fe7e391ULL, 0xd48d605081727686ULL, 0x62b0e5f3415a9e7eULL },
    { 0x7a205440ec1f9ffcULL, 0x84c9f4ce001ae4e3ULL, 0xd895fa9df594d74fULL, 0xa554c324117e2e55ULL },
    { 0x286efebd2872df5bULL, 0xb2c4a50fe27ff578ULL, 0x2ed349eeef7c8905ULL, 0x7f5928eb85937e44ULL },
    { 0x4a3124b337695f70ULL, 0x65e4d61df128865eULL, 0xe720b95104771bc7ULL, 0x8a87d423e843fe74ULL },
    { 0xf2947692a3e8297dULL, 0xc1d9309b097acbddULL, 0xe01bdc5bfb301b1dULL, 0xbf829cf24f4924daULL },
    { 0xffbf70b431bae7a4ULL, 0x48bcf8de0544320dULL, 0x39d3bb5332fcae3bULL, 0xa08b29e0c1c39f45ULL },
    { 0x0f09aef7fd05c9e5ULL, 0x34f1904212347094ULL, 0x95ed44e301b771a2ULL, 0x4a982f4f368e3be9ULL },
    { 0x15f66ca0631d4088ULL, 0xffaf52874b44c147ULL, 0x30c60ae2f14abb7eULL, 0xe68c6eccc5b67046ULL },
    { 0x00ca4fbd56a4d5a4ULL, 0xae183ec84b849ddaULL, 0xadd1643045ce5773ULL, 0x67255c1468cea6e8ULL },
    { 0x16e10ecbf28cdaa3ULL, 0x9a99949a5806e933ULL, 0x7b846fc220b2601fULL, 0x1885d1a07facced1ULL },
    { 0xd319dd8da15b5932ULL, 0x46b4a5aac01c9a50ULL, 0xba6b04e467633d9fULL, 0x7eee560bab19caf6ULL },
    { 0x742128a9ea79b11fULL, 0xee51363b35f7bde9ULL, 0x76d350755aac571dULL, 0x01707da3fec2463aULL },
    { 0x42d8a498afc135f7ULL, 0x79676b9e20eced78ULL, 0xa8db3aea15638341ULL, 0x832c83324d3bc3faULL },
    { 0xf347271c1f3b40a7ULL, 0x9a762db734f04059ULL, 0xfd4f21d26c4e3ee7ULL, 0xef5957dc398dfdb8ULL },
    { 0xdaeb492b490c9b8dULL, 0x0d70f36849d7a25bULL, 0x84558d7ad0ae3b7dULL, 0x658ef8e4f0e9a5f5ULL },
    { 0x533b1036f4a2b8a0ULL, 0x5aec3e759e07a80cULL, 0x4f88e85692946891ULL, 0x4cbcbaf8555cb05bULL },
    { 0x7b9487f3993bbbe3ULL, 0x5d1c6b72d6f4da75ULL, 0x6db334dc28acae64ULL, 0x71db28b850a5346cULL },
    { 0x2a518d10f2e261f8ULL, 0xfc75dd593364dbe3ULL, 0xa23fce43f1bcac1cULL, 0xb043e8023cd1bb67ULL },
    { 0x75a12988ca5b0a33ULL, 0x5c5316b44d19347fULL, 0x1e4d790ec3943b92ULL, 0x3fafeeb6d7757479ULL },
    { 0x21391abef7d4a8eaULL, 0x5127234c097ef45cULL, 0xd23c32ba5324a326ULL, 0xadd5a66d4a17a344ULL },
    { 0x08c9f2afa63e1db5ULL, 0x563c6b91983d5983ULL, 0x4d608672a17cf84cULL, 0xf6c76e08cc3ee246ULL },
    { 0x5e76bcb1b333982fULL, 0x2ae6c4efa566d62bULL, 0x36d4c1bee8b6f406ULL, 0x6321efbc1582ee74ULL },
    { 0x69c953f40d4ec1fdULL, 0x26585806c45a7da7ULL, 0x16fae0061614c17eULL, 0x3f9d63283daf907eULL },
    { 0x0cd29b00e3f2c9d2ULL, 0x300cd4b730ceaa5fULL, 0x9832e0f216512a74ULL, 0x9af8cee3d830eb0dULL },
    { 0x9279f1b57b9ec54bULL, 0xd36886046ee651ffULL, 0x316796e6574d239bULL, 0x05750a17f3a6e6ccULL },
    { 0xce6c3213d98176b1ULL, 0x62a205f88452173cULL, 0x47154778b3cb2bf4ULL, 0x486a9323825446ffULL },
    { 0x65655e4e0758df38ULL, 0x8e5086fc897cfcf2ULL, 0x86ca0bd0442e7031ULL, 0x4e477830a20940f0ULL },
    { 0x8338f7d139eea065ULL, 0xbd3a2ce437e95ef7ULL, 0x6ff8130126b29721ULL, 0xe7de9fefd1ed44a3ULL },
    { 0xd992257615dfa08bULL, 0xbe42dc12f6f7853cULL, 0x7eb027ab7ceca7d8ULL, 0xdea83eaada7d8d53ULL },
    { 0xd86902bd93ce25aaULL, 0xf908731afd43f65aULL, 0xa5194a17daef5fc0ULL, 0x6a21fd4c33664d97ULL },
    { 0x701541db3198b435ULL, 0x9b54cdedbb0f1eeaULL, 0x72409751a163d09aULL, 0xe26f4791bf9d75f6ULL }
};

static inline uint64_t jh_swap(uint64_t x, int k) {
    // Swaps adjacent groups of 2^k bits.
    static const uint64_t mask[6] = {
        0x5555555555555555ULL, 0x3333333333333333ULL, 0x0f0f0f0f0f0f0f0fULL,
        0x00ff00ff00ff00ffULL, 0x0000ffff0000ffffULL, 0x00000000ffffffffULL
    };
    int n = 1 << k;
    return ((x & mask[k]) << n) | ((x >> n) & mask[k]);
}

#define JH_SS(m0, m1, m2, m3, m4, m5, m6, m7, cc0, cc1) \
    m3  = ~(m3);                                        \
    m7  = ~(m7);                                        \
    m0 ^= ((~(m2)) & (cc0));                            \
    m4 ^= ((~(m6)) & (cc1));                            \
    t0  = (cc0) ^ ((m0) & (m1));                        \
    t1  = (cc1) ^ ((m4) & (m5));                        \
    m0 ^= ((m2) & (m3));                                \
    m4 ^= ((m6) & (m7));                                \
    m3 ^= ((~(m1)) & (m2));                             \
    m7 ^= ((~(m5)) & (m6));                             \
    m1 ^= ((m0) & (m2));                                \
    m5 ^= ((m4) & (m6));                                \
    m2 ^= ((m0) & (~(m3)));                             \
    m6 ^= ((m4) & (~(m7)));                             \
    m0 ^= ((m1) | (m3));                                \
    m4 ^= ((m5) | (m7));                                \
    m3 ^= ((m1) & (m2));                                \
    m7 ^= ((m5) & (m6));                                \
    m1 ^= (t0 & (m0));                                  \
    m5 ^= (t1 & (m4));                                  \
    m2 ^= t0;                                           \
    m6 ^= t1;

#define JH_L(m0, m1, m2, m3, m4, m5, m6, m7) \
    (m4) ^= (m1);                            \
    (m5) ^= (m2);                            \
    (m6) ^= (m0) ^ (m3);                     \
    (m7) ^= (m0);                            \
    (m0) ^= (m5);                            \
    (m1) ^= (m6);                            \
    (m2) ^= (m4) ^ (m7);                     \
    (m3) ^= (m4);

// x is the 1024-bit state as x[row][half], row 0..7, half 0..1.
static void jh_e8(uint64_t x[8][2]) {
    uint64_t t0, t1;

    for (int round = 0; round < 42; round += 7) {
        for (int k = 0; k < 6; ++k) {
            for (int i = 0; i < 2; ++i) {
                JH_SS(x[0][i], x[2][i], x[4][i], x[6][i],
                      x[1][i], x[3][i], x[5][i], x[7][i],
                      jh_rc[round + k][i], jh_rc[round + k][i + 2])
                JH_L(x[0][i], x[2][i], x[4][i], x[6][i],
                     x[1][i], x[3][i], x[5][i], x[7][i])
                x[1][i] = jh_swap(x[1][i], k);
                x[3][i] = jh_swap(x[3][i], k);
                x[5][i] = jh_swap(x[5][i], k);
                x[7][i] = jh_swap(x[7][i], k);
            }
        }
        for (int i = 0; i < 2; ++i) {
            JH_SS(x[0][i], x[2][i], x[4][i], x[6][i],
                  x[1][i], x[3][i], x[5][i], x[7][i],
                  jh_rc[round + 6][i], jh_rc[round + 6][i + 2])
            JH_L(x[0][i], x[2][i], x[4][i], x[6][i],
                 x[1][i], x[3][i], x[5][i], x[7][i])
        }
        // Final swapping layer of the group: exchange the two 64-bit halves
        // of every odd row.
        for (int r = 1; r < 8; r += 2) {
            uint64_t tmp = x[r][0]; x[r][0] = x[r][1]; x[r][1] = tmp;
        }
    }
}

static inline uint64_t cn_load64_le(const uint8_t* p) {
    uint64_t v = 0;
    for (int i = 0; i < 8; ++i) { v |= (uint64_t)p[i] << (8 * i); }
    return v;
}

static inline void cn_store64_le(uint8_t* p, uint64_t v) {
    for (int i = 0; i < 8; ++i) { p[i] = (uint8_t)(v >> (8 * i)); }
}

static void jh_f8(uint64_t x[8][2], const uint8_t block[64]) {
    uint64_t* flat = &x[0][0];
    for (int i = 0; i < 8; ++i) {
        flat[i] ^= cn_load64_le(block + 8 * i);
    }
    jh_e8(x);
    for (int i = 0; i < 8; ++i) {
        flat[i + 8] ^= cn_load64_le(block + 8 * i);
    }
}

static void jh256(const uint8_t* data, size_t len, uint8_t out[32]) {
    uint64_t x[8][2];
    uint8_t  block[64];
    uint64_t bits = (uint64_t)len * 8u;

    memcpy(&x[0][0], jh256_h0, sizeof(x));

    size_t full = len / 64;
    for (size_t i = 0; i < full; ++i) {
        jh_f8(x, data + 64 * i);
    }
    size_t rem = len - 64 * full;

    if (rem == 0) {
        // Length is an exact multiple of 512 bits (zero included): the padding
        // fits in a single extra block.
        memset(block, 0, 64);
        block[0] = 0x80;
        for (int i = 0; i < 8; ++i) { block[63 - i] = (uint8_t)(bits >> (8 * i)); }
        jh_f8(x, block);
    } else {
        memset(block, 0, 64);
        memcpy(block, data + 64 * full, rem);
        block[rem] |= 0x80;
        jh_f8(x, block);
        memset(block, 0, 64);
        for (int i = 0; i < 8; ++i) { block[63 - i] = (uint8_t)(bits >> (8 * i)); }
        jh_f8(x, block);
    }

    // Digest = bytes 96..128 of the 128-byte state.
    for (int i = 0; i < 4; ++i) {
        cn_store64_le(out + 8 * i, (&x[0][0])[12 + i]);
    }
    mw_memzero(x, sizeof(x));
    mw_memzero(block, sizeof(block));
}

// ===========================================================================
// Skein-512-256 (Threefish-512 in UBI mode)
// ===========================================================================

#define SKEIN_KS_PARITY 0x1BD11BDAA9FC1A22ULL

static const uint64_t skein512_iv_256[8] = {
    0xCCD044A12FDB3E13ULL, 0xE83590301A79A9EBULL,
    0x55AEA0614F816E6FULL, 0x2A2767A4AE9B94DBULL,
    0xEC06025E74DD7683ULL, 0xE7A436CDC4746251ULL,
    0xC36FBAF9393AD185ULL, 0x3EEDBA1833EDFC13ULL
};

static const uint8_t skein_rot[8][4] = {
    { 46, 36, 19, 37 }, { 33, 27, 14, 42 }, { 17, 49, 36, 39 }, { 44,  9, 54, 56 },
    { 39, 30, 34, 24 }, { 13, 50, 10, 17 }, { 25, 29, 39, 43 }, {  8, 35, 56, 22 }
};

static const uint8_t skein_perm[8] = { 2, 1, 4, 7, 6, 5, 0, 3 };

static inline uint64_t rotl64c(uint64_t x, int n) {
    return (x << n) | (x >> (64 - n));
}

// G = threefish_encrypt(G, tweak, block) XOR block
static void skein_ubi_block(uint64_t g[8], const uint8_t block[64],
                            const uint64_t tweak[2]) {
    uint64_t ks[9], ts[3], x[8], p[8], m[8];

    for (int i = 0; i < 8; ++i) { m[i] = cn_load64_le(block + 8 * i); }

    ks[8] = SKEIN_KS_PARITY;
    for (int i = 0; i < 8; ++i) {
        ks[i] = g[i];
        ks[8] ^= g[i];
    }
    ts[0] = tweak[0];
    ts[1] = tweak[1];
    ts[2] = tweak[0] ^ tweak[1];

    for (int i = 0; i < 8; ++i) { x[i] = m[i]; }

    for (int d = 0; d <= 18; ++d) {
        // Subkey injection before each group of four rounds.
        for (int i = 0; i < 8; ++i) { x[i] += ks[(d + i) % 9]; }
        x[5] += ts[d % 3];
        x[6] += ts[(d + 1) % 3];
        x[7] += (uint64_t)d;
        if (d == 18) { break; }

        for (int r = 0; r < 4; ++r) {
            int rd = 4 * d + r;
            for (int j = 0; j < 4; ++j) {
                x[2 * j] += x[2 * j + 1];
                x[2 * j + 1] = rotl64c(x[2 * j + 1], skein_rot[rd % 8][j]);
                x[2 * j + 1] ^= x[2 * j];
            }
            for (int i = 0; i < 8; ++i) { p[i] = x[skein_perm[i]]; }
            for (int i = 0; i < 8; ++i) { x[i] = p[i]; }
        }
    }

    for (int i = 0; i < 8; ++i) { g[i] = x[i] ^ m[i]; }

    mw_memzero(ks, sizeof(ks)); mw_memzero(ts, sizeof(ts));
    mw_memzero(x, sizeof(x));   mw_memzero(p, sizeof(p));
    mw_memzero(m, sizeof(m));
}

#define SKEIN_T1_FIRST (1ULL << 62)
#define SKEIN_T1_FINAL (1ULL << 63)
#define SKEIN_T1_TYPE(t) ((uint64_t)(t) << 56)

// One complete UBI chain over `len` bytes of `data` with the given block type.
static void skein_ubi(uint64_t g[8], const uint8_t* data, size_t len, int type) {
    uint8_t  block[64];
    uint64_t tweak[2];
    uint64_t pos = 0;
    int      first = 1;

    if (len == 0) {
        memset(block, 0, sizeof(block));
        tweak[0] = 0;
        tweak[1] = SKEIN_T1_TYPE(type) | SKEIN_T1_FIRST | SKEIN_T1_FINAL;
        skein_ubi_block(g, block, tweak);
        return;
    }

    while (len > 0) {
        size_t take = (len > 64) ? 64 : len;
        int    final = (len <= 64);
        memset(block, 0, sizeof(block));
        memcpy(block, data, take);
        pos += take;
        tweak[0] = pos;
        tweak[1] = SKEIN_T1_TYPE(type) |
                   (first ? SKEIN_T1_FIRST : 0) |
                   (final ? SKEIN_T1_FINAL : 0);
        skein_ubi_block(g, block, tweak);
        data  += take;
        len   -= take;
        first  = 0;
    }
    mw_memzero(block, sizeof(block));
}

static void skein512_256(const uint8_t* data, size_t len, uint8_t out[32]) {
    uint64_t g[8];
    uint8_t  counter[8];

    memcpy(g, skein512_iv_256, sizeof(g));
    skein_ubi(g, data, len, 48);              // SKEIN_BLK_TYPE_MSG

    memset(counter, 0, sizeof(counter));
    skein_ubi(g, counter, sizeof(counter), 63);   // SKEIN_BLK_TYPE_OUT

    for (int i = 0; i < 4; ++i) {
        cn_store64_le(out + 8 * i, g[i]);
    }
    mw_memzero(g, sizeof(g));
}

// ===========================================================================
// CryptoNight variant 0
// ===========================================================================

// The scratchpad is allocated once at boot (PSRAM on the ESP32-S3) so that
// signing can never fail on a late 2 MiB allocation.
static uint8_t* g_cn_scratchpad = NULL;
static int      g_cn_scratchpad_owned = 0;

int mw_cn_slow_hash_init(void) {
    if (g_cn_scratchpad != NULL) {
        return 0;
    }
#if !defined(MW_HOST_BUILD) && defined(ARDUINO)
    // TZ 1.4: the scratchpad MUST live in PSRAM, internal RAM is far too small.
    g_cn_scratchpad = (uint8_t*)heap_caps_malloc(CN_MEMORY, MALLOC_CAP_SPIRAM);
    if (g_cn_scratchpad == NULL) {
        g_cn_scratchpad = (uint8_t*)heap_caps_malloc(CN_MEMORY, MALLOC_CAP_8BIT);
    }
#else
    g_cn_scratchpad = (uint8_t*)malloc(CN_MEMORY);
#endif
    if (g_cn_scratchpad == NULL) {
        return -1;
    }
    g_cn_scratchpad_owned = 1;
    return 0;
}

void mw_cn_slow_hash_free(void) {
    if (g_cn_scratchpad != NULL && g_cn_scratchpad_owned) {
        mw_memzero(g_cn_scratchpad, CN_MEMORY);
        free(g_cn_scratchpad);
    }
    g_cn_scratchpad = NULL;
    g_cn_scratchpad_owned = 0;
}

// 64 x 64 -> 128 bit multiply, portable.
static void cn_mul128(uint64_t a, uint64_t b, uint64_t* hi, uint64_t* lo) {
#if defined(__SIZEOF_INT128__)
    unsigned __int128 p = (unsigned __int128)a * (unsigned __int128)b;
    *lo = (uint64_t)p;
    *hi = (uint64_t)(p >> 64);
#else
    uint64_t a0 = a & 0xffffffffULL, a1 = a >> 32;
    uint64_t b0 = b & 0xffffffffULL, b1 = b >> 32;
    uint64_t p00 = a0 * b0;
    uint64_t p01 = a0 * b1;
    uint64_t p10 = a1 * b0;
    uint64_t p11 = a1 * b1;
    uint64_t mid = (p00 >> 32) + (p01 & 0xffffffffULL) + (p10 & 0xffffffffULL);
    *lo = (p00 & 0xffffffffULL) | (mid << 32);
    *hi = p11 + (p01 >> 32) + (p10 >> 32) + (mid >> 32);
#endif
}

static inline size_t cn_e2i(const uint8_t a[16]) {
    return (size_t)((cn_load64_le(a) / CN_AES_BLOCK) & (CN_MEMORY / CN_AES_BLOCK - 1));
}

static mw_cn_progress_cb g_cn_progress = NULL;
static void*             g_cn_progress_user = NULL;

void mw_cn_slow_hash_set_progress(mw_cn_progress_cb cb, void* user) {
    g_cn_progress = cb;
    g_cn_progress_user = user;
}

static inline void cn_progress(int permille) {
    if (g_cn_progress) g_cn_progress(permille, g_cn_progress_user);
}

int mw_cn_slow_hash(const void* data, size_t len, uint8_t hash[32]) {
    uint8_t  state[200];
    uint8_t  text[CN_INIT_SIZE_BYTE];
    uint8_t  expanded[240];
    uint8_t  a[16], a1[16], b[16], c1[16], c2[16], d[16];
    uint8_t* sp;
    int      allocated_here = 0;

    if (g_cn_scratchpad == NULL) {
        if (mw_cn_slow_hash_init() != 0) {
            return -1;
        }
        allocated_here = 1;
    }
    sp = g_cn_scratchpad;

    // --- 1. Keccak the input into the 200-byte state -----------------------
    mw_keccak1600((const uint8_t*)data, len, state);
    memcpy(text, state + 64, CN_INIT_SIZE_BYTE);

    // --- 2. Fill the scratchpad -------------------------------------------
    aes_expand_key_256(state, expanded);
    cn_progress(0);
    for (size_t i = 0; i < CN_MEMORY / CN_INIT_SIZE_BYTE; ++i) {
        if ((i & 2047u) == 0) {
            cn_progress((int)(100u * i / (CN_MEMORY / CN_INIT_SIZE_BYTE)));
        }
        for (size_t j = 0; j < CN_INIT_SIZE_BLK; ++j) {
            aes_pseudo_round(text + CN_AES_BLOCK * j, expanded);
        }
        memcpy(sp + i * CN_INIT_SIZE_BYTE, text, CN_INIT_SIZE_BYTE);
    }

    for (int i = 0; i < 16; ++i) {
        a[i] = (uint8_t)(state[i] ^ state[32 + i]);
        b[i] = (uint8_t)(state[16 + i] ^ state[48 + i]);
    }

    // --- 3. Memory-hard loop ----------------------------------------------
    for (uint32_t iter = 0; iter < CN_ITER / 2; ++iter) {
        size_t j;
        if ((iter & 8191u) == 0) {
            cn_progress((int)(100u + (uint32_t)(800ull * iter / (CN_ITER / 2))));
        }

        // Iteration 1: one AES round keyed with `a`, result mixed with `b`.
        j = cn_e2i(a) * CN_AES_BLOCK;
        aes_round(c1, sp + j, a);
        memcpy(sp + j, c1, 16);
        for (int i = 0; i < 16; ++i) { sp[j + i] ^= b[i]; }

        // Iteration 2: 64x64->128 multiply and a 128-bit add.
        j = cn_e2i(c1) * CN_AES_BLOCK;
        memcpy(c2, sp + j, 16);
        memcpy(a1, a, 16);
        {
            uint64_t hi, lo;
            cn_mul128(cn_load64_le(c1), cn_load64_le(c2), &hi, &lo);
            cn_store64_le(d, hi);
            cn_store64_le(d + 8, lo);
        }
        {
            uint64_t a0 = cn_load64_le(a1) + cn_load64_le(d);
            uint64_t aa1 = cn_load64_le(a1 + 8) + cn_load64_le(d + 8);
            cn_store64_le(a1, a0);
            cn_store64_le(a1 + 8, aa1);
        }
        // swap_blocks(a1, c2) followed by xor_blocks(a1, c2)
        {
            uint8_t tmp[16];
            memcpy(tmp, a1, 16);
            memcpy(a1, c2, 16);
            memcpy(c2, tmp, 16);
            for (int i = 0; i < 16; ++i) { a1[i] ^= c2[i]; }
            mw_memzero(tmp, sizeof(tmp));
        }
        memcpy(sp + j, c2, 16);
        memcpy(b, c1, 16);
        memcpy(a, a1, 16);
    }

    // --- 4. Fold the scratchpad back into the state ------------------------
    memcpy(text, state + 64, CN_INIT_SIZE_BYTE);
    aes_expand_key_256(state + 32, expanded);
    for (size_t i = 0; i < CN_MEMORY / CN_INIT_SIZE_BYTE; ++i) {
        if ((i & 2047u) == 0) {
            cn_progress((int)(900u + 100u * i / (CN_MEMORY / CN_INIT_SIZE_BYTE)));
        }
        for (size_t j = 0; j < CN_INIT_SIZE_BLK; ++j) {
            uint8_t* blk = text + j * CN_AES_BLOCK;
            const uint8_t* src = sp + i * CN_INIT_SIZE_BYTE + j * CN_AES_BLOCK;
            for (int k = 0; k < 16; ++k) { blk[k] ^= src[k]; }
            aes_pseudo_round(blk, expanded);
        }
    }
    memcpy(state + 64, text, CN_INIT_SIZE_BYTE);
    mw_keccak_permute_bytes(state);

    // --- 5. Finalizer selected by the low two bits of the state ------------
    switch (state[0] & 3) {
        case 0: blake256(state, sizeof(state), hash);    break;
        case 1: groestl256(state, sizeof(state), hash);  break;
        case 2: jh256(state, sizeof(state), hash);       break;
        default: skein512_256(state, sizeof(state), hash); break;
    }

    mw_memzero(state, sizeof(state));
    mw_memzero(text, sizeof(text));
    mw_memzero(expanded, sizeof(expanded));
    mw_memzero(a, sizeof(a));   mw_memzero(a1, sizeof(a1));
    mw_memzero(b, sizeof(b));   mw_memzero(c1, sizeof(c1));
    mw_memzero(c2, sizeof(c2)); mw_memzero(d, sizeof(d));
    if (allocated_here) {
        mw_cn_slow_hash_free();
    } else {
        // The scratchpad stays allocated for the next call, but its 2 MiB are
        // derived from the input (passphrase, view key): never leave them in
        // PSRAM, which sits on an unencrypted bus (security.md 6.1).
        mw_memzero(sp, CN_MEMORY);
    }
    return 0;
}
