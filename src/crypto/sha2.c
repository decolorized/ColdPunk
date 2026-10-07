// SHA-256 and SHA-512 (FIPS 180-4). Platform independent.
#include "hash.h"
#include "memzero.h"

#include <string.h>

// ======================= SHA-256 ==========================================

static const uint32_t sha256_k[64] = {
    0x428a2f98UL, 0x71374491UL, 0xb5c0fbcfUL, 0xe9b5dba5UL,
    0x3956c25bUL, 0x59f111f1UL, 0x923f82a4UL, 0xab1c5ed5UL,
    0xd807aa98UL, 0x12835b01UL, 0x243185beUL, 0x550c7dc3UL,
    0x72be5d74UL, 0x80deb1feUL, 0x9bdc06a7UL, 0xc19bf174UL,
    0xe49b69c1UL, 0xefbe4786UL, 0x0fc19dc6UL, 0x240ca1ccUL,
    0x2de92c6fUL, 0x4a7484aaUL, 0x5cb0a9dcUL, 0x76f988daUL,
    0x983e5152UL, 0xa831c66dUL, 0xb00327c8UL, 0xbf597fc7UL,
    0xc6e00bf3UL, 0xd5a79147UL, 0x06ca6351UL, 0x14292967UL,
    0x27b70a85UL, 0x2e1b2138UL, 0x4d2c6dfcUL, 0x53380d13UL,
    0x650a7354UL, 0x766a0abbUL, 0x81c2c92eUL, 0x92722c85UL,
    0xa2bfe8a1UL, 0xa81a664bUL, 0xc24b8b70UL, 0xc76c51a3UL,
    0xd192e819UL, 0xd6990624UL, 0xf40e3585UL, 0x106aa070UL,
    0x19a4c116UL, 0x1e376c08UL, 0x2748774cUL, 0x34b0bcb5UL,
    0x391c0cb3UL, 0x4ed8aa4aUL, 0x5b9cca4fUL, 0x682e6ff3UL,
    0x748f82eeUL, 0x78a5636fUL, 0x84c87814UL, 0x8cc70208UL,
    0x90befffaUL, 0xa4506cebUL, 0xbef9a3f7UL, 0xc67178f2UL
};

static inline uint32_t rotr32(uint32_t x, int n) {
    return (x >> n) | (x << (32 - n));
}

#define S256_0(x) (rotr32(x,  2) ^ rotr32(x, 13) ^ rotr32(x, 22))
#define S256_1(x) (rotr32(x,  6) ^ rotr32(x, 11) ^ rotr32(x, 25))
#define s256_0(x) (rotr32(x,  7) ^ rotr32(x, 18) ^ ((x) >>  3))
#define s256_1(x) (rotr32(x, 17) ^ rotr32(x, 19) ^ ((x) >> 10))
#define CH(x,y,z)  (((x) & (y)) ^ ((~(x)) & (z)))
#define MAJ(x,y,z) (((x) & (y)) ^ ((x) & (z)) ^ ((y) & (z)))

static void sha256_compress(uint32_t h[8], const uint8_t block[64]) {
    uint32_t w[64];
    uint32_t a, b, c, d, e, f, g, hh;

    for (int i = 0; i < 16; ++i) {
        w[i] = ((uint32_t)block[4 * i]     << 24) |
               ((uint32_t)block[4 * i + 1] << 16) |
               ((uint32_t)block[4 * i + 2] <<  8) |
               ((uint32_t)block[4 * i + 3]);
    }
    for (int i = 16; i < 64; ++i) {
        w[i] = s256_1(w[i - 2]) + w[i - 7] + s256_0(w[i - 15]) + w[i - 16];
    }

    a = h[0]; b = h[1]; c = h[2]; d = h[3];
    e = h[4]; f = h[5]; g = h[6]; hh = h[7];

    for (int i = 0; i < 64; ++i) {
        uint32_t t1 = hh + S256_1(e) + CH(e, f, g) + sha256_k[i] + w[i];
        uint32_t t2 = S256_0(a) + MAJ(a, b, c);
        hh = g; g = f; f = e; e = d + t1;
        d = c; c = b; b = a; a = t1 + t2;
    }

    h[0] += a; h[1] += b; h[2] += c; h[3] += d;
    h[4] += e; h[5] += f; h[6] += g; h[7] += hh;

    mw_memzero(w, sizeof(w));
}

void mw_sha256_init(mw_sha256_ctx* ctx) {
    ctx->h[0] = 0x6a09e667UL; ctx->h[1] = 0xbb67ae85UL;
    ctx->h[2] = 0x3c6ef372UL; ctx->h[3] = 0xa54ff53aUL;
    ctx->h[4] = 0x510e527fUL; ctx->h[5] = 0x9b05688cUL;
    ctx->h[6] = 0x1f83d9abUL; ctx->h[7] = 0x5be0cd19UL;
    ctx->buf_len = 0;
    ctx->total   = 0;
    memset(ctx->buf, 0, sizeof(ctx->buf));
}

void mw_sha256_update(mw_sha256_ctx* ctx, const uint8_t* data, size_t len) {
    if (len == 0 || data == NULL) {
        return;
    }
    ctx->total += (uint64_t)len;

    if (ctx->buf_len > 0) {
        size_t want = MW_SHA256_BLOCK - ctx->buf_len;
        size_t take = (len < want) ? len : want;
        memcpy(ctx->buf + ctx->buf_len, data, take);
        ctx->buf_len += take;
        data += take;
        len  -= take;
        if (ctx->buf_len == MW_SHA256_BLOCK) {
            sha256_compress(ctx->h, ctx->buf);
            ctx->buf_len = 0;
        }
    }
    while (len >= MW_SHA256_BLOCK) {
        sha256_compress(ctx->h, data);
        data += MW_SHA256_BLOCK;
        len  -= MW_SHA256_BLOCK;
    }
    if (len > 0) {
        memcpy(ctx->buf, data, len);
        ctx->buf_len = len;
    }
}

void mw_sha256_final(mw_sha256_ctx* ctx, uint8_t out[MW_SHA256_DIGEST]) {
    uint64_t bits = ctx->total * 8u;
    uint8_t  pad[MW_SHA256_BLOCK * 2];
    size_t   pad_len;

    memset(pad, 0, sizeof(pad));
    pad[0] = 0x80;
    // Total length must end up congruent to 56 mod 64.
    pad_len = (ctx->buf_len < 56) ? (56 - ctx->buf_len)
                                  : (120 - ctx->buf_len);
    for (int i = 0; i < 8; ++i) {
        pad[pad_len + i] = (uint8_t)(bits >> (56 - 8 * i));
    }
    mw_sha256_update(ctx, pad, pad_len + 8);

    for (int i = 0; i < 8; ++i) {
        out[4 * i]     = (uint8_t)(ctx->h[i] >> 24);
        out[4 * i + 1] = (uint8_t)(ctx->h[i] >> 16);
        out[4 * i + 2] = (uint8_t)(ctx->h[i] >>  8);
        out[4 * i + 3] = (uint8_t)(ctx->h[i]);
    }
    mw_memzero(ctx, sizeof(*ctx));
}

void mw_sha256(const uint8_t* data, size_t len, uint8_t out[MW_SHA256_DIGEST]) {
    mw_sha256_ctx ctx;
    mw_sha256_init(&ctx);
    mw_sha256_update(&ctx, data, len);
    mw_sha256_final(&ctx, out);
}

// ======================= SHA-512 ==========================================

static const uint64_t sha512_k[80] = {
    0x428a2f98d728ae22ULL, 0x7137449123ef65cdULL, 0xb5c0fbcfec4d3b2fULL,
    0xe9b5dba58189dbbcULL, 0x3956c25bf348b538ULL, 0x59f111f1b605d019ULL,
    0x923f82a4af194f9bULL, 0xab1c5ed5da6d8118ULL, 0xd807aa98a3030242ULL,
    0x12835b0145706fbeULL, 0x243185be4ee4b28cULL, 0x550c7dc3d5ffb4e2ULL,
    0x72be5d74f27b896fULL, 0x80deb1fe3b1696b1ULL, 0x9bdc06a725c71235ULL,
    0xc19bf174cf692694ULL, 0xe49b69c19ef14ad2ULL, 0xefbe4786384f25e3ULL,
    0x0fc19dc68b8cd5b5ULL, 0x240ca1cc77ac9c65ULL, 0x2de92c6f592b0275ULL,
    0x4a7484aa6ea6e483ULL, 0x5cb0a9dcbd41fbd4ULL, 0x76f988da831153b5ULL,
    0x983e5152ee66dfabULL, 0xa831c66d2db43210ULL, 0xb00327c898fb213fULL,
    0xbf597fc7beef0ee4ULL, 0xc6e00bf33da88fc2ULL, 0xd5a79147930aa725ULL,
    0x06ca6351e003826fULL, 0x142929670a0e6e70ULL, 0x27b70a8546d22ffcULL,
    0x2e1b21385c26c926ULL, 0x4d2c6dfc5ac42aedULL, 0x53380d139d95b3dfULL,
    0x650a73548baf63deULL, 0x766a0abb3c77b2a8ULL, 0x81c2c92e47edaee6ULL,
    0x92722c851482353bULL, 0xa2bfe8a14cf10364ULL, 0xa81a664bbc423001ULL,
    0xc24b8b70d0f89791ULL, 0xc76c51a30654be30ULL, 0xd192e819d6ef5218ULL,
    0xd69906245565a910ULL, 0xf40e35855771202aULL, 0x106aa07032bbd1b8ULL,
    0x19a4c116b8d2d0c8ULL, 0x1e376c085141ab53ULL, 0x2748774cdf8eeb99ULL,
    0x34b0bcb5e19b48a8ULL, 0x391c0cb3c5c95a63ULL, 0x4ed8aa4ae3418acbULL,
    0x5b9cca4f7763e373ULL, 0x682e6ff3d6b2b8a3ULL, 0x748f82ee5defb2fcULL,
    0x78a5636f43172f60ULL, 0x84c87814a1f0ab72ULL, 0x8cc702081a6439ecULL,
    0x90befffa23631e28ULL, 0xa4506cebde82bde9ULL, 0xbef9a3f7b2c67915ULL,
    0xc67178f2e372532bULL, 0xca273eceea26619cULL, 0xd186b8c721c0c207ULL,
    0xeada7dd6cde0eb1eULL, 0xf57d4f7fee6ed178ULL, 0x06f067aa72176fbaULL,
    0x0a637dc5a2c898a6ULL, 0x113f9804bef90daeULL, 0x1b710b35131c471bULL,
    0x28db77f523047d84ULL, 0x32caab7b40c72493ULL, 0x3c9ebe0a15c9bebcULL,
    0x431d67c49c100d4cULL, 0x4cc5d4becb3e42b6ULL, 0x597f299cfc657e2aULL,
    0x5fcb6fab3ad6faecULL, 0x6c44198c4a475817ULL
};

static inline uint64_t rotr64(uint64_t x, int n) {
    return (x >> n) | (x << (64 - n));
}

#define S512_0(x) (rotr64(x, 28) ^ rotr64(x, 34) ^ rotr64(x, 39))
#define S512_1(x) (rotr64(x, 14) ^ rotr64(x, 18) ^ rotr64(x, 41))
#define s512_0(x) (rotr64(x,  1) ^ rotr64(x,  8) ^ ((x) >>  7))
#define s512_1(x) (rotr64(x, 19) ^ rotr64(x, 61) ^ ((x) >>  6))

static void sha512_compress(uint64_t h[8], const uint8_t block[128]) {
    uint64_t w[80];
    uint64_t a, b, c, d, e, f, g, hh;

    for (int i = 0; i < 16; ++i) {
        uint64_t v = 0;
        for (int j = 0; j < 8; ++j) {
            v = (v << 8) | (uint64_t)block[8 * i + j];
        }
        w[i] = v;
    }
    for (int i = 16; i < 80; ++i) {
        w[i] = s512_1(w[i - 2]) + w[i - 7] + s512_0(w[i - 15]) + w[i - 16];
    }

    a = h[0]; b = h[1]; c = h[2]; d = h[3];
    e = h[4]; f = h[5]; g = h[6]; hh = h[7];

    for (int i = 0; i < 80; ++i) {
        uint64_t t1 = hh + S512_1(e) + CH(e, f, g) + sha512_k[i] + w[i];
        uint64_t t2 = S512_0(a) + MAJ(a, b, c);
        hh = g; g = f; f = e; e = d + t1;
        d = c; c = b; b = a; a = t1 + t2;
    }

    h[0] += a; h[1] += b; h[2] += c; h[3] += d;
    h[4] += e; h[5] += f; h[6] += g; h[7] += hh;

    mw_memzero(w, sizeof(w));
}

void mw_sha512_init(mw_sha512_ctx* ctx) {
    ctx->h[0] = 0x6a09e667f3bcc908ULL; ctx->h[1] = 0xbb67ae8584caa73bULL;
    ctx->h[2] = 0x3c6ef372fe94f82bULL; ctx->h[3] = 0xa54ff53a5f1d36f1ULL;
    ctx->h[4] = 0x510e527fade682d1ULL; ctx->h[5] = 0x9b05688c2b3e6c1fULL;
    ctx->h[6] = 0x1f83d9abfb41bd6bULL; ctx->h[7] = 0x5be0cd19137e2179ULL;
    ctx->buf_len = 0;
    ctx->total   = 0;
    memset(ctx->buf, 0, sizeof(ctx->buf));
}

void mw_sha512_update(mw_sha512_ctx* ctx, const uint8_t* data, size_t len) {
    if (len == 0 || data == NULL) {
        return;
    }
    ctx->total += (uint64_t)len;

    if (ctx->buf_len > 0) {
        size_t want = MW_SHA512_BLOCK - ctx->buf_len;
        size_t take = (len < want) ? len : want;
        memcpy(ctx->buf + ctx->buf_len, data, take);
        ctx->buf_len += take;
        data += take;
        len  -= take;
        if (ctx->buf_len == MW_SHA512_BLOCK) {
            sha512_compress(ctx->h, ctx->buf);
            ctx->buf_len = 0;
        }
    }
    while (len >= MW_SHA512_BLOCK) {
        sha512_compress(ctx->h, data);
        data += MW_SHA512_BLOCK;
        len  -= MW_SHA512_BLOCK;
    }
    if (len > 0) {
        memcpy(ctx->buf, data, len);
        ctx->buf_len = len;
    }
}

void mw_sha512_final(mw_sha512_ctx* ctx, uint8_t out[MW_SHA512_DIGEST]) {
    // Messages longer than 2^61 bytes are impossible on this device, so the
    // high 64 bits of the 128-bit length field are always zero.
    uint64_t bits = ctx->total * 8u;
    uint8_t  pad[MW_SHA512_BLOCK * 2];
    size_t   pad_len;

    memset(pad, 0, sizeof(pad));
    pad[0] = 0x80;
    pad_len = (ctx->buf_len < 112) ? (112 - ctx->buf_len)
                                   : (240 - ctx->buf_len);
    for (int i = 0; i < 8; ++i) {
        pad[pad_len + 8 + i] = (uint8_t)(bits >> (56 - 8 * i));
    }
    mw_sha512_update(ctx, pad, pad_len + 16);

    for (int i = 0; i < 8; ++i) {
        for (int j = 0; j < 8; ++j) {
            out[8 * i + j] = (uint8_t)(ctx->h[i] >> (56 - 8 * j));
        }
    }
    mw_memzero(ctx, sizeof(*ctx));
}

void mw_sha512(const uint8_t* data, size_t len, uint8_t out[MW_SHA512_DIGEST]) {
    mw_sha512_ctx ctx;
    mw_sha512_init(&ctx);
    mw_sha512_update(&ctx, data, len);
    mw_sha512_final(&ctx, out);
}
