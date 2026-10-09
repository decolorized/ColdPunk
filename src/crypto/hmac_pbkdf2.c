// HMAC-SHA256/512 (RFC 2104), PBKDF2 (RFC 8018) and CRC32 (IEEE).
#include "hash.h"
#include "memzero.h"

#include <stdlib.h>
#include <string.h>

#if defined(ARDUINO) && !defined(MW_HOST_BUILD)
#include "esp_system.h"
#include "sdkconfig.h"
#if CONFIG_IDF_TARGET_ESP32S3
#define MW_PBKDF2_HW 1
#include "sha/sha_core.h"
#include "hal/sha_hal.h"
#endif
#endif

// Progress of long derivations (device password: 200 000 rounds). The hook,
// when set, is told about every MW_PBKDF2_TICK iterations done.
#define MW_PBKDF2_TICK 1024u
static mw_pbkdf2_progress_fn g_prog;
static void*                 g_prog_ctx;

void mw_pbkdf2_set_progress(mw_pbkdf2_progress_fn fn, void* ctx) {
    g_prog     = fn;
    g_prog_ctx = ctx;
}

static void pbkdf2_fatal(void) {
#if defined(ARDUINO) && !defined(MW_HOST_BUILD)
    esp_system_abort("pbkdf2: out of memory");
#else
    abort();
#endif
}

// Salts longer than this fall back to the heap; wallet salts are far shorter.
#define MW_PBKDF2_SALT_STACK 128

// ---------------------------- HMAC ----------------------------------------

void mw_hmac_sha256(const uint8_t* key, size_t key_len,
                    const uint8_t* msg, size_t msg_len,
                    uint8_t out[MW_SHA256_DIGEST]) {
    uint8_t       k[MW_SHA256_BLOCK];
    uint8_t       pad[MW_SHA256_BLOCK];
    uint8_t       inner[MW_SHA256_DIGEST];
    mw_sha256_ctx ctx;

    memset(k, 0, sizeof(k));
    if (key_len > MW_SHA256_BLOCK) {
        mw_sha256(key, key_len, k);
    } else if (key_len > 0) {
        memcpy(k, key, key_len);
    }

    for (size_t i = 0; i < MW_SHA256_BLOCK; ++i) {
        pad[i] = (uint8_t)(k[i] ^ 0x36);
    }
    mw_sha256_init(&ctx);
    mw_sha256_update(&ctx, pad, MW_SHA256_BLOCK);
    mw_sha256_update(&ctx, msg, msg_len);
    mw_sha256_final(&ctx, inner);

    for (size_t i = 0; i < MW_SHA256_BLOCK; ++i) {
        pad[i] = (uint8_t)(k[i] ^ 0x5c);
    }
    mw_sha256_init(&ctx);
    mw_sha256_update(&ctx, pad, MW_SHA256_BLOCK);
    mw_sha256_update(&ctx, inner, MW_SHA256_DIGEST);
    mw_sha256_final(&ctx, out);

    mw_memzero(k, sizeof(k));
    mw_memzero(pad, sizeof(pad));
    mw_memzero(inner, sizeof(inner));
}

void mw_hmac_sha512(const uint8_t* key, size_t key_len,
                    const uint8_t* msg, size_t msg_len,
                    uint8_t out[MW_SHA512_DIGEST]) {
    uint8_t       k[MW_SHA512_BLOCK];
    uint8_t       pad[MW_SHA512_BLOCK];
    uint8_t       inner[MW_SHA512_DIGEST];
    mw_sha512_ctx ctx;

    memset(k, 0, sizeof(k));
    if (key_len > MW_SHA512_BLOCK) {
        mw_sha512(key, key_len, k);
    } else if (key_len > 0) {
        memcpy(k, key, key_len);
    }

    for (size_t i = 0; i < MW_SHA512_BLOCK; ++i) {
        pad[i] = (uint8_t)(k[i] ^ 0x36);
    }
    mw_sha512_init(&ctx);
    mw_sha512_update(&ctx, pad, MW_SHA512_BLOCK);
    mw_sha512_update(&ctx, msg, msg_len);
    mw_sha512_final(&ctx, inner);

    for (size_t i = 0; i < MW_SHA512_BLOCK; ++i) {
        pad[i] = (uint8_t)(k[i] ^ 0x5c);
    }
    mw_sha512_init(&ctx);
    mw_sha512_update(&ctx, pad, MW_SHA512_BLOCK);
    mw_sha512_update(&ctx, inner, MW_SHA512_DIGEST);
    mw_sha512_final(&ctx, out);

    mw_memzero(k, sizeof(k));
    mw_memzero(pad, sizeof(pad));
    mw_memzero(inner, sizeof(inner));
}

// ---------------------------- PBKDF2 --------------------------------------

// The PBKDF2-HMAC-SHA256 iteration U_j = HMAC(P, U_{j-1}) is two SHA-256
// compressions once the key pads are absorbed: inner = SHA(ipad-state, U||pad)
// and U = SHA(opad-state, inner||pad). The pad states are computed once per
// call instead of twice per iteration (the plain HMAC does four
// compressions), and on the ESP32-S3 the compressions run on the SHA
// accelerator. Same output either way; the accelerator is only used after a
// self-test against the software code and never if that fails.
static void hmac256_pads(const uint8_t* key, size_t key_len,
                         uint8_t ipad[MW_SHA256_BLOCK], uint8_t opad[MW_SHA256_BLOCK]) {
    uint8_t k[MW_SHA256_BLOCK];
    memset(k, 0, sizeof(k));
    if (key_len > MW_SHA256_BLOCK) {
        mw_sha256(key, key_len, k);
    } else if (key_len > 0) {
        memcpy(k, key, key_len);
    }
    for (size_t i = 0; i < MW_SHA256_BLOCK; ++i) {
        ipad[i] = (uint8_t)(k[i] ^ 0x36);
        opad[i] = (uint8_t)(k[i] ^ 0x5c);
    }
    mw_memzero(k, sizeof(k));
}

// u = U_1 on entry; XORs U_2..U_iterations into t (t = U_1 on entry).
static void pbkdf2_256_iter_sw(const uint8_t* pw, size_t pw_len, uint8_t u[MW_SHA256_DIGEST],
                               uint8_t t[MW_SHA256_DIGEST], uint32_t iterations) {
    uint8_t       ipad[MW_SHA256_BLOCK], opad[MW_SHA256_BLOCK];
    uint8_t       inner[MW_SHA256_DIGEST];
    mw_sha256_ctx ci, co, c;

    hmac256_pads(pw, pw_len, ipad, opad);
    mw_sha256_init(&ci);
    mw_sha256_update(&ci, ipad, MW_SHA256_BLOCK);
    mw_sha256_init(&co);
    mw_sha256_update(&co, opad, MW_SHA256_BLOCK);
    for (uint32_t i = 1; i < iterations; ++i) {
        c = ci;
        mw_sha256_update(&c, u, MW_SHA256_DIGEST);
        mw_sha256_final(&c, inner);
        c = co;
        mw_sha256_update(&c, inner, MW_SHA256_DIGEST);
        mw_sha256_final(&c, u);
        for (size_t j = 0; j < MW_SHA256_DIGEST; ++j) t[j] ^= u[j];
        if (g_prog && (i % MW_PBKDF2_TICK) == 0) g_prog(MW_PBKDF2_TICK, g_prog_ctx);
    }
    mw_memzero(ipad, sizeof(ipad));
    mw_memzero(opad, sizeof(opad));
    mw_memzero(inner, sizeof(inner));
    mw_memzero(&ci, sizeof(ci));
    mw_memzero(&co, sizeof(co));
    mw_memzero(&c, sizeof(c));
}

#ifdef MW_PBKDF2_HW
// -1 not tested yet, 0 do not use, 1 digest registers read as the digest
// bytes, 2 the same with every 32-bit word byte-swapped.
static int g_hw_mode = -1;

static inline uint32_t bswap32(uint32_t x) {
    return (x >> 24) | ((x >> 8) & 0xff00u) | ((x << 8) & 0xff0000u) | (x << 24);
}

// One compression on the accelerator: from the raw register state `in`
// (NULL: the SHA-256 IV) over the 64-byte block, raw state into `out`.
// The caller holds the accelerator.
static void hw_compress(const uint32_t in[8], const uint32_t blk[16], uint32_t out[8]) {
    if (in) {
        esp_sha_write_digest_state(SHA2_256, (void*)in);
        esp_sha_block(SHA2_256, blk, false);
    } else {
        esp_sha_block(SHA2_256, blk, true);
    }
    sha_hal_wait_idle();
    esp_sha_read_digest_state(SHA2_256, out);
}

static void hw_state_bytes(const uint32_t st[8], uint8_t out[32]) {
    if (g_hw_mode == 2) {
        for (int i = 0; i < 8; ++i) {
            const uint32_t w = bswap32(st[i]);
            memcpy(out + 4 * i, &w, 4);
        }
    } else {
        memcpy(out, st, 32);
    }
}

// Second block of a 64+32-byte message: 32 data bytes, 0x80, zeros and the
// bit length 768 big-endian.
static void hw_block_96(uint32_t blk[16], const uint8_t d[32]) {
    uint8_t* b = (uint8_t*)blk;
    memcpy(b, d, 32);
    memset(b + 32, 0, 32);
    b[32] = 0x80;
    b[62] = 0x03;                       // 768 = 0x0300
}

static void pbkdf2_256_iter_hw(const uint8_t* pw, size_t pw_len, uint8_t u[MW_SHA256_DIGEST],
                               uint8_t t[MW_SHA256_DIGEST], uint32_t iterations) {
    uint32_t pad[16], blk[16], si[8], so[8], st[8];
    uint8_t  inner[MW_SHA256_DIGEST];

    esp_sha_acquire_hardware();
    esp_sha_set_mode(SHA2_256);
    hmac256_pads(pw, pw_len, (uint8_t*)blk, (uint8_t*)pad);
    hw_compress(NULL, blk, si);                     // ipad state
    hw_compress(NULL, pad, so);                     // opad state
    for (uint32_t i = 1; i < iterations; ++i) {
        hw_block_96(blk, u);
        hw_compress(si, blk, st);
        hw_state_bytes(st, inner);
        hw_block_96(blk, inner);
        hw_compress(so, blk, st);
        hw_state_bytes(st, u);
        for (size_t j = 0; j < MW_SHA256_DIGEST; ++j) t[j] ^= u[j];
        if (g_prog && (i % MW_PBKDF2_TICK) == 0) g_prog(MW_PBKDF2_TICK, g_prog_ctx);
    }
    esp_sha_release_hardware();
    mw_memzero(pad, sizeof(pad));
    mw_memzero(blk, sizeof(blk));
    mw_memzero(si, sizeof(si));
    mw_memzero(so, sizeof(so));
    mw_memzero(st, sizeof(st));
    mw_memzero(inner, sizeof(inner));
}

// Picks the digest byte order with SHA-256("abc"), then checks a full
// 5-iteration run against the software code.
static void hw_selftest(void) {
    static const uint8_t abc_digest[32] = {
        0xba, 0x78, 0x16, 0xbf, 0x8f, 0x01, 0xcf, 0xea, 0x41, 0x41, 0x40, 0xde,
        0x5d, 0xae, 0x22, 0x23, 0xb0, 0x03, 0x61, 0xa3, 0x96, 0x17, 0x7a, 0x9c,
        0xb4, 0x10, 0xff, 0x61, 0xf2, 0x00, 0x15, 0xad };
    uint32_t blk[16], st[8];
    uint8_t* b = (uint8_t*)blk;
    memset(blk, 0, sizeof(blk));
    b[0] = 'a'; b[1] = 'b'; b[2] = 'c'; b[3] = 0x80; b[63] = 24;

    g_hw_mode = 0;
    esp_sha_acquire_hardware();
    esp_sha_set_mode(SHA2_256);
    hw_compress(NULL, blk, st);
    esp_sha_release_hardware();
    uint8_t d[32];
    g_hw_mode = 1; hw_state_bytes(st, d);
    if (memcmp(d, abc_digest, 32) != 0) {
        g_hw_mode = 2; hw_state_bytes(st, d);
        if (memcmp(d, abc_digest, 32) != 0) { g_hw_mode = 0; return; }
    }

    static const uint8_t pw[] = "coldpunk pbkdf2 self-test";
    uint8_t u1[32], t1[32], u2[32], t2[32];
    for (int i = 0; i < 32; ++i) u1[i] = t1[i] = (uint8_t)(i * 7 + 1);
    memcpy(u2, u1, 32);
    memcpy(t2, t1, 32);
    mw_pbkdf2_progress_fn keep = g_prog;
    g_prog = NULL;
    pbkdf2_256_iter_sw(pw, sizeof(pw) - 1, u1, t1, 5);
    pbkdf2_256_iter_hw(pw, sizeof(pw) - 1, u2, t2, 5);
    g_prog = keep;
    if (memcmp(u1, u2, 32) != 0 || memcmp(t1, t2, 32) != 0) g_hw_mode = 0;
}
#endif  // MW_PBKDF2_HW

static void pbkdf2_256_iter(const uint8_t* pw, size_t pw_len, uint8_t u[MW_SHA256_DIGEST],
                            uint8_t t[MW_SHA256_DIGEST], uint32_t iterations) {
#ifdef MW_PBKDF2_HW
    if (g_hw_mode < 0) hw_selftest();
    if (g_hw_mode > 0) {
        pbkdf2_256_iter_hw(pw, pw_len, u, t, iterations);
        return;
    }
#endif
    pbkdf2_256_iter_sw(pw, pw_len, u, t, iterations);
}

bool mw_pbkdf2_sha256_hw(void) {
#ifdef MW_PBKDF2_HW
    if (g_hw_mode < 0) hw_selftest();
    return g_hw_mode > 0;
#else
    return false;
#endif
}

void mw_pbkdf2_sha256(const uint8_t* pw, size_t pw_len,
                      const uint8_t* salt, size_t salt_len,
                      uint32_t iterations, uint8_t* out, size_t out_len) {
    uint8_t  u[MW_SHA256_DIGEST];
    uint8_t  t[MW_SHA256_DIGEST];
    uint8_t* block;
    size_t   block_len;
    uint32_t counter = 1;

    if (out_len == 0) {
        return;
    }
    if (iterations == 0) {
        iterations = 1;
    }

    // salt || INT_32_BE(counter); allocated on the stack, salts are short.
    block_len = salt_len + 4;
    {
        uint8_t stack_buf[MW_PBKDF2_SALT_STACK];
        uint8_t* heap_buf = NULL;
        if (block_len <= sizeof(stack_buf)) {
            block = stack_buf;
        } else {
            heap_buf = (uint8_t*)malloc(block_len);
            if (heap_buf == NULL) {
                // Fail closed: an all-zero "derived key" would seal data
                // under a public key. There is no safe value to return.
                memset(out, 0, out_len);
                pbkdf2_fatal();
                return;
            }
            block = heap_buf;
        }
        if (salt_len > 0) {
            memcpy(block, salt, salt_len);
        }

        while (out_len > 0) {
            block[salt_len]     = (uint8_t)(counter >> 24);
            block[salt_len + 1] = (uint8_t)(counter >> 16);
            block[salt_len + 2] = (uint8_t)(counter >>  8);
            block[salt_len + 3] = (uint8_t)(counter);

            mw_hmac_sha256(pw, pw_len, block, block_len, u);
            memcpy(t, u, MW_SHA256_DIGEST);
            pbkdf2_256_iter(pw, pw_len, u, t, iterations);

            size_t take = (out_len < MW_SHA256_DIGEST) ? out_len
                                                       : (size_t)MW_SHA256_DIGEST;
            memcpy(out, t, take);
            out     += take;
            out_len -= take;
            counter++;
        }
        mw_memzero(block, block_len);
        if (heap_buf != NULL) {
            free(heap_buf);
        }
    }

    mw_memzero(u, sizeof(u));
    mw_memzero(t, sizeof(t));
}

void mw_pbkdf2_sha512(const uint8_t* pw, size_t pw_len,
                      const uint8_t* salt, size_t salt_len,
                      uint32_t iterations, uint8_t* out, size_t out_len) {
    uint8_t  u[MW_SHA512_DIGEST];
    uint8_t  t[MW_SHA512_DIGEST];
    uint8_t* block;
    size_t   block_len;
    uint32_t counter = 1;

    if (out_len == 0) {
        return;
    }
    if (iterations == 0) {
        iterations = 1;
    }

    block_len = salt_len + 4;
    {
        uint8_t stack_buf[MW_PBKDF2_SALT_STACK];
        uint8_t* heap_buf = NULL;
        if (block_len <= sizeof(stack_buf)) {
            block = stack_buf;
        } else {
            heap_buf = (uint8_t*)malloc(block_len);
            if (heap_buf == NULL) {
                // Fail closed: an all-zero "derived key" would seal data
                // under a public key. There is no safe value to return.
                memset(out, 0, out_len);
                pbkdf2_fatal();
                return;
            }
            block = heap_buf;
        }
        if (salt_len > 0) {
            memcpy(block, salt, salt_len);
        }

        while (out_len > 0) {
            block[salt_len]     = (uint8_t)(counter >> 24);
            block[salt_len + 1] = (uint8_t)(counter >> 16);
            block[salt_len + 2] = (uint8_t)(counter >>  8);
            block[salt_len + 3] = (uint8_t)(counter);

            mw_hmac_sha512(pw, pw_len, block, block_len, u);
            memcpy(t, u, MW_SHA512_DIGEST);

            for (uint32_t i = 1; i < iterations; ++i) {
                mw_hmac_sha512(pw, pw_len, u, MW_SHA512_DIGEST, u);
                for (size_t j = 0; j < MW_SHA512_DIGEST; ++j) {
                    t[j] ^= u[j];
                }
                if (g_prog && (i % MW_PBKDF2_TICK) == 0) g_prog(MW_PBKDF2_TICK, g_prog_ctx);
            }

            size_t take = (out_len < MW_SHA512_DIGEST) ? out_len
                                                       : (size_t)MW_SHA512_DIGEST;
            memcpy(out, t, take);
            out     += take;
            out_len -= take;
            counter++;
        }
        mw_memzero(block, block_len);
        if (heap_buf != NULL) {
            free(heap_buf);
        }
    }

    mw_memzero(u, sizeof(u));
    mw_memzero(t, sizeof(t));
}

// ---------------------------- CRC32 ---------------------------------------
// IEEE 802.3 polynomial 0xEDB88320 (reflected), init 0xFFFFFFFF, final xor
// 0xFFFFFFFF - the variant used by Monero's legacy 25-word seed checksum.
// Computed on the fly so no 1 KiB table has to live in flash.

uint32_t mw_crc32(const uint8_t* data, size_t len) {
    uint32_t crc = 0xFFFFFFFFu;
    for (size_t i = 0; i < len; ++i) {
        crc ^= (uint32_t)data[i];
        for (int b = 0; b < 8; ++b) {
            uint32_t mask = (uint32_t)(-(int32_t)(crc & 1u));
            crc = (crc >> 1) ^ (0xEDB88320u & mask);
        }
    }
    return crc ^ 0xFFFFFFFFu;
}
