// HMAC-SHA256/512 (RFC 2104), PBKDF2 (RFC 8018) and CRC32 (IEEE).
#include "hash.h"
#include "memzero.h"

#include <stdlib.h>
#include <string.h>

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
                memset(out, 0, out_len);
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

            for (uint32_t i = 1; i < iterations; ++i) {
                mw_hmac_sha256(pw, pw_len, u, MW_SHA256_DIGEST, u);
                for (size_t j = 0; j < MW_SHA256_DIGEST; ++j) {
                    t[j] ^= u[j];
                }
            }

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
                memset(out, 0, out_len);
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
