// Hash primitives: Keccak-256 (Monero's "cn_fast_hash"), SHA-256, SHA-512,
// HMAC and PBKDF2. Platform-independent; compiled both for ESP32 and the host
// test runner.
#ifndef MW_HASH_H
#define MW_HASH_H

#include <stdint.h>
#include <stddef.h>

#ifdef __cplusplus
extern "C" {
#endif

// ---------------- Keccak-256 (original Keccak padding, NOT SHA3) ----------
#define MW_KECCAK_DIGEST 32

typedef struct {
    uint64_t state[25];
    uint8_t  buf[136];   // rate for 256-bit output
    size_t   buf_len;
} mw_keccak_ctx;

void mw_keccak_init(mw_keccak_ctx* ctx);
void mw_keccak_update(mw_keccak_ctx* ctx, const uint8_t* data, size_t len);
void mw_keccak_final(mw_keccak_ctx* ctx, uint8_t out[MW_KECCAK_DIGEST]);
void mw_keccak256(const uint8_t* data, size_t len, uint8_t out[MW_KECCAK_DIGEST]);

// Monero's cn_fast_hash == keccak256.
#define mw_cn_fast_hash mw_keccak256

// Arbitrary-output-length Keccak (used by Bulletproofs+ transcript helpers).
void mw_keccak_xof(const uint8_t* data, size_t len, uint8_t* out, size_t out_len);

// ---------------- SHA-256 ------------------------------------------------
#define MW_SHA256_DIGEST 32
#define MW_SHA256_BLOCK  64

typedef struct {
    uint32_t h[8];
    uint8_t  buf[MW_SHA256_BLOCK];
    size_t   buf_len;
    uint64_t total;
} mw_sha256_ctx;

void mw_sha256_init(mw_sha256_ctx* ctx);
void mw_sha256_update(mw_sha256_ctx* ctx, const uint8_t* data, size_t len);
void mw_sha256_final(mw_sha256_ctx* ctx, uint8_t out[MW_SHA256_DIGEST]);
void mw_sha256(const uint8_t* data, size_t len, uint8_t out[MW_SHA256_DIGEST]);

// ---------------- SHA-512 ------------------------------------------------
#define MW_SHA512_DIGEST 64
#define MW_SHA512_BLOCK  128

typedef struct {
    uint64_t h[8];
    uint8_t  buf[MW_SHA512_BLOCK];
    size_t   buf_len;
    uint64_t total;
} mw_sha512_ctx;

void mw_sha512_init(mw_sha512_ctx* ctx);
void mw_sha512_update(mw_sha512_ctx* ctx, const uint8_t* data, size_t len);
void mw_sha512_final(mw_sha512_ctx* ctx, uint8_t out[MW_SHA512_DIGEST]);
void mw_sha512(const uint8_t* data, size_t len, uint8_t out[MW_SHA512_DIGEST]);

// ---------------- HMAC / PBKDF2 ------------------------------------------
void mw_hmac_sha256(const uint8_t* key, size_t key_len,
                    const uint8_t* msg, size_t msg_len,
                    uint8_t out[MW_SHA256_DIGEST]);
void mw_hmac_sha512(const uint8_t* key, size_t key_len,
                    const uint8_t* msg, size_t msg_len,
                    uint8_t out[MW_SHA512_DIGEST]);

// PBKDF2-HMAC-SHA256 - required by Polyseed (10000 iterations, TZ 6.3).
// Optional progress hook for long derivations: called from inside
// mw_pbkdf2_sha256/512 with the number of iterations done since the last
// call (every 1024). NULL switches it off. Not thread safe: set it around
// one derivation on one task.
typedef void (*mw_pbkdf2_progress_fn)(uint32_t iterations_done, void* ctx);
void mw_pbkdf2_set_progress(mw_pbkdf2_progress_fn fn, void* ctx);

void mw_pbkdf2_sha256(const uint8_t* pw, size_t pw_len,
                      const uint8_t* salt, size_t salt_len,
                      uint32_t iterations, uint8_t* out, size_t out_len);

// PBKDF2-HMAC-SHA512 - required by dice entropy (2048 rounds, TZ 6.4).
void mw_pbkdf2_sha512(const uint8_t* pw, size_t pw_len,
                      const uint8_t* salt, size_t salt_len,
                      uint32_t iterations, uint8_t* out, size_t out_len);

// CRC32 (IEEE) - Monero legacy seed checksum.
uint32_t mw_crc32(const uint8_t* data, size_t len);

#ifdef __cplusplus
}
#endif
#endif
