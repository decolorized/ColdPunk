// Portable AES-256-GCM (NIST SP 800-38D) used by the eFuse-backed sealing
// layer (TZ 8.1).
//
// Design notes
//   * Encryption only is needed by GCM (CTR mode + GHASH), so no inverse
//     cipher is compiled in.
//   * The S-box is computed algebraically (x^254 in GF(2^8) followed by the
//     affine map) instead of being looked up in a table.  There is no
//     secret-dependent memory access and no secret-dependent branch anywhere
//     in the key schedule or the round function.
//   * GHASH uses the bitwise "shift and conditional xor" algorithm with
//     arithmetic masks - also branch-free and table-free.
//   * Tag verification goes through mw_ct_equal() (constant time).
//
// On ESP32 the hardware/mbedTLS implementation can be selected by defining
// MW_AES_GCM_USE_MBEDTLS; the portable path stays the reference and is the
// one the host test suite exercises.
#ifndef MW_AES_GCM_H
#define MW_AES_GCM_H

#include <stdint.h>
#include <stddef.h>

#ifdef __cplusplus
extern "C" {
#endif

#define MW_AES256_KEY_BYTES 32
#define MW_AES_BLOCK_BYTES  16
#define MW_GCM_TAG_BYTES    16
// The sealing layer always uses a 16-byte random nonce (see wallet_entry_t.
// seed_iv[16]).  GCM allows any non-empty IV length; 12 is the "fast path".
#define MW_GCM_IV_BYTES     16

// Return codes are deliberately plain ints so this module stays independent of
// monero_types.h.
#define MW_AES_GCM_OK        0
#define MW_AES_GCM_BAD_ARG (-1)
#define MW_AES_GCM_BAD_TAG (-2)

// AES-256-GCM encryption.  `ct` may alias `pt`.  `iv_len` must be >= 1,
// `aad`/`pt` may be NULL when the corresponding length is 0.
int mw_aes256_gcm_encrypt(const uint8_t key[MW_AES256_KEY_BYTES],
                          const uint8_t* iv, size_t iv_len,
                          const uint8_t* aad, size_t aad_len,
                          const uint8_t* pt, size_t pt_len,
                          uint8_t* ct, uint8_t tag[MW_GCM_TAG_BYTES]);

// AES-256-GCM decryption with constant-time tag verification.  On a tag
// mismatch `pt` is wiped and MW_AES_GCM_BAD_TAG is returned - the caller must
// never see unauthenticated plaintext.
int mw_aes256_gcm_decrypt(const uint8_t key[MW_AES256_KEY_BYTES],
                          const uint8_t* iv, size_t iv_len,
                          const uint8_t* aad, size_t aad_len,
                          const uint8_t* ct, size_t ct_len,
                          const uint8_t tag[MW_GCM_TAG_BYTES],
                          uint8_t* pt);

// Raw AES-256 block encryption (FIPS-197).  Exposed for the test suite.
void mw_aes256_encrypt_block(const uint8_t key[MW_AES256_KEY_BYTES],
                             const uint8_t in[MW_AES_BLOCK_BYTES],
                             uint8_t out[MW_AES_BLOCK_BYTES]);

#ifdef __cplusplus
}
#endif
#endif
