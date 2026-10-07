// ChaCha20 as Monero uses it for wallet file encryption, plus the
// cn_slow_hash (CryptoNight) key-derivation Monero applies to the view key
// before encrypting outputs.bin / keyimages.bin / *_tx_set.bin (TZ 9, 11.3).
#ifndef MW_CHACHA_H
#define MW_CHACHA_H

#include <stdint.h>
#include <stddef.h>

#ifdef __cplusplus
extern "C" {
#endif

#define MW_CHACHA_KEY_SIZE 32
#define MW_CHACHA_IV_SIZE  8      // Monero uses an 8-byte IV, 8-byte counter

typedef struct { uint8_t data[MW_CHACHA_KEY_SIZE]; } mw_chacha_key;
typedef struct { uint8_t data[MW_CHACHA_IV_SIZE];  } mw_chacha_iv;

// Monero's chacha20 (20 rounds, 64-bit nonce, counter starts at 0).
// Encryption and decryption are the same operation.
void mw_chacha20(const void* in, size_t len, const mw_chacha_key* key,
                 const mw_chacha_iv* iv, void* out);

// Monero's generate_chacha_key: cn_slow_hash(data, variant 0) over the key
// material. `iterations` maps to Monero's kdf_rounds (1 for wallet files).
void mw_generate_chacha_key(const void* data, size_t len,
                            mw_chacha_key* key, uint64_t iterations);

// CryptoNight slow hash, variant 0 - needs a 2 MiB scratchpad.
// On ESP32-S3 the scratchpad MUST come from PSRAM (TZ 1.4).
// Returns 0 on success, -1 if the scratchpad could not be allocated.
int mw_cn_slow_hash(const void* data, size_t len, uint8_t hash[32]);

// Pre-allocates the 2 MiB scratchpad once at boot so signing never fails on a
// late allocation. Returns 0 on success.
int mw_cn_slow_hash_init(void);
void mw_cn_slow_hash_free(void);

#ifdef __cplusplus
}
#endif
#endif
