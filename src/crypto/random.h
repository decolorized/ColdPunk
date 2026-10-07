// RNG layer. TZ 8.2: bootloader_random_enable() first in setup(), self-test at
// boot, and CLSAG nonce hedging (TRNG XOR deterministic context).
#ifndef MW_RANDOM_H
#define MW_RANDOM_H

#include <stdint.h>
#include <stddef.h>

#ifdef __cplusplus
extern "C" {
#endif

typedef enum {
    MW_RNG_OK = 0,
    MW_RNG_ERR_NOT_INIT = -1,
    MW_RNG_ERR_SELFTEST = -2,   // repetition / adaptive-proportion test failed
    MW_RNG_ERR_STUCK    = -3    // identical blocks returned
} mw_rng_status_t;

// Enables the hardware TRNG (bootloader_random_enable on ESP32) and runs the
// boot self-test. Must be the first call in setup().
mw_rng_status_t mw_random_init(void);

// NIST SP 800-90B style health tests over a fresh sample.
mw_rng_status_t mw_random_selftest(void);

void mw_random_bytes(void* out, size_t len);

// Hedged nonce (TZ 8.2): k = hash_to_scalar(TRNG(32) || deterministic_context).
// Never produces a nonce that is weaker than either source alone.
void mw_random_hedged_scalar(void* scalar_out,
                             const uint8_t* context, size_t context_len);

// Host-test only: replace the entropy source with a deterministic stream so
// signatures become reproducible. No-op on the device build.
void mw_random_set_test_source(const uint8_t* stream, size_t len);

#ifdef __cplusplus
}
#endif
#endif
