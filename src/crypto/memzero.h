// Guaranteed-not-optimized-away zeroing plus constant-time comparison.
// TZ 5.2/5.10/8.1 require immediate wiping of seed and passphrase buffers.
#ifndef MW_MEMZERO_H
#define MW_MEMZERO_H

#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

void mw_memzero(void* p, size_t len);
#define MW_ZERO(x) mw_memzero(&(x), sizeof(x))

// Constant-time equality. Returns 1 when equal, 0 otherwise.
int mw_ct_equal(const void* a, const void* b, size_t len);

// Constant-time "is all zero". Returns 1 when every byte is zero.
int mw_ct_is_zero(const void* a, size_t len);

#ifdef __cplusplus
}
#endif
#endif
