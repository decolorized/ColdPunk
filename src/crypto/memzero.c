// Guaranteed-not-optimized-away zeroing plus constant-time comparisons.
// Platform independent: the same file builds for the host tests and ESP32.
#include "memzero.h"

#include <string.h>

// A volatile function pointer to memset cannot be optimized away by the
// compiler: it has no way to prove what the pointer actually points at.
static void* (* volatile mw_memset_ptr)(void*, int, size_t) = memset;

void mw_memzero(void* p, size_t len) {
    if (p == NULL || len == 0) {
        return;
    }
    (void)mw_memset_ptr(p, 0, len);
    // Compiler barrier: keeps the store above alive across the call boundary.
#if defined(__GNUC__) || defined(__clang__)
    __asm__ __volatile__("" : : "r"(p) : "memory");
#endif
}

int mw_ct_equal(const void* a, const void* b, size_t len) {
    const volatile uint8_t* pa = (const volatile uint8_t*)a;
    const volatile uint8_t* pb = (const volatile uint8_t*)b;
    uint8_t diff = 0;
    for (size_t i = 0; i < len; ++i) {
        diff |= (uint8_t)(pa[i] ^ pb[i]);
    }
    // diff == 0  ->  1, otherwise 0, without a branch.
    return (int)((((uint32_t)diff - 1u) >> 31) & 1u);
}

int mw_ct_is_zero(const void* a, size_t len) {
    const volatile uint8_t* pa = (const volatile uint8_t*)a;
    uint8_t acc = 0;
    for (size_t i = 0; i < len; ++i) {
        acc |= pa[i];
    }
    return (int)((((uint32_t)acc - 1u) >> 31) & 1u);
}
