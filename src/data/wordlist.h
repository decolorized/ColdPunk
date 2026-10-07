// Wordlist access layer.
//
// On ESP32 the wordlist arrays live in flash (.rodata) and are never copied
// into RAM: the pointers are dereferenced directly (memory-mapped flash), which
// satisfies TZ 5.1 ("dictionaries stay in flash, accessed page-wise").
#ifndef MW_WORDLIST_H
#define MW_WORDLIST_H

#include <stdint.h>
#include <stddef.h>

#ifdef __cplusplus
extern "C" {
#endif

// Placement qualifier for the generated tables. On Arduino/ESP32 the default
// linker script already keeps `const char* const[]` in flash.
#ifndef MW_WORDLIST_STORAGE
#define MW_WORDLIST_STORAGE
#endif

typedef enum {
    MW_WL_MONERO_EN = 0,  // 1626 words, 3-char unique prefix
    MW_WL_POLYSEED_EN = 1 // 2048 words, 4-char unique prefix, sorted
} mw_wordlist_id_t;

typedef struct {
    mw_wordlist_id_t id;
    const char* const* words;
    uint16_t count;
    uint8_t prefix_len;   // unique-prefix length used for matching
    uint8_t is_sorted;    // 1 -> binary search is allowed
    const char* name;
} mw_wordlist_t;

const mw_wordlist_t* mw_wordlist(mw_wordlist_id_t id);

// Exact lookup. Accepts either the full word or its unique prefix.
// Returns the index, or -1 if not found / ambiguous.
int mw_wordlist_find(const mw_wordlist_t* wl, const char* word);

// Prefix search used by the on-screen keyboards (TZ 5.7).
// Fills `out` with up to `max` indices of words starting with `prefix`.
// Returns the number written; `total_out` (optional) receives the total number
// of matches even when it exceeds `max`.
int mw_wordlist_prefix_matches(const mw_wordlist_t* wl, const char* prefix,
                               uint16_t* out, int max, int* total_out);

// Set of letters that can still extend `prefix` toward a valid word.
// `mask` is a 26-bit bitmap ('a' = bit 0). Used to grey out dead keys.
uint32_t mw_wordlist_next_letters(const mw_wordlist_t* wl, const char* prefix);

const char* mw_wordlist_word(const mw_wordlist_t* wl, uint16_t index);

#ifdef __cplusplus
}
#endif
#endif
