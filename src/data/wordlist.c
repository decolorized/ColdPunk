// Wordlist access layer (TZ 5.1, 5.7).
//
// The word tables themselves live in the generated headers and stay in flash
// on the ESP32: nothing here copies a word into RAM, every lookup dereferences
// the flash-resident pointer array directly.
//
// Matching rules follow the two upstream projects:
//   * Monero legacy list - words share a unique 3-character prefix.
//   * Polyseed list      - words share a unique 4-character prefix and the
//                          list is sorted, so binary search is allowed.
// A key that is at least `prefix_len` characters long matches any word it is a
// prefix of; a shorter key must equal the word exactly (some Polyseed words
// are only 3 characters long, e.g. "act" vs "action"). This is bit-for-bit the
// behaviour of tevador/polyseed's compare_prefix().
#include "wordlist.h"

#include <string.h>

#include "wordlist_monero_en.h"
#include "wordlist_polyseed_en.h"

// NOTE: the generated Monero table is in upstream english.h order, which
// happens to be alphabetical, but Monero makes no such guarantee, so the
// descriptor below declares it unsorted and every lookup uses a linear scan
// (1626 short comparisons - a few microseconds on the ESP32-S3).
static const mw_wordlist_t g_wordlists[2] = {
    {
        MW_WL_MONERO_EN,
        monero_en_words,
        MONERO_EN_COUNT,
        MONERO_EN_PREFIX_LEN,
        0,              // do not rely on ordering
        "Monero (English)"
    },
    {
        MW_WL_POLYSEED_EN,
        polyseed_en_words,
        POLYSEED_EN_COUNT,
        POLYSEED_EN_PREFIX_LEN,
        1,              // sorted -> binary search
        "Polyseed (English)"
    }
};

const mw_wordlist_t* mw_wordlist(mw_wordlist_id_t id)
{
    if (id == MW_WL_MONERO_EN)   return &g_wordlists[0];
    if (id == MW_WL_POLYSEED_EN) return &g_wordlists[1];
    return NULL;
}

const char* mw_wordlist_word(const mw_wordlist_t* wl, uint16_t index)
{
    if (wl == NULL || index >= wl->count) {
        return NULL;
    }
    return wl->words[index];
}

// strcmp-like comparison honouring the unique-prefix rule described above.
static int cmp_prefix(const char* key, const char* elm, int n)
{
    const unsigned char* k = (const unsigned char*)key;
    const unsigned char* e = (const unsigned char*)elm;
    for (int i = 1; ; ++i) {
        if (*k == '\0') {
            break;                       // key exhausted: exact-match rule
        }
        if (i >= n && k[1] == '\0') {
            break;                       // key long enough: prefix rule
        }
        if (*k != *e) {
            break;
        }
        ++k;
        ++e;
    }
    return (*k > *e) - (*k < *e);
}

int mw_wordlist_find(const mw_wordlist_t* wl, const char* word)
{
    if (wl == NULL || word == NULL || word[0] == '\0') {
        return -1;
    }
    const int n = (int)wl->prefix_len;

    if (wl->is_sorted) {
        int lo = 0, hi = (int)wl->count - 1;
        while (lo <= hi) {
            int mid = lo + (hi - lo) / 2;
            int c = cmp_prefix(word, wl->words[mid], n);
            if (c == 0) {
                return mid;
            }
            if (c < 0) {
                hi = mid - 1;
            } else {
                lo = mid + 1;
            }
        }
        return -1;
    }

    for (int i = 0; i < (int)wl->count; ++i) {
        if (cmp_prefix(word, wl->words[i], n) == 0) {
            return i;
        }
    }
    return -1;
}

// First index whose word is >= `prefix` when only `plen` characters are
// compared. Only valid on sorted lists.
static int lower_bound(const mw_wordlist_t* wl, const char* prefix, size_t plen)
{
    int lo = 0, hi = (int)wl->count;
    while (lo < hi) {
        int mid = lo + (hi - lo) / 2;
        if (strncmp(wl->words[mid], prefix, plen) < 0) {
            lo = mid + 1;
        } else {
            hi = mid;
        }
    }
    return lo;
}

int mw_wordlist_prefix_matches(const mw_wordlist_t* wl, const char* prefix,
                               uint16_t* out, int max, int* total_out)
{
    if (total_out != NULL) {
        *total_out = 0;
    }
    if (wl == NULL || prefix == NULL || max < 0) {
        return 0;
    }
    if (max > 0 && out == NULL) {
        return 0;
    }

    const size_t plen = strlen(prefix);
    int written = 0, total = 0;

    if (wl->is_sorted) {
        for (int i = lower_bound(wl, prefix, plen); i < (int)wl->count; ++i) {
            if (strncmp(wl->words[i], prefix, plen) != 0) {
                break;
            }
            ++total;
            if (written < max) {
                out[written++] = (uint16_t)i;
            }
        }
    } else {
        for (int i = 0; i < (int)wl->count; ++i) {
            if (strncmp(wl->words[i], prefix, plen) != 0) {
                continue;
            }
            ++total;
            if (written < max) {
                out[written++] = (uint16_t)i;
            }
        }
    }

    if (total_out != NULL) {
        *total_out = total;
    }
    return written;
}

uint32_t mw_wordlist_next_letters(const mw_wordlist_t* wl, const char* prefix)
{
    if (wl == NULL || prefix == NULL) {
        return 0;
    }
    const size_t plen = strlen(prefix);
    uint32_t mask = 0;

    int start = 0, end = (int)wl->count;
    if (wl->is_sorted) {
        start = lower_bound(wl, prefix, plen);
    }

    for (int i = start; i < end; ++i) {
        const char* w = wl->words[i];
        if (strncmp(w, prefix, plen) != 0) {
            if (wl->is_sorted) {
                break;      // sorted: matches are contiguous
            }
            continue;
        }
        unsigned char c = (unsigned char)w[plen];
        if (c >= 'a' && c <= 'z') {
            mask |= 1u << (c - 'a');
        }
    }
    return mask;
}
