// Monero legacy 25-word seed phrase (TZ 5.1, 6.2).
//
// 24 words carry the 32-byte seed: every 4 little-endian bytes become a
// 32-bit value x that is split into three word indices
//     w1 = x % n
//     w2 = (x / n + w1) % n
//     w3 = (x / n / n + w2) % n           (n = wordlist size, 1626 for English)
// The 25th word is the checksum word: CRC32 over the concatenated
// `prefix_len`-character prefixes of the 24 words, taken modulo 24, selects
// which of the 24 words is repeated.
#include "mnemonic.h"

#include <string.h>

#include "../crypto/hash.h"
#include "../crypto/memzero.h"

#define LEGACY_DATA_WORDS 24

// Longest prefix we are willing to hash per word (the English list uses 3).
#define MAX_PREFIX 16

static int wordlist_ok(const mw_wordlist_t* wl)
{
    return wl != NULL && wl->words != NULL && wl->count >= 2 &&
           wl->prefix_len >= 1 && wl->prefix_len <= MAX_PREFIX;
}

int mw_legacy_checksum_index(const uint16_t indices[LEGACY_DATA_WORDS],
                             const mw_wordlist_t* wl)
{
    if (indices == NULL || !wordlist_ok(wl)) {
        return -1;
    }

    uint8_t buf[LEGACY_DATA_WORDS * MAX_PREFIX];
    size_t pos = 0;

    for (int i = 0; i < LEGACY_DATA_WORDS; ++i) {
        if (indices[i] >= wl->count) {
            return -1;
        }
        const char* w = wl->words[indices[i]];
        size_t wlen = strlen(w);
        size_t take = wlen < wl->prefix_len ? wlen : wl->prefix_len;
        memcpy(buf + pos, w, take);
        pos += take;
    }

    uint32_t crc = mw_crc32(buf, pos);
    return (int)(crc % (uint32_t)LEGACY_DATA_WORDS);
}

mw_err_t mw_legacy_seed_encode(const uint8_t seed[32], const mw_wordlist_t* wl,
                               uint16_t indices_out[MW_LEGACY_SEED_WORDS])
{
    if (seed == NULL || indices_out == NULL || !wordlist_ok(wl)) {
        return MW_ERR_INVALID_ARG;
    }

    const uint32_t n = wl->count;

    for (int i = 0; i < 8; ++i) {
        uint32_t x = (uint32_t)seed[4 * i]
                   | ((uint32_t)seed[4 * i + 1] << 8)
                   | ((uint32_t)seed[4 * i + 2] << 16)
                   | ((uint32_t)seed[4 * i + 3] << 24);
        uint32_t w1 = x % n;
        uint32_t w2 = (x / n + w1) % n;
        uint32_t w3 = (x / n / n + w2) % n;
        indices_out[3 * i]     = (uint16_t)w1;
        indices_out[3 * i + 1] = (uint16_t)w2;
        indices_out[3 * i + 2] = (uint16_t)w3;
    }

    int ck = mw_legacy_checksum_index(indices_out, wl);
    if (ck < 0) {
        return MW_ERR_INVALID_ARG;
    }
    indices_out[LEGACY_DATA_WORDS] = indices_out[ck];
    return MW_OK;
}

mw_err_t mw_legacy_seed_decode(const uint16_t indices[MW_LEGACY_SEED_WORDS],
                               const mw_wordlist_t* wl, uint8_t seed_out[32])
{
    if (indices == NULL || seed_out == NULL || !wordlist_ok(wl)) {
        return MW_ERR_INVALID_ARG;
    }

    const uint32_t n = wl->count;

    for (int i = 0; i < MW_LEGACY_SEED_WORDS; ++i) {
        if (indices[i] >= wl->count) {
            return MW_ERR_UNKNOWN_WORD;
        }
    }

    // Checksum word must repeat the word CRC32 selects.
    int ck = mw_legacy_checksum_index(indices, wl);
    if (ck < 0) {
        return MW_ERR_INVALID_ARG;
    }
    if (indices[LEGACY_DATA_WORDS] != indices[ck]) {
        return MW_ERR_CHECKSUM;
    }

    uint8_t tmp[32];
    for (int i = 0; i < 8; ++i) {
        uint32_t w1 = indices[3 * i];
        uint32_t w2 = indices[3 * i + 1];
        uint32_t w3 = indices[3 * i + 2];

        uint64_t val = (uint64_t)w1
                     + (uint64_t)n * (((n - w1) + w2) % n)
                     + (uint64_t)n * n * (((n - w2) + w3) % n);

        // Not every word triple is reachable: reject the out-of-range ones.
        if ((val >> 32) != 0 || (uint32_t)(val % n) != w1) {
            mw_memzero(tmp, sizeof(tmp));
            return MW_ERR_FORMAT;
        }

        tmp[4 * i]     = (uint8_t)(val);
        tmp[4 * i + 1] = (uint8_t)(val >> 8);
        tmp[4 * i + 2] = (uint8_t)(val >> 16);
        tmp[4 * i + 3] = (uint8_t)(val >> 24);
    }

    memcpy(seed_out, tmp, 32);
    mw_memzero(tmp, sizeof(tmp));
    return MW_OK;
}
