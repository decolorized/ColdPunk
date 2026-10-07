// Wordlist layer: lookup, prefix search and the on-screen-keyboard helpers.
#include "test_framework.h"

#include "data/wordlist.h"

MW_TEST(test_descriptors)
{
    const mw_wordlist_t* mon = mw_wordlist(MW_WL_MONERO_EN);
    const mw_wordlist_t* pol = mw_wordlist(MW_WL_POLYSEED_EN);

    CHECK(mon != NULL);
    CHECK(pol != NULL);
    CHECK_EQ_INT(mon->count, 1626);
    CHECK_EQ_INT(pol->count, 2048);
    CHECK_EQ_INT(mon->prefix_len, 3);
    CHECK_EQ_INT(pol->prefix_len, 4);
    CHECK_EQ_INT(pol->is_sorted, 1);
    CHECK(mw_wordlist((mw_wordlist_id_t)7) == NULL);

    // Bounds: no out-of-range read may ever be possible from the UI.
    CHECK(mw_wordlist_word(mon, 0) != NULL);
    CHECK(mw_wordlist_word(mon, 1625) != NULL);
    CHECK(mw_wordlist_word(mon, 1626) == NULL);
    CHECK(mw_wordlist_word(pol, 2048) == NULL);
    CHECK(mw_wordlist_word(NULL, 0) == NULL);

    CHECK_EQ_STR(mw_wordlist_word(mon, 0), "abbey");
    CHECK_EQ_STR(mw_wordlist_word(mon, 1625), "zoom");
    CHECK_EQ_STR(mw_wordlist_word(pol, 0), "abandon");
    CHECK_EQ_STR(mw_wordlist_word(pol, 2047), "zoo");
}

MW_TEST(test_unique_prefixes)
{
    // The whole seed-phrase scheme relies on these being unique.
    const mw_wordlist_t* mon = mw_wordlist(MW_WL_MONERO_EN);
    const mw_wordlist_t* pol = mw_wordlist(MW_WL_POLYSEED_EN);
    int collisions = 0;

    for (int i = 0; i < mon->count; ++i) {
        for (int j = i + 1; j < mon->count; ++j) {
            if (strncmp(mon->words[i], mon->words[j], 3) == 0) {
                collisions++;
            }
        }
    }
    CHECK_EQ_INT(collisions, 0);

    collisions = 0;
    for (int i = 0; i < pol->count; ++i) {
        for (int j = i + 1; j < pol->count; ++j) {
            if (strncmp(pol->words[i], pol->words[j], 4) == 0) {
                // Two words may only share a 4-char prefix if one of them is
                // shorter than 4 characters and they are not equal.
                if (strlen(pol->words[i]) >= 4 && strlen(pol->words[j]) >= 4) {
                    collisions++;
                }
            }
        }
    }
    CHECK_EQ_INT(collisions, 0);

    // The Polyseed list must stay sorted for the binary search to be valid.
    int unsorted = 0;
    for (int i = 1; i < pol->count; ++i) {
        if (strcmp(pol->words[i - 1], pol->words[i]) >= 0) {
            unsorted++;
        }
    }
    CHECK_EQ_INT(unsorted, 0);
}

MW_TEST(test_find_exact_and_prefix)
{
    const mw_wordlist_t* mon = mw_wordlist(MW_WL_MONERO_EN);
    const mw_wordlist_t* pol = mw_wordlist(MW_WL_POLYSEED_EN);

    // Every word must find itself, and so must its unique prefix.
    int bad_full = 0, bad_prefix = 0;
    for (int i = 0; i < mon->count; ++i) {
        if (mw_wordlist_find(mon, mon->words[i]) != i) {
            bad_full++;
        }
        char pre[4];
        memcpy(pre, mon->words[i], 3);
        pre[3] = '\0';
        if (mw_wordlist_find(mon, pre) != i) {
            bad_prefix++;
        }
    }
    CHECK_EQ_INT(bad_full, 0);
    CHECK_EQ_INT(bad_prefix, 0);

    bad_full = bad_prefix = 0;
    for (int i = 0; i < pol->count; ++i) {
        if (mw_wordlist_find(pol, pol->words[i]) != i) {
            bad_full++;
        }
        char pre[5];
        size_t len = strlen(pol->words[i]);
        size_t take = len < 4 ? len : 4;
        memcpy(pre, pol->words[i], take);
        pre[take] = '\0';
        if (mw_wordlist_find(pol, pre) != i) {
            bad_prefix++;
        }
    }
    CHECK_EQ_INT(bad_full, 0);
    CHECK_EQ_INT(bad_prefix, 0);

    CHECK_EQ_INT(mw_wordlist_find(mon, "abbey"), 0);
    CHECK_EQ_INT(mw_wordlist_find(mon, "abb"), 0);
    CHECK_EQ_INT(mw_wordlist_find(mon, "tavern"), 1361);
    CHECK_EQ_INT(mw_wordlist_find(pol, "abandon"), 0);
    CHECK_EQ_INT(mw_wordlist_find(pol, "aban"), 0);

    // Words shorter than the prefix length must match exactly, and must not be
    // confused with the longer words that start the same way.
    CHECK_EQ_INT(mw_wordlist_find(pol, "act"), 19);
    CHECK_EQ_INT(mw_wordlist_find(pol, "acti"), 20);
    CHECK_EQ_INT(mw_wordlist_find(pol, "action"), 20);

    // Unknown / too-short / degenerate input.
    CHECK_EQ_INT(mw_wordlist_find(mon, "notaword"), -1);
    CHECK_EQ_INT(mw_wordlist_find(mon, "ab"), -1);
    CHECK_EQ_INT(mw_wordlist_find(mon, ""), -1);
    CHECK_EQ_INT(mw_wordlist_find(mon, NULL), -1);
    CHECK_EQ_INT(mw_wordlist_find(NULL, "abbey"), -1);
    CHECK_EQ_INT(mw_wordlist_find(pol, "zzzz"), -1);
    CHECK_EQ_INT(mw_wordlist_find(pol, "abandonment"), -1);
}

MW_TEST(test_prefix_matches)
{
    const mw_wordlist_t* mon = mw_wordlist(MW_WL_MONERO_EN);
    const mw_wordlist_t* pol = mw_wordlist(MW_WL_POLYSEED_EN);

    uint16_t out[8];
    int total = 0;

    int n = mw_wordlist_prefix_matches(mon, "zo", out, 8, &total);
    CHECK_EQ_INT(n, 4);
    CHECK_EQ_INT(total, 4);
    CHECK_EQ_STR(mw_wordlist_word(mon, out[0]), "zodiac");
    CHECK_EQ_STR(mw_wordlist_word(mon, out[1]), "zombie");
    CHECK_EQ_STR(mw_wordlist_word(mon, out[2]), "zones");
    CHECK_EQ_STR(mw_wordlist_word(mon, out[3]), "zoom");

    n = mw_wordlist_prefix_matches(mon, "q", out, 8, &total);
    CHECK_EQ_INT(n, 3);
    CHECK_EQ_INT(total, 3);

    // `max` truncates the output but `total` still reports everything.
    n = mw_wordlist_prefix_matches(mon, "", out, 8, &total);
    CHECK_EQ_INT(n, 8);
    CHECK_EQ_INT(total, 1626);
    CHECK_EQ_STR(mw_wordlist_word(mon, out[0]), "abbey");

    n = mw_wordlist_prefix_matches(mon, "x", out, 8, &total);
    CHECK_EQ_INT(n, 0);
    CHECK_EQ_INT(total, 0);

    n = mw_wordlist_prefix_matches(pol, "zo", out, 8, &total);
    CHECK_EQ_INT(n, 2);
    CHECK_EQ_INT(total, 2);
    CHECK_EQ_STR(mw_wordlist_word(pol, out[0]), "zone");
    CHECK_EQ_STR(mw_wordlist_word(pol, out[1]), "zoo");

    n = mw_wordlist_prefix_matches(pol, "ab", out, 8, &total);
    CHECK_EQ_INT(n, 8);
    CHECK_EQ_INT(total, 10);

    n = mw_wordlist_prefix_matches(pol, "", out, 8, &total);
    CHECK_EQ_INT(total, 2048);

    // Degenerate arguments must not write anything.
    CHECK_EQ_INT(mw_wordlist_prefix_matches(NULL, "a", out, 8, &total), 0);
    CHECK_EQ_INT(total, 0);
    CHECK_EQ_INT(mw_wordlist_prefix_matches(pol, NULL, out, 8, NULL), 0);
    CHECK_EQ_INT(mw_wordlist_prefix_matches(pol, "a", NULL, 8, NULL), 0);
    CHECK_EQ_INT(mw_wordlist_prefix_matches(pol, "", out, 0, &total), 0);
    CHECK_EQ_INT(total, 2048);   // total is still reported with max == 0
}

MW_TEST(test_next_letters)
{
    const mw_wordlist_t* mon = mw_wordlist(MW_WL_MONERO_EN);
    const mw_wordlist_t* pol = mw_wordlist(MW_WL_POLYSEED_EN);

    // "zo" -> zodiac, zombie, zones, zoom  =>  d, m, n, o
    uint32_t m = mw_wordlist_next_letters(mon, "zo");
    CHECK_EQ_INT(m, 0x7008u);
    CHECK((m & (1u << ('d' - 'a'))) != 0);
    CHECK((m & (1u << ('m' - 'a'))) != 0);
    CHECK((m & (1u << ('n' - 'a'))) != 0);
    CHECK((m & (1u << ('o' - 'a'))) != 0);
    CHECK((m & (1u << ('a' - 'a'))) == 0);

    CHECK_EQ_INT(mw_wordlist_next_letters(mon, "q"), 0x100000u);   // only 'u'
    CHECK_EQ_INT(mw_wordlist_next_letters(mon, "abb"), 0x10u);     // only 'e'
    CHECK_EQ_INT(mw_wordlist_next_letters(mon, ""), 0x37fffffu);   // no 'v'/'x'
    CHECK_EQ_INT(mw_wordlist_next_letters(mon, "x"), 0u);
    CHECK_EQ_INT(mw_wordlist_next_letters(mon, "zoom"), 0u);       // complete

    CHECK_EQ_INT(mw_wordlist_next_letters(pol, "zo"), 0x6000u);    // n, o
    CHECK_EQ_INT(mw_wordlist_next_letters(pol, "q"), 0x100000u);   // only 'u'
    CHECK_EQ_INT(mw_wordlist_next_letters(pol, "ab"), 0x144901u);
    CHECK_EQ_INT(mw_wordlist_next_letters(pol, ""), 0x37fffffu);
    CHECK_EQ_INT(mw_wordlist_next_letters(pol, "zzz"), 0u);
    CHECK_EQ_INT(mw_wordlist_next_letters(NULL, "a"), 0u);
    CHECK_EQ_INT(mw_wordlist_next_letters(pol, NULL), 0u);

    // Cross-check the mask against a brute-force scan for a few prefixes.
    static const char* prefixes[] = { "a", "b", "co", "st", "wa", "un", "pre" };
    for (size_t p = 0; p < sizeof(prefixes) / sizeof(prefixes[0]); ++p) {
        for (int list = 0; list < 2; ++list) {
            const mw_wordlist_t* wl = list ? pol : mon;
            size_t plen = strlen(prefixes[p]);
            uint32_t expect = 0;
            for (int i = 0; i < wl->count; ++i) {
                const char* w = wl->words[i];
                if (strncmp(w, prefixes[p], plen) == 0 && strlen(w) > plen) {
                    char c = w[plen];
                    if (c >= 'a' && c <= 'z') {
                        expect |= 1u << (c - 'a');
                    }
                }
            }
            CHECK_EQ_INT(mw_wordlist_next_letters(wl, prefixes[p]), expect);
        }
    }
}

int main(void)
{
    RUN_TEST(test_descriptors);
    RUN_TEST(test_unique_prefixes);
    RUN_TEST(test_find_exact_and_prefix);
    RUN_TEST(test_prefix_matches);
    RUN_TEST(test_next_letters);
    return mw_test_summary();
}
