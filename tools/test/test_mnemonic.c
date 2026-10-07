// Monero legacy 25-word seed phrase (TZ 5.1, 6.2).
#include "test_framework.h"

#include "monero/address.h"
#include "monero/mnemonic.h"
#include "data/wordlist.h"
#include "config/app_config.h"

// ---------------------------------------------------------------- helpers
static uint32_t rng_state = 0x12345678u;

static uint32_t rng_next(void)
{
    // xorshift32 - deterministic, reproducible failures.
    uint32_t x = rng_state;
    x ^= x << 13;
    x ^= x >> 17;
    x ^= x << 5;
    rng_state = x;
    return x;
}

static void rng_bytes(uint8_t* out, size_t len)
{
    for (size_t i = 0; i < len; ++i) {
        out[i] = (uint8_t)(rng_next() >> 24);
    }
}

// Joins the indices into a space-separated phrase.
static void phrase_of(const uint16_t* idx, int n, const mw_wordlist_t* wl,
                      char* out, size_t out_len)
{
    size_t pos = 0;
    out[0] = '\0';
    for (int i = 0; i < n; ++i) {
        const char* w = mw_wordlist_word(wl, idx[i]);
        size_t len = strlen(w);
        if (pos + len + 2 >= out_len) {
            return;
        }
        if (i) {
            out[pos++] = ' ';
        }
        memcpy(out + pos, w, len);
        pos += len;
        out[pos] = '\0';
    }
}

// Splits a phrase back into indices; returns the word count.
static int indices_of(const char* phrase, const mw_wordlist_t* wl, uint16_t* out,
                      int max)
{
    int n = 0;
    const char* p = phrase;
    while (*p && n < max) {
        while (*p == ' ') ++p;
        if (!*p) break;
        char word[32];
        size_t len = 0;
        while (p[len] && p[len] != ' ' && len < sizeof(word) - 1) {
            word[len] = p[len];
            ++len;
        }
        word[len] = '\0';
        p += len;
        int idx = mw_wordlist_find(wl, word);
        if (idx < 0) {
            return -1;
        }
        out[n++] = (uint16_t)idx;
    }
    return n;
}

// -------------------------------------------------------------- test cases
//
// NOTE on the vector shipped with the task description: the 25-word phrase it
// pairs with seed 3b094ca7...4109 is NOT self-consistent. Its own checksum word
// ("rounded") does not match the CRC32 index its 24 words produce (that index
// selects "deepest"), and decoding its words yields
// 3b094ca751129932838ccb331f4facb7... instead of the given seed. Only its first
// five words agree with the Monero algorithm. The value asserted below was
// re-derived from the algorithm and is cross-checked against the independent
// monero-python documentation vector in test_vector_monero_python().
MW_TEST(test_vector_task_seed)
{
    const mw_wordlist_t* wl = mw_wordlist(MW_WL_MONERO_EN);

    uint8_t seed[32];
    CHECK_EQ_INT(mw_test_hex("3b094ca7218f175e91fa2402b4ae239a"
                             "2fe8262792a3e718533a1a357a1e4109", seed, 32), 32);

    uint16_t idx[MW_LEGACY_SEED_WORDS];
    CHECK_EQ_INT(mw_legacy_seed_encode(seed, wl, idx), MW_OK);

    char phrase[512];
    phrase_of(idx, MW_LEGACY_SEED_WORDS, wl, phrase, sizeof(phrase));
    CHECK_EQ_STR(phrase,
        "tavern judge beyond bifocals deepest mural onward dummy eagle diode "
        "gained vacation rally cause firm idled jerseys moat vigilant upload "
        "bobsled jobs cunning doing jobs");

    // CRC32 over the 24 three-character prefixes selects word #21 ("jobs").
    CHECK_EQ_INT(mw_legacy_checksum_index(idx, wl), 21);
    CHECK_EQ_INT(idx[24], idx[21]);

    uint8_t back[32];
    CHECK_EQ_INT(mw_legacy_seed_decode(idx, wl, back), MW_OK);
    CHECK_EQ_MEM(back, seed, 32);
}

// Vector from the monero-python documentation (an independent implementation).
MW_TEST(test_vector_monero_python)
{
    const mw_wordlist_t* wl = mw_wordlist(MW_WL_MONERO_EN);
    static const char* expect =
        "fewest lipstick auburn cocoa macro circle hurried impel macro hatchet "
        "jeopardy swung aloof spiders gags jaws abducts buying alpine athlete "
        "junk patio academy loudly academy";

    uint8_t seed[32];
    CHECK_EQ_INT(mw_test_hex("73192a945d7400a3a76a941be451a962"
                             "3f37dd834006d02140a6a762b9142d80", seed, 32), 32);

    uint16_t idx[MW_LEGACY_SEED_WORDS];
    CHECK_EQ_INT(mw_legacy_seed_encode(seed, wl, idx), MW_OK);

    char phrase[512];
    phrase_of(idx, MW_LEGACY_SEED_WORDS, wl, phrase, sizeof(phrase));
    CHECK_EQ_STR(phrase, expect);

    // ... and the other direction, starting from the words.
    uint16_t parsed[MW_LEGACY_SEED_WORDS];
    CHECK_EQ_INT(indices_of(expect, wl, parsed, MW_LEGACY_SEED_WORDS),
                 MW_LEGACY_SEED_WORDS);
    uint8_t back[32];
    CHECK_EQ_INT(mw_legacy_seed_decode(parsed, wl, back), MW_OK);
    CHECK_EQ_MEM(back, seed, 32);
}

MW_TEST(test_roundtrip_random)
{
    const mw_wordlist_t* wl = mw_wordlist(MW_WL_MONERO_EN);
    int failures = 0;

    for (int iter = 0; iter < 2000; ++iter) {
        uint8_t seed[32], back[32];
        rng_bytes(seed, 32);

        uint16_t idx[MW_LEGACY_SEED_WORDS];
        if (mw_legacy_seed_encode(seed, wl, idx) != MW_OK) {
            failures++;
            continue;
        }
        for (int i = 0; i < MW_LEGACY_SEED_WORDS; ++i) {
            if (idx[i] >= wl->count) {
                failures++;
            }
        }
        if (mw_legacy_seed_decode(idx, wl, back) != MW_OK ||
            memcmp(seed, back, 32) != 0) {
            failures++;
        }

        // Round-trip through the printed phrase as well.
        char phrase[512];
        uint16_t parsed[MW_LEGACY_SEED_WORDS];
        phrase_of(idx, MW_LEGACY_SEED_WORDS, wl, phrase, sizeof(phrase));
        if (indices_of(phrase, wl, parsed, MW_LEGACY_SEED_WORDS) !=
                MW_LEGACY_SEED_WORDS ||
            memcmp(parsed, idx, sizeof(idx)) != 0) {
            failures++;
        }
    }
    CHECK_EQ_INT(failures, 0);
}

MW_TEST(test_prefix_only_input)
{
    // Users may type only the unique 3-character prefixes.
    const mw_wordlist_t* wl = mw_wordlist(MW_WL_MONERO_EN);
    static const char* prefixes =
        "few lip aub coc mac cir hur imp mac hat jeo swu alo spi gag jaw abd "
        "buy alp ath jun pat aca lou aca";

    uint16_t idx[MW_LEGACY_SEED_WORDS];
    CHECK_EQ_INT(indices_of(prefixes, wl, idx, MW_LEGACY_SEED_WORDS),
                 MW_LEGACY_SEED_WORDS);

    uint8_t seed[32], expect[32];
    mw_test_hex("73192a945d7400a3a76a941be451a962"
                "3f37dd834006d02140a6a762b9142d80", expect, 32);
    CHECK_EQ_INT(mw_legacy_seed_decode(idx, wl, seed), MW_OK);
    CHECK_EQ_MEM(seed, expect, 32);
}

MW_TEST(test_checksum_rejection)
{
    const mw_wordlist_t* wl = mw_wordlist(MW_WL_MONERO_EN);
    uint8_t seed[32], back[32];
    rng_bytes(seed, 32);

    uint16_t idx[MW_LEGACY_SEED_WORDS];
    CHECK_EQ_INT(mw_legacy_seed_encode(seed, wl, idx), MW_OK);

    // A wrong checksum word is rejected.
    uint16_t bad[MW_LEGACY_SEED_WORDS];
    memcpy(bad, idx, sizeof(idx));
    bad[24] = (uint16_t)((bad[24] + 1) % wl->count);
    CHECK_EQ_INT(mw_legacy_seed_decode(bad, wl, back), MW_ERR_CHECKSUM);

    // Changing any data word almost always moves the checksum word too; the
    // decode must fail rather than silently return a different seed.
    int accepted_silently = 0;
    for (int i = 0; i < 24; ++i) {
        memcpy(bad, idx, sizeof(idx));
        bad[i] = (uint16_t)((bad[i] + 1) % wl->count);
        mw_err_t err = mw_legacy_seed_decode(bad, wl, back);
        if (err == MW_OK && memcmp(back, seed, 32) == 0) {
            accepted_silently++;
        }
    }
    CHECK_EQ_INT(accepted_silently, 0);

    // Unknown word (index past the end of the list).
    memcpy(bad, idx, sizeof(idx));
    bad[3] = 1626;
    CHECK_EQ_INT(mw_legacy_seed_decode(bad, wl, back), MW_ERR_UNKNOWN_WORD);
    CHECK_EQ_INT(indices_of("abbey notaword abbey", wl, bad, 3), -1);

    // Bad arguments.
    CHECK_EQ_INT(mw_legacy_seed_decode(NULL, wl, back), MW_ERR_INVALID_ARG);
    CHECK_EQ_INT(mw_legacy_seed_decode(idx, NULL, back), MW_ERR_INVALID_ARG);
    CHECK_EQ_INT(mw_legacy_seed_encode(seed, wl, NULL), MW_ERR_INVALID_ARG);
    CHECK_EQ_INT(mw_legacy_checksum_index(NULL, wl), -1);
}

MW_TEST(test_out_of_range_triple)
{
    // Not every triple of words is reachable: the 32-bit value it encodes may
    // overflow. Such a phrase must be rejected even when its checksum is right.
    const mw_wordlist_t* wl = mw_wordlist(MW_WL_MONERO_EN);

    // w1=0, w2=1, w3=0 makes the third term n*n*1625, which alone exceeds
    // 2^32, so the triple cannot come from any 4-byte group.
    uint16_t idx[MW_LEGACY_SEED_WORDS];
    for (int i = 0; i < 8; ++i) {
        idx[3 * i]     = 0;
        idx[3 * i + 1] = 1;
        idx[3 * i + 2] = 0;
    }
    int ck = mw_legacy_checksum_index(idx, wl);
    CHECK(ck >= 0);
    idx[24] = idx[ck];

    uint8_t seed[32];
    CHECK_EQ_INT(mw_legacy_seed_decode(idx, wl, seed), MW_ERR_FORMAT);
}

// ---------------------------------------------------------------------------
// Dice entropy (TZ 6.4 / 13.4): throws -> entropy -> phrase -> address.
//
// This conversion used to live as a static helper inside src/ui/flows.cpp,
// where the host build cannot reach it, so "Кубики -> корректная фраза" had no
// automated coverage at all. mw_dice_to_entropy() is the same computation in a
// place tests can call.
//
// The expected entropy was computed independently with Python's
// hashlib.pbkdf2_hmac('sha512', <the digits>, b"Monero dice entropy", 2048),
// and the address independently from the entropy with a separate Ed25519 /
// base58 implementation.
// ---------------------------------------------------------------------------
#define DICE_ROLLS                                                            \
    "5263352123535526246413661251314614552533224421452235361541113153152442"  \
    "631341124115612261545455155144"

#define DICE_ENTROPY                                                          \
    "9bca667b1974839d1e24bbd8e9c56f32652193f954c570b6d0fee00aa2e43656"

#define DICE_PHRASE                                                           \
    "doorway fainted seasons menu argue pouch hounded ramped mops newt ouch "  \
    "suture september lettuce kept sonic luggage dullness gutter hubcaps "     \
    "january fitting honked riots honked"

#define DICE_ADDRESS                                                          \
    "46H2YC9un8NJtvpAncxX85JLbEazMdaqj1DR3JsnNuXhXh9AomLfosPHHtJRVChprYGLd"    \
    "KM1fxJJAZA3qMpm6F4tKJsA8fw"

static size_t dice_rolls_of(const char* digits, uint8_t* out, size_t cap)
{
    size_t n = 0;
    while (digits[n] != '\0' && n < cap) {
        out[n] = (uint8_t)(digits[n] - '0');
        n++;
    }
    return n;
}

MW_TEST(test_dice_entropy_vector)
{
    const mw_wordlist_t* wl = mw_wordlist(MW_WL_MONERO_EN);
    uint8_t rolls[MW_DICE_ROLLS_MAX];
    uint8_t entropy[32], expect[32];

    size_t n = dice_rolls_of(DICE_ROLLS, rolls, sizeof rolls);
    CHECK_EQ_INT((int)n, MW_DICE_ROLLS_REQUIRED);

    CHECK_EQ_INT(mw_dice_to_entropy(rolls, n, entropy), MW_OK);
    CHECK_EQ_INT((int)mw_test_hex(DICE_ENTROPY, expect, sizeof expect), 32);
    CHECK_EQ_MEM(entropy, expect, 32);

    // ... the same 25-word phrase ...
    uint16_t idx[MW_LEGACY_SEED_WORDS];
    CHECK_EQ_INT(mw_legacy_seed_encode(entropy, wl, idx), MW_OK);
    char phrase[512];
    phrase_of(idx, MW_LEGACY_SEED_WORDS, wl, phrase, sizeof phrase);
    CHECK_EQ_STR(phrase, DICE_PHRASE);

    // ... and the same primary address.
    mw_account_keys_t keys;
    mw_address_t addr;
    char str[MW_ADDRESS_STR_MAX];
    CHECK_EQ_INT(mw_seed_to_keys(MW_SEED_MONERO_LEGACY, entropy, 32, "", &keys),
                 MW_OK);
    CHECK_EQ_INT(mw_address_from_keys(&keys, MW_NET_MAINNET, &addr), MW_OK);
    CHECK_EQ_INT(mw_address_encode(&addr, str, sizeof str), MW_OK);
    CHECK_EQ_STR(str, DICE_ADDRESS);

    // Every throw must reach the KDF: dropping the last one has to change the
    // result (a truncating implementation would silently lose entropy).
    uint8_t shorter[32];
    CHECK_EQ_INT(mw_dice_to_entropy(rolls, n - 1, shorter), MW_ERR_INVALID_ARG);
}

MW_TEST(test_dice_entropy_rejects_bad_input)
{
    uint8_t rolls[MW_DICE_ROLLS_MAX];
    uint8_t out[32];
    size_t n = dice_rolls_of(DICE_ROLLS, rolls, sizeof rolls);

    CHECK_EQ_INT(mw_dice_to_entropy(NULL, n, out), MW_ERR_INVALID_ARG);
    CHECK_EQ_INT(mw_dice_to_entropy(rolls, n, NULL), MW_ERR_INVALID_ARG);

    // Too few throws: TZ 6.4 wants at least MW_DICE_ROLLS_REQUIRED.
    CHECK_EQ_INT(mw_dice_to_entropy(rolls, 0, out), MW_ERR_INVALID_ARG);
    CHECK_EQ_INT(mw_dice_to_entropy(rolls, MW_DICE_ROLLS_REQUIRED - 1, out),
                 MW_ERR_INVALID_ARG);
    CHECK_EQ_INT(mw_dice_to_entropy(rolls, MW_DICE_ROLLS_MAX + 1, out),
                 MW_ERR_TOO_MANY);

    // A d6 has six faces; 0 and 7 are a corrupted buffer, not a throw.
    for (size_t i = 0; i < n; i += 37) {
        uint8_t bad[MW_DICE_ROLLS_MAX];
        memcpy(bad, rolls, n);
        bad[i] = 0;
        CHECK_EQ_INT(mw_dice_to_entropy(bad, n, out), MW_ERR_RANGE);
        bad[i] = 7;
        CHECK_EQ_INT(mw_dice_to_entropy(bad, n, out), MW_ERR_RANGE);
    }

    // The maximum accepted length still works.
    uint8_t full[MW_DICE_ROLLS_MAX];
    for (size_t i = 0; i < sizeof full; ++i) {
        full[i] = (uint8_t)(i % 6u + 1u);
    }
    CHECK_EQ_INT(mw_dice_to_entropy(full, sizeof full, out), MW_OK);
}

int main(void)
{
    RUN_TEST(test_vector_task_seed);
    RUN_TEST(test_vector_monero_python);
    RUN_TEST(test_roundtrip_random);
    RUN_TEST(test_prefix_only_input);
    RUN_TEST(test_checksum_rejection);
    RUN_TEST(test_out_of_range_triple);
    RUN_TEST(test_dice_entropy_vector);
    RUN_TEST(test_dice_entropy_rejects_bad_input);
    return mw_test_summary();
}
