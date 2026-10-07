// Polyseed (16 words, GF(2048)) - TZ 5.1, 6.3.
//
// The known-answer vectors come from tevador/polyseed's own test suite:
// the English phrase below is upstream's test phrase, and its expected secret
// and KDF salt are the ones upstream's fake PBKDF2 asserts on
// (tests/tests.c: pbkdf2_dummy1). The expected 32-byte key was computed
// independently with Python's hashlib.pbkdf2_hmac.
#include "test_framework.h"

#include "monero/mnemonic.h"
#include "data/wordlist.h"

#define UPSTREAM_PHRASE \
    "raven tail swear infant grief assist regular lamp duck valid " \
    "someone little harsh puppy airport language"
#define UPSTREAM_SECRET "dd76e7359a0ded37cd0ff0f3c829a5ae016733"

static uint32_t rng_state = 0xdeadbeefu;

static uint32_t rng_next(void)
{
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

// Local copy of the GF(2048) arithmetic, used only to forge phrases with a
// valid checksum but hostile contents.
static uint16_t gf_mul2(uint16_t x)
{
    static const uint16_t tab[8] = { 5, 7, 1, 3, 13, 15, 9, 11 };
    if (x < 1024) {
        return (uint16_t)(2 * x);
    }
    return (uint16_t)(tab[x % 8] + 16 * ((x - 1024) / 8));
}

static uint16_t gf_eval(const uint16_t* coeff)
{
    uint16_t r = coeff[MW_POLYSEED_WORDS - 1];
    for (int i = MW_POLYSEED_WORDS - 2; i >= 0; --i) {
        r = (uint16_t)(gf_mul2(r) ^ coeff[i]);
    }
    return r;
}

// Recomputes coeff[0] so that the polynomial evaluates to zero again.
static void gf_fix_checksum(uint16_t* coeff)
{
    coeff[0] = 0;
    coeff[0] = gf_eval(coeff);
}

// -------------------------------------------------------------- test cases
MW_TEST(test_upstream_vector)
{
    const mw_wordlist_t* wl = mw_wordlist(MW_WL_POLYSEED_EN);

    uint16_t idx[MW_POLYSEED_WORDS];
    CHECK_EQ_INT(indices_of(UPSTREAM_PHRASE, wl, idx, MW_POLYSEED_WORDS),
                 MW_POLYSEED_WORDS);

    mw_polyseed_t seed;
    CHECK_EQ_INT(mw_polyseed_decode(idx, wl, &seed), MW_OK);
    CHECK_EQ_INT(seed.birthday, 1);
    CHECK_EQ_INT(seed.features, 0);
    CHECK_EQ_INT(mw_polyseed_is_encrypted(&seed), 0);

    uint8_t expect[32];
    memset(expect, 0, sizeof(expect));
    CHECK_EQ_INT(mw_test_hex(UPSTREAM_SECRET, expect, 32), 19);
    CHECK_EQ_MEM(seed.secret, expect, 32);

    // birthday 1 == EPOCH + one time step (2021-12-02 09:09:06 UTC)
    CHECK_EQ_INT(mw_polyseed_birthday_time(&seed),
                 (uint64_t)MW_POLYSEED_EPOCH + MW_POLYSEED_TIME_STEP);

    // Re-encoding must reproduce the very same words.
    uint16_t again[MW_POLYSEED_WORDS];
    CHECK_EQ_INT(mw_polyseed_encode(&seed, wl, again), MW_OK);
    CHECK_EQ_MEM(again, idx, sizeof(idx));

    // Truncated 4-character prefixes must decode to the same phrase.
    uint16_t pre[MW_POLYSEED_WORDS];
    CHECK_EQ_INT(indices_of("rave tail swea infan grie assi regul lamp duck "
                            "vali some litt hars pupp airp langua",
                            wl, pre, MW_POLYSEED_WORDS), MW_POLYSEED_WORDS);
    CHECK_EQ_MEM(pre, idx, sizeof(idx));
}

MW_TEST(test_keygen_vector)
{
    const mw_wordlist_t* wl = mw_wordlist(MW_WL_POLYSEED_EN);
    uint16_t idx[MW_POLYSEED_WORDS];
    indices_of(UPSTREAM_PHRASE, wl, idx, MW_POLYSEED_WORDS);

    mw_polyseed_t seed;
    CHECK_EQ_INT(mw_polyseed_decode(idx, wl, &seed), MW_OK);

    uint8_t key[32], expect[32];
    mw_polyseed_keygen(&seed, MW_POLYSEED_COIN_MONERO, key);
    mw_test_hex("21268a76048a3b25a4a9ac179d86b12f"
                "ab5800b8d858da9facf4b0a778dc2840", expect, 32);
    CHECK_EQ_MEM(key, expect, 32);

    // A different coin must produce a different key (salt domain separation).
    uint8_t other[32];
    mw_polyseed_keygen(&seed, 1, other);
    CHECK(memcmp(key, other, 32) != 0);
}

MW_TEST(test_crypt_vector)
{
    const mw_wordlist_t* wl = mw_wordlist(MW_WL_POLYSEED_EN);
    uint16_t idx[MW_POLYSEED_WORDS];
    indices_of(UPSTREAM_PHRASE, wl, idx, MW_POLYSEED_WORDS);

    mw_polyseed_t seed, original;
    CHECK_EQ_INT(mw_polyseed_decode(idx, wl, &seed), MW_OK);
    original = seed;

    mw_polyseed_crypt(&seed, "password");
    CHECK_EQ_INT(mw_polyseed_is_encrypted(&seed), 1);
    CHECK_EQ_INT(seed.features, 16);
    CHECK_EQ_INT(seed.birthday, original.birthday);
    CHECK(memcmp(seed.secret, original.secret, 19) != 0);

    // Expected ciphertext: secret XOR PBKDF2-SHA256("password",
    // "POLYSEED mask"\0\xff\xff, 10000), top two bits cleared.
    uint8_t expect[32];
    memset(expect, 0, sizeof(expect));
    mw_test_hex("551190ebb969f3166df2d5deff8075c52ce00e", expect, 32);
    CHECK_EQ_MEM(seed.secret, expect, 32);

    // The encrypted phrase must still carry a valid checksum ...
    uint16_t enc_idx[MW_POLYSEED_WORDS];
    CHECK_EQ_INT(mw_polyseed_encode(&seed, wl, enc_idx), MW_OK);
    mw_polyseed_t reloaded;
    CHECK_EQ_INT(mw_polyseed_decode(enc_idx, wl, &reloaded), MW_OK);
    CHECK_EQ_INT(mw_polyseed_is_encrypted(&reloaded), 1);
    CHECK_EQ_MEM(reloaded.secret, seed.secret, 32);

    // ... and applying it a second time restores the original seed.
    mw_polyseed_crypt(&reloaded, "password");
    CHECK_EQ_INT(mw_polyseed_is_encrypted(&reloaded), 0);
    CHECK_EQ_MEM(reloaded.secret, original.secret, 32);
    CHECK_EQ_INT(reloaded.checksum, original.checksum);
    CHECK_EQ_INT(reloaded.birthday, original.birthday);
    CHECK_EQ_INT(reloaded.features, original.features);
}

MW_TEST(test_create_roundtrip)
{
    const mw_wordlist_t* wl = mw_wordlist(MW_WL_POLYSEED_EN);
    int failures = 0;

    for (int iter = 0; iter < 1000; ++iter) {
        uint8_t entropy[19];
        rng_bytes(entropy, sizeof(entropy));
        uint64_t when = (uint64_t)MW_POLYSEED_EPOCH +
                        (uint64_t)(rng_next() % 3000000000u);

        mw_polyseed_t seed;
        if (mw_polyseed_create(entropy, sizeof(entropy), when, 0, &seed) != MW_OK) {
            failures++;
            continue;
        }
        // The two clear bits are dropped, everything else survives.
        entropy[18] &= 0x3f;
        if (memcmp(seed.secret, entropy, 19) != 0) {
            failures++;
        }
        for (int i = 19; i < 32; ++i) {
            if (seed.secret[i] != 0) {
                failures++;
            }
        }
        if (seed.birthday > 1023 || seed.features != 0) {
            failures++;
        }

        uint16_t idx[MW_POLYSEED_WORDS];
        if (mw_polyseed_encode(&seed, wl, idx) != MW_OK) {
            failures++;
            continue;
        }
        for (int i = 0; i < MW_POLYSEED_WORDS; ++i) {
            if (idx[i] >= 2048) {
                failures++;
            }
        }

        mw_polyseed_t back;
        if (mw_polyseed_decode(idx, wl, &back) != MW_OK ||
            memcmp(back.secret, seed.secret, 32) != 0 ||
            back.birthday != seed.birthday ||
            back.features != seed.features ||
            back.checksum != seed.checksum) {
            failures++;
        }
    }
    CHECK_EQ_INT(failures, 0);
}

MW_TEST(test_birthday)
{
    uint8_t entropy[19];
    memset(entropy, 0x42, sizeof(entropy));
    mw_polyseed_t seed;

    // Upstream SEED_TIME1 lands on birthday 1.
    CHECK_EQ_INT(mw_polyseed_create(entropy, sizeof(entropy), 1638446400u, 0, &seed),
                 MW_OK);
    CHECK_EQ_INT(seed.birthday, 1);

    // Anything at or before the epoch means "unknown".
    CHECK_EQ_INT(mw_polyseed_create(entropy, sizeof(entropy), 0, 0, &seed), MW_OK);
    CHECK_EQ_INT(seed.birthday, 0);
    CHECK_EQ_INT(mw_polyseed_create(entropy, sizeof(entropy), 1000000000u, 0, &seed),
                 MW_OK);
    CHECK_EQ_INT(seed.birthday, 0);
    CHECK_EQ_INT(mw_polyseed_birthday_time(&seed), MW_POLYSEED_EPOCH);
    // wallet2::get_approximate_blockchain_height() at the epoch, minus the
    // one-week margin: 1009827 + (1635768000 - 1458748658) / 120 - 5040.
    CHECK_EQ_INT(mw_polyseed_restore_height(&seed, MW_NET_MAINNET),
                 1009827 + (1635768000 - 1458748658) / 120 - 5040);
    CHECK(mw_polyseed_restore_height(&seed, MW_NET_MAINNET) < 2484988);

    // Exactly one time step later -> one 120-second block window per step.
    CHECK_EQ_INT(mw_polyseed_create(entropy, sizeof(entropy),
                                    MW_POLYSEED_EPOCH + MW_POLYSEED_TIME_STEP,
                                    0, &seed), MW_OK);
    CHECK_EQ_INT(seed.birthday, 1);
    CHECK_EQ_INT(mw_polyseed_restore_height(&seed, MW_NET_MAINNET),
                 1009827 + (1635768000 - 1458748658 + MW_POLYSEED_TIME_STEP) / 120 - 5040);
    CHECK(mw_polyseed_restore_height(&seed, MW_NET_STAGENET) <
          mw_polyseed_restore_height(&seed, MW_NET_MAINNET));

    // The 10-bit field wraps after 1024 steps (~85 years).
    CHECK_EQ_INT(mw_polyseed_create(entropy, sizeof(entropy),
                                    MW_POLYSEED_EPOCH + 1024 * MW_POLYSEED_TIME_STEP,
                                    0, &seed), MW_OK);
    CHECK_EQ_INT(seed.birthday, 0);
}

MW_TEST(test_rejections)
{
    const mw_wordlist_t* wl = mw_wordlist(MW_WL_POLYSEED_EN);
    uint16_t idx[MW_POLYSEED_WORDS];
    indices_of(UPSTREAM_PHRASE, wl, idx, MW_POLYSEED_WORDS);

    mw_polyseed_t seed;

    // Any single altered word breaks the GF(2048) checksum.
    for (int i = 0; i < MW_POLYSEED_WORDS; ++i) {
        uint16_t bad[MW_POLYSEED_WORDS];
        memcpy(bad, idx, sizeof(idx));
        bad[i] = (uint16_t)((bad[i] + 1) % 2048);
        CHECK_EQ_INT(mw_polyseed_decode(bad, wl, &seed), MW_ERR_CHECKSUM);
    }

    // Word index out of range.
    uint16_t bad[MW_POLYSEED_WORDS];
    memcpy(bad, idx, sizeof(idx));
    bad[5] = 2048;
    CHECK_EQ_INT(mw_polyseed_decode(bad, wl, &seed), MW_ERR_UNKNOWN_WORD);

    // An unknown word never resolves to an index in the first place.
    CHECK_EQ_INT(indices_of("raven tail notaword infant", wl, bad, 4), -1);
    // Nor does a 3-character stem of a longer word (prefix length is 4).
    CHECK_EQ_INT(indices_of("rav", wl, bad, 1), -1);

    // Reserved feature bits are refused, both on create and on decode.
    uint8_t entropy[19];
    memset(entropy, 0x11, sizeof(entropy));
    CHECK_EQ_INT(mw_polyseed_create(entropy, sizeof(entropy), 0, 1, &seed),
                 MW_ERR_NOT_SUPPORTED);
    CHECK_EQ_INT(mw_polyseed_create(entropy, sizeof(entropy), 0, 16, &seed),
                 MW_ERR_NOT_SUPPORTED);
    CHECK_EQ_INT(mw_polyseed_create(entropy, 10, 0, 0, &seed), MW_ERR_INVALID_ARG);
    CHECK_EQ_INT(mw_polyseed_create(NULL, 19, 0, 0, &seed), MW_ERR_INVALID_ARG);

    // Forge a phrase carrying user feature bit 0 (coefficient 5, bit 0) and a
    // repaired checksum: it must be rejected as unsupported, not accepted.
    memcpy(bad, idx, sizeof(idx));
    bad[5] ^= 1;
    gf_fix_checksum(bad);
    CHECK_EQ_INT(mw_polyseed_decode(bad, wl, &seed), MW_ERR_NOT_SUPPORTED);

    // The same forgery on coefficient 1 flips the "encrypted" bit, which IS
    // supported (that is how encrypted phrases travel).
    memcpy(bad, idx, sizeof(idx));
    bad[1] ^= 1;
    gf_fix_checksum(bad);
    CHECK_EQ_INT(mw_polyseed_decode(bad, wl, &seed), MW_OK);
    CHECK_EQ_INT(mw_polyseed_is_encrypted(&seed), 1);

    // Degenerate arguments.
    CHECK_EQ_INT(mw_polyseed_decode(NULL, wl, &seed), MW_ERR_INVALID_ARG);
    CHECK_EQ_INT(mw_polyseed_decode(idx, NULL, &seed), MW_ERR_INVALID_ARG);
    CHECK_EQ_INT(mw_polyseed_decode(idx, mw_wordlist(MW_WL_MONERO_EN), &seed),
                 MW_ERR_INVALID_ARG);   // 1626 words is too few for GF(2048)
    CHECK_EQ_INT(mw_polyseed_encode(&seed, wl, NULL), MW_ERR_INVALID_ARG);
}

int main(void)
{
    RUN_TEST(test_upstream_vector);
    RUN_TEST(test_keygen_vector);
    RUN_TEST(test_crypt_vector);
    RUN_TEST(test_create_roundtrip);
    RUN_TEST(test_birthday);
    RUN_TEST(test_rejections);
    return mw_test_summary();
}
