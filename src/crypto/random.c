#if defined(MW_HOST_BUILD) && defined(_WIN32)
#define _CRT_RAND_S   // rand_s() in <stdlib.h>; must precede every system header
#endif
// RNG layer (TZ 8.2).
//
// Device build : entropy comes from the ESP32 hardware TRNG (esp_random()
//                after bootloader_random_enable()).
// Host build   : entropy comes from /dev/urandom, or from the deterministic
//                test stream installed with mw_random_set_test_source().
//
// In both cases the raw entropy only ever seeds a ChaCha20 DRBG; callers get
// DRBG output, and the DRBG rekeys itself from its own stream after every
// request so a state compromise cannot reveal earlier outputs.
#include "random.h"
#include "chacha.h"
#include "hash.h"
#include "memzero.h"
#include "ed25519.h"

#include <string.h>

#if defined(MW_HOST_BUILD)
#include <stdlib.h>
#include <stdio.h>
#else
#ifdef ARDUINO
#include "esp_random.h"
#include "esp_system.h"
#include "bootloader_random.h"
#endif
#endif

// ---------------------------------------------------------------------------
// SP 800-90B health-test parameters.
//
// Samples are bytes; the assumed min-entropy is a deliberately pessimistic
// H = 4 bits per byte, and alpha = 2^-30.
//
//   Repetition Count Test  : C = 1 + ceil(-log2(alpha) / H) = 1 + ceil(30/4) = 9
//   Adaptive Proportion    : W = 512, C = 71
//                            (smallest C with P[Binomial(512, 1/16) >= C] < 2^-30)
// ---------------------------------------------------------------------------
#define MW_RCT_CUTOFF 9
#define MW_APT_WINDOW 512
#define MW_APT_CUTOFF 71
#define MW_SELFTEST_SAMPLE (MW_APT_WINDOW * 2)

// ---------------------------------------------------------------------------
// DRBG state
// ---------------------------------------------------------------------------
typedef struct {
    mw_chacha_key key;
    uint64_t      counter;      // folded into the IV so blocks never repeat
    int           initialised;
} mw_drbg_t;

static mw_drbg_t g_drbg;

#if defined(MW_HOST_BUILD)
static const uint8_t* g_test_stream     = NULL;
static size_t         g_test_stream_len = 0;
#endif

// Collects `len` bytes of raw entropy from the platform source.
// Returns 0 on success.
static int raw_entropy(uint8_t* out, size_t len) {
#if defined(MW_HOST_BUILD)
    if (g_test_stream != NULL && g_test_stream_len > 0) {
        // Deterministic host mode: expand the caller's stream with Keccak so
        // a short seed still fills an arbitrary request.
        uint8_t block[MW_KECCAK_DIGEST + 8];
        uint64_t ctr = 0;
        while (len > 0) {
            mw_keccak_ctx ctx;
            uint8_t digest[MW_KECCAK_DIGEST];
            mw_keccak_init(&ctx);
            mw_keccak_update(&ctx, (const uint8_t*)"mw-test-entropy", 15);
            mw_keccak_update(&ctx, g_test_stream, g_test_stream_len);
            for (int i = 0; i < 8; ++i) {
                block[i] = (uint8_t)(ctr >> (8 * i));
            }
            mw_keccak_update(&ctx, block, 8);
            mw_keccak_final(&ctx, digest);
            size_t take = (len < MW_KECCAK_DIGEST) ? len : (size_t)MW_KECCAK_DIGEST;
            memcpy(out, digest, take);
            out += take;
            len -= take;
            ctr++;
            mw_memzero(digest, sizeof(digest));
        }
        mw_memzero(block, sizeof(block));
        return 0;
    }
#if defined(_WIN32)
    // Windows host (w64devkit / MinGW): no /dev/urandom. rand_s() draws from
    // RtlGenRandom, the OS CSPRNG.
    while (len > 0) {
        unsigned int v = 0;
        if (rand_s(&v) != 0) {
            return -1;
        }
        size_t take = (len < sizeof(v)) ? len : sizeof(v);
        memcpy(out, &v, take);
        out += take;
        len -= take;
    }
    return 0;
#else
    {
        FILE* f = fopen("/dev/urandom", "rb");
        if (f == NULL) {
            return -1;
        }
        size_t got = fread(out, 1, len, f);
        fclose(f);
        return (got == len) ? 0 : -1;
    }
#endif
#elif defined(ARDUINO)
    while (len > 0) {
        uint32_t v = esp_random();
        size_t take = (len < 4) ? len : 4;
        memcpy(out, &v, take);
        out += take;
        len -= take;
        v = 0;
        (void)v;
    }
    return 0;
#else
    (void)out;
    (void)len;
    return -1;
#endif
}

// Generates `len` bytes of DRBG output and rekeys afterwards.
static void drbg_generate(uint8_t* out, size_t len) {
    mw_chacha_iv iv;
    uint8_t      newkey[MW_CHACHA_KEY_SIZE];

    for (int i = 0; i < 8; ++i) {
        iv.data[i] = (uint8_t)(g_drbg.counter >> (8 * i));
    }
    g_drbg.counter++;

    if (len > 0) {
        memset(out, 0, len);
        mw_chacha20(out, len, &g_drbg.key, &iv, out);
    }

    // Rekey from a fresh keystream block so past output stays unreachable.
    for (int i = 0; i < 8; ++i) {
        iv.data[i] = (uint8_t)(g_drbg.counter >> (8 * i));
    }
    g_drbg.counter++;
    memset(newkey, 0, sizeof(newkey));
    mw_chacha20(newkey, sizeof(newkey), &g_drbg.key, &iv, newkey);
    memcpy(g_drbg.key.data, newkey, MW_CHACHA_KEY_SIZE);

    mw_memzero(newkey, sizeof(newkey));
    mw_memzero(&iv, sizeof(iv));
}

static mw_rng_status_t drbg_reseed(void) {
    uint8_t seed[64];
    uint8_t digest[MW_KECCAK_DIGEST];

    if (raw_entropy(seed, sizeof(seed)) != 0) {
        mw_memzero(seed, sizeof(seed));
        return MW_RNG_ERR_NOT_INIT;
    }
    // Mix the fresh entropy with whatever key we already had.
    {
        mw_keccak_ctx ctx;
        mw_keccak_init(&ctx);
        mw_keccak_update(&ctx, g_drbg.key.data, MW_CHACHA_KEY_SIZE);
        mw_keccak_update(&ctx, seed, sizeof(seed));
        mw_keccak_final(&ctx, digest);
    }
    memcpy(g_drbg.key.data, digest, MW_CHACHA_KEY_SIZE);
    g_drbg.counter    = 0;
    g_drbg.initialised = 1;

    mw_memzero(seed, sizeof(seed));
    mw_memzero(digest, sizeof(digest));
    return MW_RNG_OK;
}

// ---------------------------------------------------------------------------
// SP 800-90B style health tests
// ---------------------------------------------------------------------------

// Repetition Count Test: fail when the same byte value appears MW_RCT_CUTOFF
// times in a row.
static int rct_check(const uint8_t* s, size_t len) {
    if (len == 0) {
        return 0;
    }
    uint8_t prev = s[0];
    unsigned run = 1;
    for (size_t i = 1; i < len; ++i) {
        if (s[i] == prev) {
            if (++run >= MW_RCT_CUTOFF) {
                return -1;
            }
        } else {
            prev = s[i];
            run  = 1;
        }
    }
    return 0;
}

// Adaptive Proportion Test: in every window of MW_APT_WINDOW samples, the
// first sample of the window must not reappear MW_APT_CUTOFF times or more.
static int apt_check(const uint8_t* s, size_t len) {
    size_t pos = 0;
    while (pos + MW_APT_WINDOW <= len) {
        uint8_t  a = s[pos];
        unsigned c = 0;
        for (size_t i = 0; i < MW_APT_WINDOW; ++i) {
            if (s[pos + i] == a) {
                c++;
            }
        }
        if (c >= MW_APT_CUTOFF) {
            return -1;
        }
        pos += MW_APT_WINDOW;
    }
    return 0;
}

mw_rng_status_t mw_random_selftest(void) {
    uint8_t sample[MW_SELFTEST_SAMPLE];
    mw_rng_status_t st = MW_RNG_OK;

    if (!g_drbg.initialised) {
        return MW_RNG_ERR_NOT_INIT;
    }

    // Test the raw platform entropy, which is what the tests are actually
    // about; a stuck TRNG must be detected even though the DRBG would keep
    // producing healthy-looking output.
    if (raw_entropy(sample, sizeof(sample)) != 0) {
        return MW_RNG_ERR_NOT_INIT;
    }
    if (rct_check(sample, sizeof(sample)) != 0 ||
        apt_check(sample, sizeof(sample)) != 0) {
        st = MW_RNG_ERR_SELFTEST;
        goto done;
    }

    // Identical-block test: two independent 32-byte draws must differ.
    {
        uint8_t a[32], b[32];
        drbg_generate(a, sizeof(a));
        drbg_generate(b, sizeof(b));
        int same = mw_ct_equal(a, b, sizeof(a));
        mw_memzero(a, sizeof(a));
        mw_memzero(b, sizeof(b));
        if (same) {
            st = MW_RNG_ERR_STUCK;
            goto done;
        }
    }

done:
    mw_memzero(sample, sizeof(sample));
    return st;
}

// ---------------------------------------------------------------------------
// Public API
// ---------------------------------------------------------------------------

mw_rng_status_t mw_random_init(void) {
#if !defined(MW_HOST_BUILD) && defined(ARDUINO)
    bootloader_random_enable();
#endif
    memset(&g_drbg, 0, sizeof(g_drbg));

    mw_rng_status_t st = drbg_reseed();
    if (st != MW_RNG_OK) {
        return st;
    }
    return mw_random_selftest();
}

// Fail closed (audit round 2, item 1). Random bytes feed IVs, the fake
// responses of CLSAG and the blinding factors of Bulletproofs+; zeros there
// would make the real input distinguishable in the signature itself, i.e.
// visible to anyone reading the chain. There is no safe value to return, so
// the operation is stopped: on the device the chip restarts (the crash crumb
// tells the PC which operation it was), on the host the test aborts.
static void rng_fatal(const char* why) {
#if defined(MW_HOST_BUILD)
    fprintf(stderr, "mw_random: %s - aborting\n", why);
    abort();
#elif defined(ARDUINO)
    esp_system_abort(why);
#else
    (void)why;
    for (;;) { }
#endif
}

void mw_random_bytes(void* out, size_t len) {
    if (!g_drbg.initialised) {
        // Late initialisation: never hand back predictable bytes.
        if (drbg_reseed() != MW_RNG_OK) {
            if (out && len) memset(out, 0, len);   // never left as garbage
            rng_fatal("no entropy source");
            return;
        }
    }
    drbg_generate((uint8_t*)out, len);
}

void mw_random_hedged_scalar(void* scalar_out,
                             const uint8_t* context, size_t context_len) {
    uint8_t       trng[32];
    mw_keccak_ctx ctx;
    uint8_t       digest[MW_KECCAK_DIGEST];
    mw_scalar_t*  s = (mw_scalar_t*)scalar_out;

    mw_random_bytes(trng, sizeof(trng));

    // k = hash_to_scalar(TRNG(32) || context). Even a fully predictable TRNG
    // leaves the deterministic context, and a context collision is still
    // masked by the TRNG half.
    mw_keccak_init(&ctx);
    mw_keccak_update(&ctx, trng, sizeof(trng));
    if (context != NULL && context_len > 0) {
        mw_keccak_update(&ctx, context, context_len);
    }
    mw_keccak_final(&ctx, digest);

    memcpy(s->b, digest, 32);
    mw_sc_reduce32(s);

    mw_memzero(trng, sizeof(trng));
    mw_memzero(digest, sizeof(digest));
}

void mw_random_set_test_source(const uint8_t* stream, size_t len) {
#if defined(MW_HOST_BUILD)
    g_test_stream     = stream;
    g_test_stream_len = len;
    memset(&g_drbg, 0, sizeof(g_drbg));
    (void)drbg_reseed();
#else
    (void)stream;
    (void)len;
#endif
}
