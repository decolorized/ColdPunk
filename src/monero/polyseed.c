// Polyseed (16 words, 150-bit secret) - a bit-compatible port of
// tevador/polyseed (Apache-2.0): gf.c, storage.c, birthday.h, features.h and
// polyseed.c.  TZ 5.1 / 6.3.
//
// Layout of the 16 GF(2048) coefficients:
//   coeff[0]      checksum digit
//   coeff[1..15]  15 data words, each carrying 10 bits of the secret plus one
//                 bit of the 15-bit "extra" value (5 feature bits followed by
//                 10 birthday bits, most significant first)
// The polynomial is evaluated with Horner's method at x = 2 over GF(2^11)
// (reduction table polyseed_mul2_table) and the coin id is XORed into
// coeff[1] so that a phrase for one coin never validates for another.
#include "mnemonic.h"

#include <string.h>

#include "../crypto/hash.h"
#include "../crypto/memzero.h"

// ---------------------------------------------------------------- constants
#define GF_BITS               11
#define GF_SIZE               (1u << GF_BITS)
#define GF_MASK               (GF_SIZE - 1)
#define POLY_NUM_CHECK_DIGITS 1
#define POLY_NUM_WORDS        MW_POLYSEED_WORDS
#define DATA_WORDS            (POLY_NUM_WORDS - POLY_NUM_CHECK_DIGITS)
#define SHARE_BITS            10          // bits of the secret per word

#define SECRET_BITS           MW_POLYSEED_SECRET_BITS      // 150
#define SECRET_SIZE           MW_POLYSEED_SECRET_SIZE      // 19
#define SECRET_BUFFER_SIZE    32
#define CLEAR_BITS            (SECRET_SIZE * 8 - SECRET_BITS)    // 2
#define CLEAR_MASK            ((uint8_t)~(uint8_t)(((1u << CLEAR_BITS) - 1) << (8 - CLEAR_BITS)))

#define DATE_BITS             MW_POLYSEED_DATE_BITS        // 10
#define DATE_MASK             ((1u << DATE_BITS) - 1)
#define FEATURE_BITS          MW_POLYSEED_FEATURE_BITS     // 5
#define FEATURE_MASK          ((1u << FEATURE_BITS) - 1)

#define USER_FEATURES         3
#define USER_FEATURES_MASK    ((1u << USER_FEATURES) - 1)
#define ENCRYPTED_MASK        16u

#define KDF_NUM_ITERATIONS    10000

// No polyseed_enable_features() equivalent is exposed: the device supports the
// encryption bit only, exactly like an unconfigured upstream library.
#define RESERVED_FEATURES     (FEATURE_MASK ^ ENCRYPTED_MASK)   // 15

typedef uint16_t gf_elem;

typedef struct {
    gf_elem coeff[POLY_NUM_WORDS];
} gf_poly;

static const gf_elem polyseed_mul2_table[8] = { 5, 7, 1, 3, 13, 15, 9, 11 };

static gf_elem gf_elem_mul2(gf_elem x)
{
    if (x < 1024) {
        return (gf_elem)(2 * x);
    }
    return (gf_elem)(polyseed_mul2_table[x % 8] + 16 * ((x - 1024) / 8));
}

static gf_elem gf_poly_eval(const gf_poly* poly)
{
    // Horner's method at x = 2.
    gf_elem result = poly->coeff[POLY_NUM_WORDS - 1];
    for (int i = POLY_NUM_WORDS - 2; i >= 0; --i) {
        result = (gf_elem)(gf_elem_mul2(result) ^ poly->coeff[i]);
    }
    return result;
}

static void gf_poly_encode(gf_poly* message)
{
    message->coeff[0] = gf_poly_eval(message);
}

static int gf_poly_check(const gf_poly* message)
{
    return gf_poly_eval(message) == 0;
}

static int features_supported(unsigned features)
{
    return (features & RESERVED_FEATURES) == 0;
}

#define MINU(a, b) ((a) < (b) ? (a) : (b))

// ------------------------------------------------------- poly <-> seed data
static void data_to_poly(const mw_polyseed_t* data, gf_poly* poly)
{
    unsigned extra_val = (data->features << DATE_BITS) | data->birthday;
    unsigned extra_bits = FEATURE_BITS + DATE_BITS;

    unsigned word_bits = 0;
    unsigned word_val = 0;

    unsigned secret_idx = 0;
    unsigned secret_val = data->secret[secret_idx];
    unsigned secret_bits = 8;
    unsigned seed_rem_bits = SECRET_BITS - 8;

    for (int i = 0; i < DATA_WORDS; ++i) {
        while (word_bits < SHARE_BITS) {
            if (secret_bits == 0) {
                secret_idx++;
                secret_bits = MINU(seed_rem_bits, 8u);
                secret_val = data->secret[secret_idx];
                seed_rem_bits -= secret_bits;
            }
            unsigned chunk_bits = MINU(secret_bits, SHARE_BITS - word_bits);
            secret_bits -= chunk_bits;
            word_bits += chunk_bits;
            word_val <<= chunk_bits;
            word_val |= (secret_val >> secret_bits) & ((1u << chunk_bits) - 1);
        }
        word_val <<= 1;
        extra_bits--;
        word_val |= (extra_val >> extra_bits) & 1;
        poly->coeff[POLY_NUM_CHECK_DIGITS + i] = (gf_elem)word_val;
        word_val = 0;
        word_bits = 0;
    }
}

static void poly_to_data(const gf_poly* poly, mw_polyseed_t* data)
{
    data->birthday = 0;
    data->features = 0;
    memset(data->secret, 0, sizeof(data->secret));
    data->checksum = poly->coeff[0];

    unsigned extra_val = 0;
    unsigned word_bits = 0;
    unsigned word_val = 0;
    unsigned secret_idx = 0;
    unsigned secret_bits = 0;

    for (int i = POLY_NUM_CHECK_DIGITS; i < POLY_NUM_WORDS; ++i) {
        word_val = poly->coeff[i];

        extra_val <<= 1;
        extra_val |= word_val & 1;
        word_val >>= 1;
        word_bits = GF_BITS - 1;

        while (word_bits > 0) {
            if (secret_bits == 8) {
                secret_idx++;
                secret_bits = 0;
            }
            unsigned chunk_bits = MINU(word_bits, 8u - secret_bits);
            word_bits -= chunk_bits;
            unsigned chunk_mask = (1u << chunk_bits) - 1;
            if (chunk_bits < 8) {
                data->secret[secret_idx] = (uint8_t)(data->secret[secret_idx] << chunk_bits);
            }
            data->secret[secret_idx] |= (uint8_t)((word_val >> word_bits) & chunk_mask);
            secret_bits += chunk_bits;
        }
    }

    data->birthday = extra_val & DATE_MASK;
    data->features = extra_val >> DATE_BITS;
}

// ------------------------------------------------------------------ birthday
static unsigned birthday_encode(uint64_t time)
{
    if (time == (uint64_t)-1 || time < MW_POLYSEED_EPOCH) {
        return 0;
    }
    return (unsigned)(((time - MW_POLYSEED_EPOCH) / MW_POLYSEED_TIME_STEP) & DATE_MASK);
}

static uint64_t birthday_decode(unsigned birthday)
{
    return MW_POLYSEED_EPOCH + (uint64_t)birthday * MW_POLYSEED_TIME_STEP;
}

// --------------------------------------------------------------- public API
mw_err_t mw_polyseed_create(const uint8_t* entropy, size_t entropy_len,
                            uint64_t unix_time, unsigned features,
                            mw_polyseed_t* out)
{
    if (entropy == NULL || out == NULL || entropy_len < SECRET_SIZE) {
        return MW_ERR_INVALID_ARG;
    }

    unsigned seed_features = features & USER_FEATURES_MASK;
    if (seed_features != features || !features_supported(seed_features)) {
        // User feature bits need an explicit opt-in that this build does not
        // provide, so only features == 0 can be created here.
        return MW_ERR_NOT_SUPPORTED;
    }

    memset(out, 0, sizeof(*out));
    out->birthday = birthday_encode(unix_time);
    out->features = seed_features;
    memcpy(out->secret, entropy, SECRET_SIZE);
    out->secret[SECRET_SIZE - 1] &= CLEAR_MASK;

    gf_poly poly;
    memset(&poly, 0, sizeof(poly));
    data_to_poly(out, &poly);
    gf_poly_encode(&poly);
    out->checksum = poly.coeff[0];

    mw_memzero(&poly, sizeof(poly));
    return MW_OK;
}

mw_err_t mw_polyseed_encode(const mw_polyseed_t* seed, const mw_wordlist_t* wl,
                            uint16_t indices_out[MW_POLYSEED_WORDS])
{
    if (seed == NULL || indices_out == NULL || wl == NULL ||
        wl->words == NULL || wl->count < GF_SIZE) {
        return MW_ERR_INVALID_ARG;
    }
    if (seed->birthday > DATE_MASK || seed->features > FEATURE_MASK) {
        return MW_ERR_INVALID_ARG;
    }

    gf_poly poly;
    memset(&poly, 0, sizeof(poly));
    poly.coeff[0] = seed->checksum;
    data_to_poly(seed, &poly);

    // Domain-separate by coin (Monero == 0, so this is a no-op today).
    poly.coeff[POLY_NUM_CHECK_DIGITS] ^= (gf_elem)MW_POLYSEED_COIN_MONERO;

    for (int i = 0; i < POLY_NUM_WORDS; ++i) {
        indices_out[i] = poly.coeff[i];
    }

    mw_memzero(&poly, sizeof(poly));
    return MW_OK;
}

mw_err_t mw_polyseed_decode(const uint16_t indices[MW_POLYSEED_WORDS],
                            const mw_wordlist_t* wl, mw_polyseed_t* out)
{
    if (indices == NULL || out == NULL || wl == NULL ||
        wl->words == NULL || wl->count < GF_SIZE) {
        return MW_ERR_INVALID_ARG;
    }

    gf_poly poly;
    memset(&poly, 0, sizeof(poly));
    for (int i = 0; i < POLY_NUM_WORDS; ++i) {
        if (indices[i] >= GF_SIZE) {
            return MW_ERR_UNKNOWN_WORD;
        }
        poly.coeff[i] = indices[i];
    }

    poly.coeff[POLY_NUM_CHECK_DIGITS] ^= (gf_elem)MW_POLYSEED_COIN_MONERO;

    if (!gf_poly_check(&poly)) {
        mw_memzero(&poly, sizeof(poly));
        return MW_ERR_CHECKSUM;
    }

    poly_to_data(&poly, out);
    mw_memzero(&poly, sizeof(poly));

    if (!features_supported(out->features)) {
        mw_memzero(out, sizeof(*out));
        return MW_ERR_NOT_SUPPORTED;
    }
    return MW_OK;
}

// ------------------------------------------------- serialized seed context
// birthday(2, LE) || features(1) || secret. Keeping the birthday and the
// feature bits with the secret is not optional: mw_polyseed_keygen() salts the
// KDF with all three, so a context that loses them derives a different, and
// for any real phrase a foreign, spend key.
mw_err_t mw_polyseed_pack(const mw_polyseed_t* seed, uint8_t* out, size_t cap,
                          size_t* len_out)
{
    if (seed == NULL || out == NULL || len_out == NULL) {
        return MW_ERR_INVALID_ARG;
    }
    if (cap < MW_POLYSEED_BLOB_MIN) {
        return MW_ERR_MEMORY;
    }
    if (seed->birthday > DATE_MASK || seed->features > FEATURE_MASK) {
        return MW_ERR_INVALID_ARG;
    }

    out[0] = (uint8_t)(seed->birthday & 0xffu);
    out[1] = (uint8_t)((seed->birthday >> 8) & 0xffu);
    out[2] = (uint8_t)seed->features;
    memcpy(out + MW_POLYSEED_BLOB_HDR, seed->secret, SECRET_SIZE);
    *len_out = MW_POLYSEED_BLOB_MIN;
    return MW_OK;
}

mw_err_t mw_polyseed_unpack(const uint8_t* blob, size_t len, mw_polyseed_t* out)
{
    if (blob == NULL || out == NULL) {
        return MW_ERR_INVALID_ARG;
    }
    if (len < MW_POLYSEED_BLOB_MIN || len > MW_POLYSEED_BLOB_MAX) {
        return MW_ERR_INVALID_ARG;
    }

    unsigned birthday = (unsigned)blob[0] | ((unsigned)blob[1] << 8);
    unsigned features = blob[2];
    if (birthday > DATE_MASK || features > FEATURE_MASK) {
        return MW_ERR_FORMAT;
    }

    memset(out, 0, sizeof(*out));
    out->birthday = birthday;
    out->features = features;
    memcpy(out->secret, blob + MW_POLYSEED_BLOB_HDR, len - MW_POLYSEED_BLOB_HDR);

    // The checksum belongs to the phrase, not to the context; recompute it so
    // the struct is self-consistent for mw_polyseed_encode().
    gf_poly poly;
    memset(&poly, 0, sizeof(poly));
    data_to_poly(out, &poly);
    gf_poly_encode(&poly);
    out->checksum = poly.coeff[0];
    mw_memzero(&poly, sizeof(poly));
    return MW_OK;
}

static void store32le(uint8_t* p, uint32_t u)
{
    p[0] = (uint8_t)u;
    p[1] = (uint8_t)(u >> 8);
    p[2] = (uint8_t)(u >> 16);
    p[3] = (uint8_t)(u >> 24);
}

void mw_polyseed_keygen(const mw_polyseed_t* seed, uint32_t coin,
                        uint8_t key_out[32])
{
    if (seed == NULL || key_out == NULL) {
        return;
    }

    // salt = "POLYSEED key" 0x00 0xff 0xff 0xff | coin | birthday | features
    uint8_t salt[32];
    memset(salt, 0, sizeof(salt));
    memcpy(salt, "POLYSEED key", 12);
    salt[13] = 0xff;
    salt[14] = 0xff;
    salt[15] = 0xff;
    store32le(&salt[16], coin);
    store32le(&salt[20], (uint32_t)seed->birthday);
    store32le(&salt[24], (uint32_t)seed->features);

    // The password is the whole zero-padded 32-byte secret buffer.
    mw_pbkdf2_sha256(seed->secret, SECRET_BUFFER_SIZE, salt, sizeof(salt),
                     KDF_NUM_ITERATIONS, key_out, 32);

    mw_memzero(salt, sizeof(salt));
}

void mw_polyseed_crypt(mw_polyseed_t* seed, const char* password)
{
    if (seed == NULL || password == NULL) {
        return;
    }

    // Upstream normalizes the password to NFKD first. The device keyboard only
    // produces ASCII, which is already NFKD, so the bytes are used as-is.
    size_t pw_len = strlen(password);

    uint8_t salt[16];
    memset(salt, 0, sizeof(salt));
    memcpy(salt, "POLYSEED mask", 13);
    salt[14] = 0xff;
    salt[15] = 0xff;

    uint8_t mask[32];
    mw_pbkdf2_sha256((const uint8_t*)password, pw_len, salt, sizeof(salt),
                     KDF_NUM_ITERATIONS, mask, sizeof(mask));

    for (int i = 0; i < SECRET_SIZE; ++i) {
        seed->secret[i] ^= mask[i];
    }
    seed->secret[SECRET_SIZE - 1] &= CLEAR_MASK;
    seed->features ^= ENCRYPTED_MASK;

    gf_poly poly;
    memset(&poly, 0, sizeof(poly));
    data_to_poly(seed, &poly);
    gf_poly_encode(&poly);
    seed->checksum = poly.coeff[0];

    mw_memzero(&poly, sizeof(poly));
    mw_memzero(mask, sizeof(mask));
    mw_memzero(salt, sizeof(salt));
}

int mw_polyseed_is_encrypted(const mw_polyseed_t* seed)
{
    if (seed == NULL) {
        return 0;
    }
    return (seed->features & ENCRYPTED_MASK) != 0 ? 1 : 0;
}

uint64_t mw_polyseed_birthday_time(const mw_polyseed_t* seed)
{
    if (seed == NULL) {
        return 0;
    }
    return birthday_decode(seed->birthday);
}

// Restore height (TZ 6.3) - APPROXIMATE BY CONSTRUCTION.
//
// Monero targets one block every 120 s, so a timestamp is converted with a
// single linear anchor:
//     height ~= anchor_height + (t - anchor_time) / 120
// Mainnet anchor: height 2 500 000 was mined around the Polyseed epoch
// (1635768000 = 2021-11-01 12:00 UTC). Real block times drift by minutes and
// the chain is not scheduled, so the result can be off by thousands of blocks;
// it is a scan hint, never an exact height.
// Stagenet/testnet have no authoritative anchor here: their values are rough
// estimates derived from the same 120 s target and are rounded DOWN on
// purpose, because starting the scan too early only costs time while starting
// too late silently hides funds.
#define MW_BLOCK_TIME_SEC 120

uint32_t mw_polyseed_restore_height(const mw_polyseed_t* seed, mw_network_t net)
{
    if (seed == NULL) {
        return 0;
    }

    // wallet2::get_approximate_blockchain_height(): height of the v2 fork plus
    // the seconds since it at 120 s per block (DIFFICULTY_TARGET_V2). The old
    // fixed anchor (2 500 000 at the polyseed epoch) was ~15 000 blocks too
    // high on mainnet, i.e. a restore could start AFTER the first payments.
    uint64_t fork_time, fork_block;
    switch (net) {
    case MW_NET_TESTNET:  fork_time = 1448285909ULL; fork_block = 624634ULL;  break;
    case MW_NET_STAGENET: fork_time = 1520937818ULL; fork_block = 32000ULL;   break;
    case MW_NET_MAINNET:
    default:              fork_time = 1458748658ULL; fork_block = 1009827ULL; break;
    }

    // The birthday is already rounded down to its time step; on top of that
    // a week of margin covers the drift of the real chain from the estimate.
    // Starting a little early only costs scanning time, starting late loses
    // payments.
    const uint64_t margin = 7ULL * 24 * 3600 / MW_BLOCK_TIME_SEC;

    uint64_t t = birthday_decode(seed->birthday);
    if (t < MW_POLYSEED_EPOCH) t = MW_POLYSEED_EPOCH;
    uint64_t height = fork_block + (t > fork_time ? (t - fork_time) / MW_BLOCK_TIME_SEC : 0);
    height = (height > margin) ? height - margin : 0;
    if (height > 0xFFFFFFFFULL) {
        height = 0xFFFFFFFFULL;
    }
    return (uint32_t)height;
}
