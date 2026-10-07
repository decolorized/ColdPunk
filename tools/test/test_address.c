// Monero base58 + address encoding (TZ 6.5, 12.3).
//
// The address vectors were generated with an independent Python implementation
// that reproduces the published monero-python vector
//   seed 73192a94...2d80 -> 49j9ikUyGfkSkPV8TY66p2RsSs6xL7NR5LauJTt7y6LZ...
// exactly, so they are anchored to real Monero behaviour.
#include "test_framework.h"

#include "monero/address.h"
#include "monero/monero_types.h"
#include "crypto/ed25519.h"

// Keys of the legacy test seed 3b094ca7...4109.
#define SPEND_PUB "dae41d6b13568fdd71ec3d20c2f614c65fe819f36ca5da8d24df3bd89b2bad9d"
#define VIEW_PUB  "865cbfab852a1d1ccdfc7328e4dac90f78fc2154257d07522e9b79e637326dfa"

#define ADDR_MAIN "49vDbkSo7eve3J41sBdjvjaBUyz8qHohsQcGtRf63qEUTMBvmA45fpp5pSacMdSg7A3b71RejLzB8EkGbfjp5PELVF2N4Zn"
#define ADDR_STAGE "5A8FgbMkmG2e3J41sBdjvjaBUyz8qHohsQcGtRf63qEUTMBvmA45fpp5pSacMdSg7A3b71RejLzB8EkGbfjp5PELVHCRUaE"
#define ADDR_TEST "A1Tm6174Q22e3J41sBdjvjaBUyz8qHohsQcGtRf63qEUTMBvmA45fpp5pSacMdSg7A3b71RejLzB8EkGbfjp5PELVKKfJLQ"
#define ADDR_INT  "4KctcZGHivSe3J41sBdjvjaBUyz8qHohsQcGtRf63qEUTMBvmA45fpp5pSacMdSg7A3b71RejLzB8EkGbfjp5PELipMfXPS2PSLU4C1ukC"
#define ADDR_SUB  "82rYviTJiZtJPQAdXY3MndTh9kyf32GkhLQfygHwLL11FcVTb4SqmojZv6RaDEDafxbjuvRcR4oGY7gmeqnWchzn4EFR3y4"

static uint32_t rng_state = 0xa5a5a5a5u;

static uint32_t rng_next(void)
{
    uint32_t x = rng_state;
    x ^= x << 13;
    x ^= x >> 17;
    x ^= x << 5;
    rng_state = x;
    return x;
}

static void fill_addr(mw_address_t* a, mw_network_t net, mw_address_type_t type)
{
    memset(a, 0, sizeof(*a));
    mw_test_hex(SPEND_PUB, a->spend.b, 32);
    mw_test_hex(VIEW_PUB, a->view.b, 32);
    a->network = net;
    a->type = type;
}

MW_TEST(test_base58_vectors)
{
    char out[64];
    uint8_t bin[32];
    size_t n;

    struct { const char* hex; const char* b58; } vec[] = {
        { "00",                       "11"          },
        { "ff",                       "5Q"          },
        { "0000",                     "111"         },
        { "ffff",                     "LUv"         },
        { "00000000",                 "111111"      },
        { "ffffffff",                 "7YXq9G"      },
        { "0000000000000000",         "11111111111" },
        { "ffffffffffffffff",         "jpXCZedGfVQ" },
        { "06156013762879",           "1ENXbDTxxx"  },
        { "ffffffffffffffffffffffff", "jpXCZedGfVQ7YXq9G" },
    };

    for (size_t i = 0; i < sizeof(vec) / sizeof(vec[0]); ++i) {
        size_t len = mw_test_hex(vec[i].hex, bin, sizeof(bin));
        n = mw_base58_encode(bin, len, out, sizeof(out));
        CHECK_EQ_INT(n, strlen(vec[i].b58));
        CHECK_EQ_STR(out, vec[i].b58);

        uint8_t back[32];
        size_t written = 0;
        CHECK_EQ_INT(mw_base58_decode(vec[i].b58, back, sizeof(back), &written),
                     MW_OK);
        CHECK_EQ_INT(written, len);
        CHECK_EQ_MEM(back, bin, len);
    }

    // Empty input.
    n = mw_base58_encode((const uint8_t*)"", 0, out, sizeof(out));
    CHECK_EQ_INT(n, 0);
    CHECK_EQ_STR(out, "");

    // Output buffer too small -> refuse rather than overflow.
    CHECK_EQ_INT(mw_base58_encode(bin, 8, out, 4), 0);

    // Malformed input.
    uint8_t back[32];
    size_t written = 0;
    CHECK_EQ_INT(mw_base58_decode("1", back, sizeof(back), &written),
                 MW_ERR_FORMAT);                          // impossible length
    CHECK_EQ_INT(mw_base58_decode("110", back, sizeof(back), &written),
                 MW_ERR_FORMAT);                          // '0' is not in the alphabet
    CHECK_EQ_INT(mw_base58_decode("zzzzzzzzzzz", back, sizeof(back), &written),
                 MW_ERR_FORMAT);                          // block value >= 2^64
}

MW_TEST(test_base58_roundtrip)
{
    int failures = 0;
    for (int iter = 0; iter < 2000; ++iter) {
        uint8_t data[96], back[96];
        char enc[160];
        size_t len = 1 + rng_next() % 96;
        for (size_t i = 0; i < len; ++i) {
            data[i] = (uint8_t)(rng_next() >> 24);
        }
        size_t n = mw_base58_encode(data, len, enc, sizeof(enc));
        if (n == 0 || strlen(enc) != n) {
            failures++;
            continue;
        }
        size_t written = 0;
        if (mw_base58_decode(enc, back, sizeof(back), &written) != MW_OK ||
            written != len || memcmp(data, back, len) != 0) {
            failures++;
        }

        // ... and the checksummed variant.
        if (len <= 80) {
            char encc[160];
            if (mw_base58_encode_check(data, len, encc, sizeof(encc)) == 0) {
                failures++;
                continue;
            }
            written = 0;
            if (mw_base58_decode_check(encc, back, sizeof(back), &written) != MW_OK ||
                written != len || memcmp(data, back, len) != 0) {
                failures++;
            }
        }
    }
    CHECK_EQ_INT(failures, 0);
}

MW_TEST(test_prefixes)
{
    CHECK_EQ_INT(mw_address_prefix(MW_NET_MAINNET, MW_ADDR_STANDARD), 18);
    CHECK_EQ_INT(mw_address_prefix(MW_NET_MAINNET, MW_ADDR_INTEGRATED), 19);
    CHECK_EQ_INT(mw_address_prefix(MW_NET_MAINNET, MW_ADDR_SUBADDRESS), 42);
    CHECK_EQ_INT(mw_address_prefix(MW_NET_TESTNET, MW_ADDR_STANDARD), 53);
    CHECK_EQ_INT(mw_address_prefix(MW_NET_TESTNET, MW_ADDR_INTEGRATED), 54);
    CHECK_EQ_INT(mw_address_prefix(MW_NET_TESTNET, MW_ADDR_SUBADDRESS), 63);
    CHECK_EQ_INT(mw_address_prefix(MW_NET_STAGENET, MW_ADDR_STANDARD), 24);
    CHECK_EQ_INT(mw_address_prefix(MW_NET_STAGENET, MW_ADDR_INTEGRATED), 25);
    CHECK_EQ_INT(mw_address_prefix(MW_NET_STAGENET, MW_ADDR_SUBADDRESS), 36);
}

MW_TEST(test_address_vectors)
{
    mw_address_t a;
    char out[MW_ADDRESS_STR_MAX];

    fill_addr(&a, MW_NET_MAINNET, MW_ADDR_STANDARD);
    CHECK_EQ_INT(mw_address_encode(&a, out, sizeof(out)), MW_OK);
    CHECK_EQ_STR(out, ADDR_MAIN);
    CHECK_EQ_INT(out[0], '4');                  // mainnet addresses start with 4
    CHECK_EQ_INT(strlen(out), 95);

    fill_addr(&a, MW_NET_STAGENET, MW_ADDR_STANDARD);
    CHECK_EQ_INT(mw_address_encode(&a, out, sizeof(out)), MW_OK);
    CHECK_EQ_STR(out, ADDR_STAGE);
    CHECK_EQ_INT(out[0], '5');                  // stagenet addresses start with 5

    fill_addr(&a, MW_NET_TESTNET, MW_ADDR_STANDARD);
    CHECK_EQ_INT(mw_address_encode(&a, out, sizeof(out)), MW_OK);
    CHECK_EQ_STR(out, ADDR_TEST);
    CHECK_EQ_INT(out[0], 'A');

    fill_addr(&a, MW_NET_MAINNET, MW_ADDR_INTEGRATED);
    mw_test_hex("0123456789abcdef", a.payment_id, 8);
    a.has_payment_id = true;
    CHECK_EQ_INT(mw_address_encode(&a, out, sizeof(out)), MW_OK);
    CHECK_EQ_STR(out, ADDR_INT);
    CHECK_EQ_INT(strlen(out), 106);

    // An integrated address without a payment id is a programming error.
    a.has_payment_id = false;
    CHECK_EQ_INT(mw_address_encode(&a, out, sizeof(out)), MW_ERR_INVALID_ARG);
}

MW_TEST(test_address_decode)
{
    mw_address_t a;

    CHECK_EQ_INT(mw_address_decode(ADDR_MAIN, &a), MW_OK);
    CHECK_EQ_INT(a.network, MW_NET_MAINNET);
    CHECK_EQ_INT(a.type, MW_ADDR_STANDARD);
    CHECK_EQ_INT(a.has_payment_id, false);
    uint8_t spend[32], view[32];
    mw_test_hex(SPEND_PUB, spend, 32);
    mw_test_hex(VIEW_PUB, view, 32);
    CHECK_EQ_MEM(a.spend.b, spend, 32);
    CHECK_EQ_MEM(a.view.b, view, 32);

    CHECK_EQ_INT(mw_address_decode(ADDR_STAGE, &a), MW_OK);
    CHECK_EQ_INT(a.network, MW_NET_STAGENET);
    CHECK_EQ_INT(a.type, MW_ADDR_STANDARD);

    CHECK_EQ_INT(mw_address_decode(ADDR_TEST, &a), MW_OK);
    CHECK_EQ_INT(a.network, MW_NET_TESTNET);

    CHECK_EQ_INT(mw_address_decode(ADDR_INT, &a), MW_OK);
    CHECK_EQ_INT(a.type, MW_ADDR_INTEGRATED);
    CHECK_EQ_INT(a.has_payment_id, true);
    uint8_t pid[8];
    mw_test_hex("0123456789abcdef", pid, 8);
    CHECK_EQ_MEM(a.payment_id, pid, 8);

    CHECK_EQ_INT(mw_address_decode(ADDR_SUB, &a), MW_OK);
    CHECK_EQ_INT(a.type, MW_ADDR_SUBADDRESS);
    CHECK_EQ_INT(a.network, MW_NET_MAINNET);

    // Re-encoding any decoded address reproduces the original string.
    static const char* all[] = { ADDR_MAIN, ADDR_STAGE, ADDR_TEST, ADDR_INT, ADDR_SUB };
    for (size_t i = 0; i < sizeof(all) / sizeof(all[0]); ++i) {
        char out[MW_ADDRESS_STR_MAX];
        CHECK_EQ_INT(mw_address_decode(all[i], &a), MW_OK);
        CHECK_EQ_INT(mw_address_encode(&a, out, sizeof(out)), MW_OK);
        CHECK_EQ_STR(out, all[i]);
    }
}

MW_TEST(test_address_rejections)
{
    mw_address_t a;

    // One flipped character breaks the keccak checksum.
    char bad[MW_ADDRESS_STR_MAX];
    strcpy(bad, ADDR_MAIN);
    bad[40] = (bad[40] == 'A') ? 'B' : 'A';
    CHECK_EQ_INT(mw_address_decode(bad, &a), MW_ERR_CHECKSUM);

    // Truncated / overlong / empty / illegal characters.
    strcpy(bad, ADDR_MAIN);
    bad[80] = '\0';
    CHECK(mw_address_decode(bad, &a) != MW_OK);
    CHECK_EQ_INT(mw_address_decode("", &a), MW_ERR_FORMAT);
    CHECK(mw_address_decode("4000000000", &a) != MW_OK);
    CHECK_EQ_INT(mw_address_decode(NULL, &a), MW_ERR_INVALID_ARG);
    CHECK_EQ_INT(mw_address_decode(ADDR_MAIN, NULL), MW_ERR_INVALID_ARG);

    // An unknown network prefix must not decode.
    uint8_t raw[1 + 64];
    raw[0] = 99;
    mw_test_hex(SPEND_PUB, raw + 1, 32);
    mw_test_hex(VIEW_PUB, raw + 33, 32);
    char enc[MW_ADDRESS_STR_MAX];
    CHECK(mw_base58_encode_check(raw, sizeof(raw), enc, sizeof(enc)) > 0);
    CHECK_EQ_INT(mw_address_decode(enc, &a), MW_ERR_FORMAT);

    // Right prefix, wrong payload length.
    uint8_t short_raw[1 + 32];
    short_raw[0] = 18;
    mw_test_hex(SPEND_PUB, short_raw + 1, 32);
    CHECK(mw_base58_encode_check(short_raw, sizeof(short_raw), enc, sizeof(enc)) > 0);
    CHECK_EQ_INT(mw_address_decode(enc, &a), MW_ERR_FORMAT);

    // Encoding into a buffer that cannot hold the result.
    char tiny[16];
    fill_addr(&a, MW_NET_MAINNET, MW_ADDR_STANDARD);
    CHECK_EQ_INT(mw_address_encode(&a, tiny, sizeof(tiny)), MW_ERR_RANGE);
}

MW_TEST(test_shorten)
{
    char out[64];

    mw_address_shorten(ADDR_MAIN, out, sizeof(out), 5, 5);
    CHECK_EQ_STR(out, "49vDb...2N4Zn");        // 5 + "..." + 5
    CHECK_EQ_INT(strlen(out), 13);

    mw_address_shorten("short", out, sizeof(out), 5, 5);
    CHECK_EQ_STR(out, "short");

    mw_address_shorten(ADDR_MAIN, out, 8, 5, 5);   // buffer too small
    CHECK_EQ_INT(strlen(out), 7);

    mw_address_shorten(NULL, out, sizeof(out), 5, 5);
    CHECK_EQ_STR(out, "");
}

MW_TEST(test_misc_types)
{
    CHECK_EQ_STR(mw_err_str(MW_OK), "ok");
    CHECK_EQ_STR(mw_err_str(MW_ERR_CHECKSUM), "checksum mismatch");
    CHECK_EQ_STR(mw_err_str((mw_err_t)-999), "unknown error");

    char buf[32];
    mw_format_amount(0, buf, sizeof(buf));
    CHECK_EQ_STR(buf, "0.000000000000");
    mw_format_amount(1, buf, sizeof(buf));
    CHECK_EQ_STR(buf, "0.000000000001");
    mw_format_amount(MW_ATOMIC_UNITS, buf, sizeof(buf));
    CHECK_EQ_STR(buf, "1.000000000000");
    mw_format_amount(12345678901234ULL, buf, sizeof(buf));
    CHECK_EQ_STR(buf, "12.345678901234");
    mw_format_amount(18446744073709551615ULL, buf, sizeof(buf));
    CHECK_EQ_STR(buf, "18446744.073709551615");
}

// ---------------------------------------------------------------------------
// TZ 8.3 hardening: an address is untrusted input (a scanned QR, a typed
// string), so the two points it carries must pass the subgroup check before
// anything can use them. Without this, a low-order spend or view key walks
// straight into key derivation.
// ---------------------------------------------------------------------------
MW_TEST(test_address_rejects_low_order_points)
{
    // Canonical small-order Ed25519 encodings. All of them decode to a valid
    // curve point, which is exactly why mw_point_is_valid() alone is not
    // enough; none of them is in the prime-order subgroup (or, for the first
    // one, it is the identity, i.e. a degenerate public key).
    static const char* const low_order[] = {
        "0100000000000000000000000000000000000000000000000000000000000000",
        "ecffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff7f",
        "0000000000000000000000000000000000000000000000000000000000000000",
        "0000000000000000000000000000000000000000000000000000000000000080",
        "26e8958fc2b227b045c3f489f2ef98f0d5dfac05d3c63339b13802886d53fc05",
        "c7176a703d4dd84fba3c0b760d10670f2a2053fa2c39ccc64ec7fd7792ac03fa",
    };
    const size_t n_low = sizeof(low_order) / sizeof(low_order[0]);

    char enc[MW_ADDRESS_STR_MAX];
    mw_address_t a;

    for (size_t i = 0; i < n_low; ++i) {
        mw_point_t p;
        CHECK_EQ_INT((int)mw_test_hex(low_order[i], p.b, 32), 32);
        // Remember the convention: 1 means "passed", so a bad point gives 0.
        CHECK_EQ_INT(mw_point_check_public(&p), 0);

        // Low-order SPEND key.
        uint8_t raw[1 + 64];
        raw[0] = 18;                                   // mainnet, standard
        memcpy(raw + 1, p.b, 32);
        mw_test_hex(VIEW_PUB, raw + 33, 32);
        CHECK(mw_base58_encode_check(raw, sizeof(raw), enc, sizeof(enc)) > 0);
        memset(&a, 0xcc, sizeof(a));
        CHECK_EQ_INT(mw_address_decode(enc, &a), MW_ERR_SUBGROUP);

        // Low-order VIEW key.
        mw_test_hex(SPEND_PUB, raw + 1, 32);
        memcpy(raw + 33, p.b, 32);
        CHECK(mw_base58_encode_check(raw, sizeof(raw), enc, sizeof(enc)) > 0);
        memset(&a, 0xcc, sizeof(a));
        CHECK_EQ_INT(mw_address_decode(enc, &a), MW_ERR_SUBGROUP);

        // Integrated addresses go through the same gate.
        uint8_t raw_int[1 + 64 + 8];
        raw_int[0] = 19;                               // mainnet, integrated
        memcpy(raw_int + 1, p.b, 32);
        mw_test_hex(VIEW_PUB, raw_int + 33, 32);
        memset(raw_int + 65, 0x11, 8);
        CHECK(mw_base58_encode_check(raw_int, sizeof(raw_int), enc,
                                     sizeof(enc)) > 0);
        CHECK_EQ_INT(mw_address_decode(enc, &a), MW_ERR_SUBGROUP);
    }

    // A point that is on the curve but is not a valid encoding at all must be
    // refused too, not just mis-decoded.
    {
        uint8_t raw[1 + 64];
        raw[0] = 18;
        memset(raw + 1, 0xff, 32);                     // not a curve point
        mw_test_hex(VIEW_PUB, raw + 33, 32);
        CHECK(mw_base58_encode_check(raw, sizeof(raw), enc, sizeof(enc)) > 0);
        CHECK_EQ_INT(mw_address_decode(enc, &a), MW_ERR_SUBGROUP);
    }

    // The genuine address still decodes, so the check is not simply refusing
    // everything.
    CHECK_EQ_INT(mw_address_decode(ADDR_MAIN, &a), MW_OK);
}

int main(void)
{
    RUN_TEST(test_base58_vectors);
    RUN_TEST(test_base58_roundtrip);
    RUN_TEST(test_prefixes);
    RUN_TEST(test_address_vectors);
    RUN_TEST(test_address_decode);
    RUN_TEST(test_address_rejections);
    RUN_TEST(test_address_rejects_low_order_points);
    RUN_TEST(test_shorten);
    RUN_TEST(test_misc_types);
    return mw_test_summary();
}
