// End-to-end tests that cross module boundaries. Everything here goes through
// the frozen public headers only - if this suite compiles and passes, the
// contracts the modules were written against actually fit together.
//
// Covered flows:
//   1. seed phrase -> keys -> address, for both seed formats
//   2. the passphrase policy of TZ 5.2
//   3. the file envelope of TZ 9: seal -> open round trip and tamper rejection
//   4. the key image sync of TZ 11: outputs -> key images, including the
//      "one bad record must not abort the batch" rule
//   5. the hostile-input rules of TZ 8.3 on every parser
#include <string.h>

// Portable memmem (mingw-w64 has none).
static const void* tst_memmem(const void* hay, size_t hlen, const void* needle, size_t nlen)
{
    const unsigned char* h = (const unsigned char*)hay;
    if (nlen == 0) return hay;
    for (size_t i = 0; i + nlen <= hlen; ++i) {
        if (memcmp(h + i, needle, nlen) == 0) return h + i;
    }
    return NULL;
}
#define memmem tst_memmem

#include "test_framework.h"

#include "crypto/ed25519.h"
#include "crypto/hash.h"
#include "crypto/memzero.h"
#include "crypto/random.h"
#include "data/wordlist.h"
#include "monero/address.h"
#include "monero/file_formats.h"
#include "monero/key_image.h"
#include "monero/keys.h"
#include "monero/mnemonic.h"
#include "monero/monero_types.h"

// ---------------------------------------------------------------------------
// 1. seed -> keys -> address, both formats
// ---------------------------------------------------------------------------
MW_TEST(test_legacy_seed_to_address) {
    uint8_t seed[32];
    for (int i = 0; i < 32; ++i) seed[i] = (uint8_t)(i * 7 + 1);

    const mw_wordlist_t* wl = mw_wordlist(MW_WL_MONERO_EN);
    CHECK(wl != NULL);

    uint16_t words[MW_LEGACY_SEED_WORDS];
    CHECK_EQ_INT(mw_legacy_seed_encode(seed, wl, words), MW_OK);

    // The phrase must round-trip back to the very same 32 bytes.
    uint8_t seed2[32];
    CHECK_EQ_INT(mw_legacy_seed_decode(words, wl, seed2), MW_OK);
    CHECK_EQ_MEM(seed, seed2, 32);

    mw_account_keys_t keys;
    CHECK_EQ_INT(mw_seed_to_keys(MW_SEED_MONERO_LEGACY, seed, 32, "", &keys), MW_OK);

    // TZ 8.3: the device must be able to prove its own keys are consistent.
    CHECK_EQ_INT(mw_check_key_pair(&keys.sec.spend, &keys.pub.spend), MW_OK);
    CHECK_EQ_INT(mw_check_key_pair(&keys.sec.view, &keys.pub.view), MW_OK);

    mw_address_t addr;
    CHECK_EQ_INT(mw_address_from_keys(&keys, MW_NET_MAINNET, &addr), MW_OK);

    char str[MW_ADDRESS_STR_MAX];
    CHECK_EQ_INT(mw_address_encode(&addr, str, sizeof str), MW_OK);
    CHECK_EQ_INT(str[0], '4');           // every mainnet standard address
    CHECK_EQ_INT((int)strlen(str), 95);

    mw_address_t back;
    CHECK_EQ_INT(mw_address_decode(str, &back), MW_OK);
    CHECK_EQ_MEM(back.spend.b, addr.spend.b, 32);
    CHECK_EQ_MEM(back.view.b, addr.view.b, 32);
    CHECK_EQ_INT(back.network, MW_NET_MAINNET);
    CHECK_EQ_INT(back.type, MW_ADDR_STANDARD);
}

MW_TEST(test_polyseed_to_address) {
    uint8_t entropy[32];
    for (int i = 0; i < 32; ++i) entropy[i] = (uint8_t)(0xA0 ^ i);

    mw_polyseed_t seed;
    CHECK_EQ_INT(mw_polyseed_create(entropy, sizeof entropy,
                                    1700000000ULL, 0, &seed), MW_OK);

    const mw_wordlist_t* wl = mw_wordlist(MW_WL_POLYSEED_EN);
    uint16_t words[MW_POLYSEED_WORDS];
    CHECK_EQ_INT(mw_polyseed_encode(&seed, wl, words), MW_OK);

    mw_polyseed_t back;
    CHECK_EQ_INT(mw_polyseed_decode(words, wl, &back), MW_OK);
    CHECK_EQ_INT(back.birthday, seed.birthday);
    CHECK_EQ_INT(back.features, seed.features);
    CHECK_EQ_MEM(back.secret, seed.secret, MW_POLYSEED_SECRET_SIZE);

    // TZ 6.3: the restore height comes out of the seed itself.
    uint32_t h = mw_polyseed_restore_height(&back, MW_NET_MAINNET);
    CHECK(h > 2000000u);

    uint8_t key[32];
    mw_polyseed_keygen(&back, MW_POLYSEED_COIN_MONERO, key);

    mw_account_keys_t keys;
    mw_keys_from_polyseed_key(key, &keys);
    CHECK_EQ_INT(mw_keys_derive_public(&keys), MW_OK);
    CHECK_EQ_INT(mw_check_key_pair(&keys.sec.spend, &keys.pub.spend), MW_OK);

    mw_address_t addr;
    CHECK_EQ_INT(mw_address_from_keys(&keys, MW_NET_MAINNET, &addr), MW_OK);
    char str[MW_ADDRESS_STR_MAX];
    CHECK_EQ_INT(mw_address_encode(&addr, str, sizeof str), MW_OK);
    CHECK_EQ_INT(str[0], '4');
}

// ---------------------------------------------------------------------------
// 2. passphrase policy (TZ 5.2)
// ---------------------------------------------------------------------------
MW_TEST(test_passphrase_policy) {
    uint8_t seed[32];
    for (int i = 0; i < 32; ++i) seed[i] = (uint8_t)(i + 0x10);

    mw_account_keys_t plain, empty, withpass, withpass2;
    CHECK_EQ_INT(mw_seed_to_keys(MW_SEED_MONERO_LEGACY, seed, 32, "", &empty), MW_OK);

    // An empty passphrase must reproduce the plain Monero wallet EXACTLY -
    // that is what makes the written-down seed restorable in monero-wallet-cli.
    mw_keys_from_legacy_seed(seed, &plain);
    CHECK_EQ_INT(mw_keys_derive_public(&plain), MW_OK);
    CHECK_EQ_MEM(plain.sec.spend.b, empty.sec.spend.b, 32);
    CHECK_EQ_MEM(plain.pub.spend.b, empty.pub.spend.b, 32);

    // A non-empty passphrase must change the wallet, deterministically.
    CHECK_EQ_INT(mw_seed_to_keys(MW_SEED_MONERO_LEGACY, seed, 32, "correct horse", &withpass), MW_OK);
    CHECK(memcmp(withpass.sec.spend.b, plain.sec.spend.b, 32) != 0);

    CHECK_EQ_INT(mw_seed_to_keys(MW_SEED_MONERO_LEGACY, seed, 32, "correct horse", &withpass2), MW_OK);
    CHECK_EQ_MEM(withpass.sec.spend.b, withpass2.sec.spend.b, 32);

    // Passphrases must be case sensitive and whitespace sensitive.
    mw_account_keys_t other;
    CHECK_EQ_INT(mw_seed_to_keys(MW_SEED_MONERO_LEGACY, seed, 32, "Correct horse", &other), MW_OK);
    CHECK(memcmp(withpass.sec.spend.b, other.sec.spend.b, 32) != 0);
    CHECK_EQ_INT(mw_seed_to_keys(MW_SEED_MONERO_LEGACY, seed, 32, "correct  horse", &other), MW_OK);
    CHECK(memcmp(withpass.sec.spend.b, other.sec.spend.b, 32) != 0);
}

// ---------------------------------------------------------------------------
// 3. the TZ 9 file envelope
// ---------------------------------------------------------------------------
static void make_keys(mw_account_keys_t* keys) {
    uint8_t seed[32];
    for (int i = 0; i < 32; ++i) seed[i] = (uint8_t)(i * 3 + 5);
    mw_keys_from_legacy_seed(seed, keys);
    mw_keys_derive_public(keys);
}

MW_TEST(test_file_envelope_roundtrip) {
    mw_account_keys_t keys;
    make_keys(&keys);

    uint8_t payload[512];
    for (size_t i = 0; i < sizeof payload; ++i) payload[i] = (uint8_t)(i ^ 0x5A);

    uint8_t file[1024];
    size_t file_len = 0;
    mw_err_t err = mw_file_seal(&MW_FILE_KEYIMAGES, payload, sizeof payload,
                                &keys, file, sizeof file, &file_len);
    CHECK_EQ_INT(err, MW_OK);
    CHECK(file_len > sizeof payload);

    // The magic must be on the wire verbatim, at the documented length.
    CHECK_EQ_MEM(file, MW_MAGIC_KEYIMAGES, MW_MAGIC_KEYIMAGES_LEN);
    CHECK_EQ_INT(MW_MAGIC_KEYIMAGES_LEN, 24);   // TZ 9.2 misprints this as 26

    // The body must not be stored in the clear.
    CHECK(memmem(file, file_len, payload, sizeof payload) == NULL);

    uint8_t out[512];
    size_t out_len = 0;
    CHECK_EQ_INT(mw_file_open(&MW_FILE_KEYIMAGES, file, file_len, &keys,
                              out, sizeof out, &out_len), MW_OK);
    CHECK_EQ_INT((int)out_len, (int)sizeof payload);
    CHECK_EQ_MEM(out, payload, sizeof payload);
}

MW_TEST(test_file_envelope_rejects_tampering) {
    mw_account_keys_t keys, other;
    make_keys(&keys);
    uint8_t seed[32];
    memset(seed, 0x42, sizeof seed);
    mw_keys_from_legacy_seed(seed, &other);
    mw_keys_derive_public(&other);

    uint8_t payload[128];
    memset(payload, 0x11, sizeof payload);

    uint8_t file[512], out[512];
    size_t file_len = 0, out_len = 0;
    CHECK_EQ_INT(mw_file_seal(&MW_FILE_KEYIMAGES, payload, sizeof payload,
                              &keys, file, sizeof file, &file_len), MW_OK);

    // Wrong wallet must not be able to open it.
    CHECK(mw_file_open(&MW_FILE_KEYIMAGES, file, file_len, &other,
                       out, sizeof out, &out_len) != MW_OK);

    // A flipped bit anywhere in the ciphertext must fail the signature check.
    for (size_t pos = MW_MAGIC_KEYIMAGES_LEN; pos < file_len; pos += 17) {
        uint8_t copy[512];
        memcpy(copy, file, file_len);
        copy[pos] ^= 0x01;
        mw_err_t e = mw_file_open(&MW_FILE_KEYIMAGES, copy, file_len, &keys,
                                  out, sizeof out, &out_len);
        CHECK(e != MW_OK);
    }

    // Corrupt magic, truncation and an empty file must all be rejected
    // without reading out of bounds (run this suite under ASan).
    uint8_t bad[512];
    memcpy(bad, file, file_len);
    bad[0] ^= 0xFF;
    CHECK_EQ_INT(mw_file_open(&MW_FILE_KEYIMAGES, bad, file_len, &keys,
                              out, sizeof out, &out_len), MW_ERR_MAGIC);
    for (size_t trunc = 0; trunc < file_len; trunc += 7) {
        mw_err_t e = mw_file_open(&MW_FILE_KEYIMAGES, file, trunc, &keys,
                                  out, sizeof out, &out_len);
        CHECK(e != MW_OK);
    }
}

// ---------------------------------------------------------------------------
// 4. key image sync (TZ 11)
// ---------------------------------------------------------------------------
static void make_output(const mw_account_keys_t* keys, uint32_t idx,
                        mw_exported_output_t* out) {
    memset(out, 0, sizeof *out);

    // Pretend to be the sender: pick r, publish R = r*G, and derive the
    // one-time key the way a real transaction would.
    mw_scalar_t r;
    uint8_t material[36];
    memcpy(material, keys->sec.spend.b, 32);
    material[32] = (uint8_t)idx;
    material[33] = 0xA5;
    material[34] = 0x5A;
    material[35] = 0x3C;
    mw_hash_to_scalar(material, sizeof material, &r);

    mw_point_scalarmult_base(&out->tx_pub_key, &r);

    mw_point_t derivation;
    CHECK_EQ_INT(mw_generate_key_derivation(&keys->pub.view, &r, &derivation), MW_OK);
    CHECK_EQ_INT(mw_derive_public_key(&derivation, idx, &keys->pub.spend,
                                      &out->one_time_pubkey), MW_OK);

    out->internal_output_index = idx;
    out->global_output_index = 1000 + idx;
    out->amount = 1000000000ULL * (idx + 1);
    out->rct = true;
}

MW_TEST(test_key_image_sync) {
    mw_account_keys_t keys;
    make_keys(&keys);

    enum { N = 8 };
    mw_exported_output_t outs[N];
    for (uint32_t i = 0; i < N; ++i) make_output(&keys, i, &outs[i]);

    mw_exported_key_image_t kis[N];
    for (uint32_t i = 0; i < N; ++i) {
        CHECK_EQ_INT(mw_key_image_from_output(&keys, &outs[i], &kis[i]), MW_OK);

        // TZ 8.3: every key image we emit must be a valid main-subgroup point.
        // Note the boolean convention: 1 means the point passed.
        CHECK_EQ_INT(mw_point_check_public(&kis[i].image), 1);

        // The export signature must verify against the same public key.
        CHECK_EQ_INT(mw_check_key_image_signature(&outs[i].one_time_pubkey,
                                                  &kis[i].image, &kis[i].sig), MW_OK);
    }

    // Key images must be distinct - a collision would mean a derivation bug
    // that silently marks unrelated outputs as spent.
    for (int i = 0; i < N; ++i)
        for (int j = i + 1; j < N; ++j)
            CHECK(memcmp(kis[i].image.b, kis[j].image.b, 32) != 0);

    // Determinism: the same output must always give the same key image.
    mw_exported_key_image_t again;
    CHECK_EQ_INT(mw_key_image_from_output(&keys, &outs[3], &again), MW_OK);
    CHECK_EQ_MEM(again.image.b, kis[3].image.b, 32);
}

MW_TEST(test_key_image_batch_survives_bad_record) {
    mw_account_keys_t keys;
    make_keys(&keys);

    enum { N = 6 };
    mw_exported_output_t outs[N];
    for (uint32_t i = 0; i < N; ++i) make_output(&keys, i, &outs[i]);

    // TZ 11.3: one corrupt record in the middle must not abort the batch.
    // A one-time key that is not on the curve is the realistic corruption.
    memset(outs[2].one_time_pubkey.b, 0xFF, 32);

    mw_exported_key_image_t kis[N];
    mw_ki_failure_t failures[N];
    mw_ki_batch_result_t res = {0, 0, failures, N};

    mw_err_t err = mw_key_image_batch(&keys, outs, N, kis, &res, NULL, NULL);
    CHECK_EQ_INT(err, MW_OK);
    CHECK_EQ_INT(res.processed, N - 1);
    CHECK_EQ_INT(res.failed, 1);
    CHECK_EQ_INT(failures[0].index, 2);
    CHECK(failures[0].err != MW_OK);
}

// ---------------------------------------------------------------------------
// 5. hostile input (TZ 8.3)
// ---------------------------------------------------------------------------
MW_TEST(test_parsers_reject_garbage) {
    mw_account_keys_t keys;
    make_keys(&keys);

    uint8_t out[4096];
    size_t out_len = 0;

    // Empty, tiny and all-zero inputs must be rejected, never crash.
    CHECK(mw_file_open(&MW_FILE_OUTPUTS, NULL, 0, &keys, out, sizeof out, &out_len) != MW_OK);

    uint8_t junk[256];
    memset(junk, 0, sizeof junk);
    CHECK(mw_file_open(&MW_FILE_OUTPUTS, junk, sizeof junk, &keys, out, sizeof out, &out_len) != MW_OK);

    memset(junk, 0xFF, sizeof junk);
    CHECK(mw_file_open(&MW_FILE_OUTPUTS, junk, sizeof junk, &keys, out, sizeof out, &out_len) != MW_OK);

    // A file claiming to be an unsigned tx set but truncated mid-header.
    uint8_t hdr[64];
    memcpy(hdr, MW_MAGIC_UNSIGNED_TX, MW_MAGIC_UNSIGNED_TX_LEN);
    memset(hdr + MW_MAGIC_UNSIGNED_TX_LEN, 0, sizeof hdr - MW_MAGIC_UNSIGNED_TX_LEN);
    for (size_t n = 0; n <= sizeof hdr; ++n) {
        mw_transaction_t tx;
        uint32_t count = 0;
        CHECK(mw_file_open(&MW_FILE_UNSIGNED_TX, hdr, n, &keys, out, sizeof out, &out_len) != MW_OK);
        (void)tx; (void)count;
    }

    // Points that are on the curve but in a small subgroup must be refused
    // wherever they arrive from outside (TZ 8.3).
    // Points of order 2, 4 and 8. None of these lie in the prime-order
    // subgroup, so both checks must refuse them.
    static const char* const low_order[] = {
        "0000000000000000000000000000000000000000000000000000000000000000",
        "c7176a703d4dd84fba3c0b760d10670f2a2053fa2c39ccc64ec7fd7792ac03fa",
        "26e8958fc2b227b045c3f489f2ef98f0d5dfac05d3c63339b13802886d53fc05",
        "ecffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff7f",
    };
    for (size_t i = 0; i < sizeof low_order / sizeof *low_order; ++i) {
        mw_point_t p;
        CHECK_EQ_INT((int)mw_test_hex(low_order[i], p.b, 32), 32);
        CHECK_EQ_INT(mw_point_in_main_subgroup(&p), 0);
        CHECK_EQ_INT(mw_point_check_public(&p), 0);
    }

    // The identity is a special case: it genuinely IS in the prime-order
    // subgroup, so only the stricter check may reject it. A public key of
    // identity would mean a zero secret key.
    mw_point_t id;
    CHECK_EQ_INT((int)mw_test_hex("0100000000000000000000000000000000000000000000000000000000000000",
                                  id.b, 32), 32);
    CHECK_EQ_INT(mw_point_in_main_subgroup(&id), 1);
    CHECK_EQ_INT(mw_point_check_public(&id), 0);

    // The base point and Monero's H, by contrast, must pass.
    CHECK_EQ_INT(mw_point_check_public(&MW_POINT_G), 1);
    CHECK_EQ_INT(mw_point_check_public(&MW_POINT_H), 1);
}

int main(void) {
    mw_random_init();

    RUN_TEST(test_legacy_seed_to_address);
    RUN_TEST(test_polyseed_to_address);
    RUN_TEST(test_passphrase_policy);
    RUN_TEST(test_file_envelope_roundtrip);
    RUN_TEST(test_file_envelope_rejects_tampering);
    RUN_TEST(test_key_image_sync);
    RUN_TEST(test_key_image_batch_survives_bad_record);
    RUN_TEST(test_parsers_reject_garbage);

    return mw_test_summary();
}
