// Key derivation, subaddresses and the RCT ECDH helpers (TZ 6.2, 7.x, 8.3).
//
// Every vector below was produced with an independent Python implementation of
// keccak-256 / ed25519 / Monero's address format, validated against the
// published monero-python vector
//   73192a94...2d80 -> 49j9ikUyGfkSkPV8TY66p2RsSs6xL7NR5LauJTt7y6LZ...
#include "test_framework.h"
#include "crypto/chacha.h"

#include "monero/keys.h"
#include "monero/address.h"
#include "monero/mnemonic.h"
#include "data/wordlist.h"
#include "crypto/ed25519.h"

#define LEGACY_SEED  "3b094ca7218f175e91fa2402b4ae239a2fe8262792a3e718533a1a357a1e4109"
#define LEGACY_VIEW  "0f3fe25d0c6d4c94dde0c0bcc214b233e9c72927f813728b0f01f28f9d5e1201"
#define LEGACY_SPUB  "dae41d6b13568fdd71ec3d20c2f614c65fe819f36ca5da8d24df3bd89b2bad9d"
#define LEGACY_VPUB  "865cbfab852a1d1ccdfc7328e4dac90f78fc2154257d07522e9b79e637326dfa"

static void hex32(const char* hex, uint8_t out[32])
{
    size_t n = mw_test_hex(hex, out, 32);
    if (n != 32) {
        printf("    BAD TEST VECTOR: %s\n", hex);
    }
}

MW_TEST(test_legacy_account_keys)
{
    uint8_t seed[32];
    hex32(LEGACY_SEED, seed);

    mw_account_keys_t keys;
    mw_keys_from_legacy_seed(seed, &keys);
    CHECK_EQ_INT(mw_keys_derive_public(&keys), MW_OK);

    uint8_t expect[32];
    hex32(LEGACY_SEED, expect);
    CHECK_EQ_MEM(keys.sec.spend.b, expect, 32);   // already reduced
    hex32(LEGACY_VIEW, expect);
    CHECK_EQ_MEM(keys.sec.view.b, expect, 32);
    hex32(LEGACY_SPUB, expect);
    CHECK_EQ_MEM(keys.pub.spend.b, expect, 32);
    hex32(LEGACY_VPUB, expect);
    CHECK_EQ_MEM(keys.pub.view.b, expect, 32);

    // Scalars must be canonical and the pairs must verify.
    CHECK(mw_sc_check(&keys.sec.spend));
    CHECK(mw_sc_check(&keys.sec.view));
    CHECK_EQ_INT(mw_check_key_pair(&keys.sec.spend, &keys.pub.spend), MW_OK);
    CHECK_EQ_INT(mw_check_key_pair(&keys.sec.view, &keys.pub.view), MW_OK);
    CHECK_EQ_INT(mw_check_key_pair(&keys.sec.view, &keys.pub.spend),
                 MW_ERR_KEY_MISMATCH);

    mw_address_t addr;
    char str[MW_ADDRESS_STR_MAX];
    CHECK_EQ_INT(mw_address_from_keys(&keys, MW_NET_MAINNET, &addr), MW_OK);
    CHECK_EQ_INT(mw_address_encode(&addr, str, sizeof(str)), MW_OK);
    CHECK_EQ_STR(str, "49vDbkSo7eve3J41sBdjvjaBUyz8qHohsQcGtRf63qEUTMBvmA45"
                      "fpp5pSacMdSg7A3b71RejLzB8EkGbfjp5PELVF2N4Zn");
}

MW_TEST(test_passphrase_folding)
{
    uint8_t seed[32];
    hex32(LEGACY_SEED, seed);

    // An empty passphrase must reproduce the plain Monero wallet exactly.
    mw_account_keys_t plain, empty, nul;
    mw_keys_from_legacy_seed(seed, &plain);
    CHECK_EQ_INT(mw_keys_derive_public(&plain), MW_OK);

    CHECK_EQ_INT(mw_seed_to_keys(MW_SEED_MONERO_LEGACY, seed, 32, "", &empty),
                 MW_OK);
    CHECK_EQ_INT(mw_seed_to_keys(MW_SEED_MONERO_LEGACY, seed, 32, NULL, &nul),
                 MW_OK);
    CHECK_EQ_MEM(empty.sec.spend.b, plain.sec.spend.b, 32);
    CHECK_EQ_MEM(empty.sec.view.b, plain.sec.view.b, 32);
    CHECK_EQ_MEM(empty.pub.spend.b, plain.pub.spend.b, 32);
    CHECK_EQ_MEM(nul.sec.spend.b, plain.sec.spend.b, 32);

    // A non-empty passphrase applies Monero's seed offset exactly as
    // cryptonote::decrypt_key() does for Monero CLI / GUI / Feather:
    //     key = sc_sub(seed, cn_slow_hash(passphrase))  (ref10, unreduced)
    //     spend = sc_reduce32(key), view = sc_reduce32(keccak(spend))
    mw_account_keys_t pass;
    CHECK_EQ_INT(mw_seed_to_keys(MW_SEED_MONERO_LEGACY, seed, 32, "trezor", &pass),
                 MW_OK);
    {
        uint8_t h[32], k[32];
        mw_account_keys_t manual;
        CHECK_EQ_INT(mw_cn_slow_hash("trezor", 6, h), 0);
        mw_sc_sub_ref10(k, seed, h);
        mw_keys_from_legacy_seed(k, &manual);
        CHECK_EQ_INT(mw_keys_derive_public(&manual), MW_OK);
        CHECK_EQ_MEM(pass.sec.spend.b, manual.sec.spend.b, 32);
        CHECK_EQ_MEM(pass.sec.view.b, manual.sec.view.b, 32);
        CHECK_EQ_MEM(pass.pub.spend.b, manual.pub.spend.b, 32);
        // encrypt_key() is the inverse: sc_add(key, hash) gives the seed back.
        uint8_t back[32];
        mw_scalar_t a, b, s;
        memcpy(a.b, k, 32);
        memcpy(b.b, h, 32);
        mw_sc_reduce32(&a);
        mw_sc_reduce32(&b);
        mw_sc_add(&s, &a, &b);
        memcpy(back, seed, 32);
        mw_scalar_t seed_red;
        memcpy(seed_red.b, back, 32);
        mw_sc_reduce32(&seed_red);
        CHECK_EQ_MEM(s.b, seed_red.b, 32);
    }
    CHECK(memcmp(pass.sec.spend.b, plain.sec.spend.b, 32) != 0);
    CHECK(mw_sc_check(&pass.sec.spend));

    // Deterministic: the same passphrase always gives the same wallet.
    mw_account_keys_t again;
    CHECK_EQ_INT(mw_seed_to_keys(MW_SEED_MONERO_LEGACY, seed, 32, "trezor", &again),
                 MW_OK);
    CHECK_EQ_MEM(again.sec.spend.b, pass.sec.spend.b, 32);

    // Different passphrases must not collide (case matters).
    mw_account_keys_t other;
    CHECK_EQ_INT(mw_seed_to_keys(MW_SEED_MONERO_LEGACY, seed, 32, "trezoR", &other),
                 MW_OK);
    CHECK(memcmp(other.sec.spend.b, pass.sec.spend.b, 32) != 0);

    // Bad arguments.
    CHECK_EQ_INT(mw_seed_to_keys(MW_SEED_MONERO_LEGACY, seed, 31, "", &plain),
                 MW_ERR_INVALID_ARG);
    CHECK_EQ_INT(mw_seed_to_keys(MW_SEED_MONERO_LEGACY, NULL, 32, "", &plain),
                 MW_ERR_INVALID_ARG);
    CHECK_EQ_INT(mw_seed_to_keys((mw_seed_type_t)9, seed, 32, "", &plain),
                 MW_ERR_NOT_SUPPORTED);
}

MW_TEST(test_polyseed_account_keys)
{
    const mw_wordlist_t* wl = mw_wordlist(MW_WL_POLYSEED_EN);
    static const char* words[MW_POLYSEED_WORDS] = {
        "raven", "tail", "swear", "infant", "grief", "assist", "regular",
        "lamp", "duck", "valid", "someone", "little", "harsh", "puppy",
        "airport", "language"
    };
    uint16_t idx[MW_POLYSEED_WORDS];
    for (int i = 0; i < MW_POLYSEED_WORDS; ++i) {
        int found = mw_wordlist_find(wl, words[i]);
        CHECK(found >= 0);
        idx[i] = (uint16_t)found;
    }

    mw_polyseed_t seed;
    CHECK_EQ_INT(mw_polyseed_decode(idx, wl, &seed), MW_OK);

    uint8_t key[32], expect[32];
    mw_polyseed_keygen(&seed, MW_POLYSEED_COIN_MONERO, key);
    hex32("21268a76048a3b25a4a9ac179d86b12fab5800b8d858da9facf4b0a778dc2840", expect);
    CHECK_EQ_MEM(key, expect, 32);

    mw_account_keys_t keys;
    mw_keys_from_polyseed_key(key, &keys);
    CHECK_EQ_INT(mw_keys_derive_public(&keys), MW_OK);
    hex32("6dd6b2029bfdf1c44a36ce8b229f35dcaa5800b8d858da9facf4b0a778dc2800", expect);
    CHECK_EQ_MEM(keys.sec.spend.b, expect, 32);
    hex32("3c56a3cc3e7f94dc428ffe3b856adb6054552dfa14360d4cdec3f7730b999107", expect);
    CHECK_EQ_MEM(keys.sec.view.b, expect, 32);

    mw_address_t addr;
    char str[MW_ADDRESS_STR_MAX];
    CHECK_EQ_INT(mw_address_from_keys(&keys, MW_NET_MAINNET, &addr), MW_OK);
    CHECK_EQ_INT(mw_address_encode(&addr, str, sizeof(str)), MW_OK);
    CHECK_EQ_STR(str, "47AjPj7DVPQVGGXJXbbTMZWcKQDejGHYZChVkeujy8qPLjKkgdsx"
                      "ge4DzvkRMgU4sDUigGLuBN9stKBMowhuXH2HJHWAuRf");

    // The same seed through mw_seed_to_keys with an empty passphrase, in the
    // form the firmware actually stores and passes around: the packed context.
    // Feeding the raw struct here is what let the birthday-dropping storage bug
    // (D1) hide, so the test now uses the same bytes the wallet store seals.
    uint8_t blob[MW_POLYSEED_BLOB_MAX];
    size_t blob_len = 0;
    CHECK_EQ_INT(mw_polyseed_pack(&seed, blob, sizeof(blob), &blob_len), MW_OK);
    CHECK_EQ_INT((int)blob_len, MW_POLYSEED_BLOB_MIN);
    CHECK_EQ_INT((int)blob[0], 1);            // birthday 1, little endian
    CHECK_EQ_INT((int)blob[1], 0);
    CHECK_EQ_INT((int)blob[2], 0);            // features
    CHECK_EQ_MEM(blob + 3, seed.secret, MW_POLYSEED_SECRET_SIZE);

    mw_account_keys_t via_api;
    CHECK_EQ_INT(mw_seed_to_keys(MW_SEED_POLYSEED, blob, blob_len, "", &via_api),
                 MW_OK);
    CHECK_EQ_MEM(via_api.sec.spend.b, keys.sec.spend.b, 32);
    CHECK_EQ_MEM(via_api.pub.spend.b, keys.pub.spend.b, 32);

    // A context that lost the birthday must NOT produce the same wallet - that
    // is precisely the funds-loss case, and it has to stay visible here.
    {
        uint8_t zero_bd[MW_POLYSEED_BLOB_MAX];
        mw_account_keys_t wrong;
        memcpy(zero_bd, blob, blob_len);
        zero_bd[0] = 0;
        zero_bd[1] = 0;
        CHECK_EQ_INT(mw_seed_to_keys(MW_SEED_POLYSEED, zero_bd, blob_len, "",
                                     &wrong), MW_OK);
        CHECK(memcmp(wrong.sec.spend.b, keys.sec.spend.b, 32) != 0);
    }

    // With a passphrase: Feather's path - polyseed_keygen() output handed
    // to recoverDeterministicWalletFromSpendKey() with the seed offset, i.e.
    // decrypt_key() on the keygen output (NOT polyseed's own encryption).
    mw_account_keys_t with_pass;
    CHECK_EQ_INT(mw_seed_to_keys(MW_SEED_POLYSEED, blob, blob_len, "password",
                                 &with_pass), MW_OK);
    CHECK(memcmp(with_pass.sec.spend.b, keys.sec.spend.b, 32) != 0);
    {
        uint8_t key[32], h[32], k[32];
        mw_account_keys_t manual_keys;
        mw_polyseed_keygen(&seed, MW_POLYSEED_COIN_MONERO, key);
        CHECK_EQ_INT(mw_cn_slow_hash("password", 8, h), 0);
        mw_sc_sub_ref10(k, key, h);
        mw_keys_from_legacy_seed(k, &manual_keys);
        CHECK_EQ_INT(mw_keys_derive_public(&manual_keys), MW_OK);
        CHECK_EQ_MEM(with_pass.sec.spend.b, manual_keys.sec.spend.b, 32);
    }

    CHECK_EQ_INT(mw_seed_to_keys(MW_SEED_POLYSEED, blob, 7, "", &via_api),
                 MW_ERR_INVALID_ARG);
    // The bare 19-byte secret is no longer a valid seed material length: it
    // used to be silently taken with birthday = features = 0.
    CHECK_EQ_INT(mw_seed_to_keys(MW_SEED_POLYSEED, seed.secret,
                                 MW_POLYSEED_SECRET_SIZE, "", &via_api),
                 MW_ERR_INVALID_ARG);
    // Out-of-range birthday / features in a context are a format error.
    {
        uint8_t bad[MW_POLYSEED_BLOB_MAX];
        memcpy(bad, blob, blob_len);
        bad[1] = 0xff;                         // birthday > 10 bits
        CHECK_EQ_INT(mw_seed_to_keys(MW_SEED_POLYSEED, bad, blob_len, "",
                                     &via_api), MW_ERR_FORMAT);
        memcpy(bad, blob, blob_len);
        bad[2] = 0x20;                         // features > 5 bits
        CHECK_EQ_INT(mw_seed_to_keys(MW_SEED_POLYSEED, bad, blob_len, "",
                                     &via_api), MW_ERR_FORMAT);
    }
}

MW_TEST(test_subaddress)
{
    uint8_t seed[32];
    hex32(LEGACY_SEED, seed);
    mw_account_keys_t keys;
    mw_keys_from_legacy_seed(seed, &keys);
    CHECK_EQ_INT(mw_keys_derive_public(&keys), MW_OK);

    // m = Hs("SubAddr\0" || a || major || minor)
    mw_scalar_t m;
    uint8_t expect[32];
    mw_get_subaddress_secret_key(&keys.sec.view, 1, 1, &m);
    hex32("38f77e9929e4d093ec2abe16f57685ce738b2a6995ede8e82ba29572cf304e0a", expect);
    CHECK_EQ_MEM(m.b, expect, 32);

    mw_address_t sub;
    CHECK_EQ_INT(mw_get_subaddress(&keys, 1, 1, &sub), MW_OK);
    CHECK_EQ_INT(sub.type, MW_ADDR_SUBADDRESS);
    CHECK_EQ_INT(sub.major, 1);
    CHECK_EQ_INT(sub.minor, 1);
    hex32("0a99b24ac740df67f1fdcf786879a69f95247ae1deda8a74089f1550f68dc457", expect);
    CHECK_EQ_MEM(sub.spend.b, expect, 32);
    hex32("5be0351fdb6336c4c9d15e70de92e7cfb2343b853b3f5527f89ae2c28e409f1c", expect);
    CHECK_EQ_MEM(sub.view.b, expect, 32);

    char str[MW_ADDRESS_STR_MAX];
    CHECK_EQ_INT(mw_address_encode(&sub, str, sizeof(str)), MW_OK);
    CHECK_EQ_STR(str, "82rYviTJiZtJPQAdXY3MndTh9kyf32GkhLQfygHwLL11FcVTb4Sq"
                      "mojZv6RaDEDafxbjuvRcR4oGY7gmeqnWchzn4EFR3y4");
    CHECK_EQ_INT(str[0], '8');

    // (0,0) is the primary address, not a subaddress.
    mw_address_t primary;
    CHECK_EQ_INT(mw_get_subaddress(&keys, 0, 0, &primary), MW_OK);
    CHECK_EQ_INT(primary.type, MW_ADDR_STANDARD);
    CHECK_EQ_MEM(primary.spend.b, keys.pub.spend.b, 32);
    CHECK_EQ_MEM(primary.view.b, keys.pub.view.b, 32);

    // Different indices give different addresses.
    mw_address_t a01, a10;
    CHECK_EQ_INT(mw_get_subaddress(&keys, 0, 1, &a01), MW_OK);
    CHECK_EQ_INT(mw_get_subaddress(&keys, 1, 0, &a10), MW_OK);
    CHECK(memcmp(a01.spend.b, a10.spend.b, 32) != 0);
    CHECK(memcmp(a01.spend.b, sub.spend.b, 32) != 0);

    CHECK_EQ_INT(mw_get_subaddress(NULL, 1, 1, &sub), MW_ERR_INVALID_ARG);
}

MW_TEST(test_key_derivation)
{
    uint8_t a_sec[32], b_sec[32], r_sec[32];
    hex32("be990915c96825b31c37f400a4c2aee44615f0bd9eda258f3e53bfe486cbd309", a_sec);
    hex32("6ffaa3ede03812e8a37027dc655fd5986c6ab11fee1863f0faef07e29baeb00f", b_sec);
    hex32("cd6c1ec29e2bd61b6a2f193c8e19c1a6cfc30233587c5089a848b1615eb7fb0f", r_sec);

    mw_seckey_t a, b, r;
    memcpy(a.b, a_sec, 32);
    memcpy(b.b, b_sec, 32);
    memcpy(r.b, r_sec, 32);

    mw_pubkey_t A, B, R, expect_pub;
    mw_point_scalarmult_base(&A, &a);
    mw_point_scalarmult_base(&B, &b);
    mw_point_scalarmult_base(&R, &r);
    hex32("086f822e7d579ee89f6b614b0dd629ee59022328c367fab38b387ab7cc0ee0b1", expect_pub.b);
    CHECK_EQ_MEM(A.b, expect_pub.b, 32);
    hex32("2be9185ae2e4a8f1915b9b32dbe611fa332c7de09bfea0500cdc63bf141761a6", expect_pub.b);
    CHECK_EQ_MEM(B.b, expect_pub.b, 32);
    hex32("f73c6447f7b1acc790f405587ef1fde13fa3cf167980d4e899385b5cdef72fb7", expect_pub.b);
    CHECK_EQ_MEM(R.b, expect_pub.b, 32);

    // Sender and receiver must agree on 8*r*A == 8*a*R.
    mw_point_t d_send, d_recv, expect;
    CHECK_EQ_INT(mw_generate_key_derivation(&A, &r, &d_send), MW_OK);
    CHECK_EQ_INT(mw_generate_key_derivation(&R, &a, &d_recv), MW_OK);
    CHECK_EQ_MEM(d_send.b, d_recv.b, 32);
    hex32("150a95905596f3892f89eb66652ab585448619318dc7b92051dd154fc74827fa", expect.b);
    CHECK_EQ_MEM(d_send.b, expect.b, 32);

    struct { uint32_t idx; const char* scalar; const char* pub; const char* sec; } v[] = {
        { 0,
          "a8edeb2a11ee8e40b9374e8ee266bba0a42c353dac95ea568549920e982b220b",
          "96f142a60b4a984a8caddb08f0edf7b6007e6447a0fd49e762ea669fb963234d",
          "2a149abbd7c38ed0860b7ec769ccb1241197e65c9aae4d4780399af033dad20a" },
        { 7,
          "ea39ce3b50969fbff444b3cc2cd251b945e0b4b78955184e592cfa7029975b02",
          "26d30ab92fba7386eb0d9039d69446a92ec772747421331d313518080a84a88e",
          "6c607ccc166c9f4fc218e305b437483db24a66d7776e7b3e541c0253c5450c02" },
        { 300,     // exercises the two-byte varint
          "30f93422b222f61ddd19bb5b0a76b8a709ded74cdfdfe77e79a6da42f5c78700",
          "72b3ea86a6b59b7763071b3921d9c1f26197e7dab48d2535454eddf0c3bc694e",
          "b21fe3b278f8f5adaaedea9491dbae2b7648896ccdf84a6f7496e22491763800" },
    };

    for (size_t i = 0; i < sizeof(v) / sizeof(v[0]); ++i) {
        uint8_t want[32];
        mw_scalar_t s;
        mw_derivation_to_scalar(&d_send, v[i].idx, &s);
        hex32(v[i].scalar, want);
        CHECK_EQ_MEM(s.b, want, 32);

        mw_pubkey_t P;
        CHECK_EQ_INT(mw_derive_public_key(&d_send, v[i].idx, &B, &P), MW_OK);
        hex32(v[i].pub, want);
        CHECK_EQ_MEM(P.b, want, 32);

        mw_seckey_t x;
        mw_derive_secret_key(&d_send, v[i].idx, &b, &x);
        hex32(v[i].sec, want);
        CHECK_EQ_MEM(x.b, want, 32);

        // The one-time secret really opens the one-time public key.
        CHECK_EQ_INT(mw_check_key_pair(&x, &P), MW_OK);
    }

    // A malformed public key must be rejected, not crash. y = 2 has no
    // matching x on the curve, so this encoding can never decompress.
    mw_pubkey_t junk;
    memset(junk.b, 0, 32);
    junk.b[0] = 2;
    mw_point_t out;
    CHECK_EQ_INT(mw_generate_key_derivation(&junk, &r, &out), MW_ERR_FORMAT);
    CHECK_EQ_INT(mw_generate_key_derivation(NULL, &r, &out), MW_ERR_INVALID_ARG);

    // A non-canonical scalar (>= l) must be refused too.
    mw_seckey_t huge;
    memset(huge.b, 0xff, 32);
    CHECK_EQ_INT(mw_generate_key_derivation(&A, &huge, &out), MW_ERR_INVALID_ARG);
}

MW_TEST(test_ecdh)
{
    mw_scalar_t shared;
    hex32("8accab716aa30effb2ff88080a844e8e3f332b51ea48c87ef8224ec445497701", shared.b);

    uint8_t h[32], want[32];
    mw_ecdh_hash(&shared, h);
    hex32("c0e622dc4108e57e00000000000000000000000000000000000000000000000000", want);
    CHECK_EQ_MEM(h, want, 8);

    const uint64_t amount = 1234567890123ULL;
    uint8_t enc[8];
    mw_ecdh_mask_t mask;
    mw_ecdh_encode(&shared, amount, enc, &mask);

    uint8_t want_enc[8];
    mw_test_hex("0be2d9ad5e09e57e", want_enc, 8);
    CHECK_EQ_MEM(enc, want_enc, 8);

    hex32("77ad98d701311b74d791656dfa4eadff95fbfa0bd00a43fe6234b16ba259fd05", want);
    CHECK_EQ_MEM(mask.b, want, 32);
    CHECK(mw_sc_check(&mask));

    // Decoding the encoded blob gives the amount back.
    uint64_t roundtrip = 0;
    for (int i = 7; i >= 0; --i) {
        roundtrip = (roundtrip << 8) | enc[i];
    }
    mw_ecdh_mask_t mask2;
    mw_ecdh_decode(&shared, &roundtrip, &mask2);
    CHECK_EQ_INT(roundtrip, amount);
    CHECK_EQ_MEM(mask2.b, mask.b, 32);

    // Zero amounts and the maximum supply must survive as well.
    const uint64_t values[] = { 0ULL, 1ULL, 18446744073709551615ULL };
    for (size_t i = 0; i < sizeof(values) / sizeof(values[0]); ++i) {
        uint8_t blob[8];
        mw_ecdh_encode(&shared, values[i], blob, NULL);
        uint64_t v = 0;
        for (int j = 7; j >= 0; --j) {
            v = (v << 8) | blob[j];
        }
        mw_ecdh_decode(&shared, &v, NULL);
        CHECK_EQ_INT(v, values[i]);
    }
}

int main(void)
{
    RUN_TEST(test_legacy_account_keys);
    RUN_TEST(test_passphrase_folding);
    RUN_TEST(test_polyseed_account_keys);
    RUN_TEST(test_subaddress);
    RUN_TEST(test_key_derivation);
    RUN_TEST(test_ecdh);
    return mw_test_summary();
}
