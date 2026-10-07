// AES-256-GCM vectors + the multi-wallet store lifecycle (TZ 7, 8.1).
//
// Build (host):
//   gcc -std=c11 -Wall -Wextra -O2 -I../src -I. -DMW_HOST_BUILD=1
//       test_wallet_store.c ../src/wallet/*.c ../src/crypto/*.c
//       ../src/monero/*.c ../src/data/*.c test_framework.c -o /tmp/t_ws && /tmp/t_ws

#include "test_framework.h"

#include "crypto/aes_gcm.h"
#include "crypto/memzero.h"
#include "crypto/random.h"
#include "crypto/ed25519.h"
#include "monero/address.h"
#include "monero/keys.h"
#include "monero/mnemonic.h"
#include "data/wordlist.h"
#include "wallet/secure_storage.h"
#include "wallet/wallet_store.h"

// Host-backend test hooks (not part of the frozen API).
void mw_host_store_set_dir(const char* dir);
void mw_host_store_reset(void);
void mw_settings_test_set_display(int has_touch, int width, int height);

#define STORE_DIR "./.mw_test_store"

// task2 item 1: every seal needs the user password key next to the eFuse
// key. The suites install a fixed one; device_auth itself is covered by
// test_device_auth.c.
static const uint8_t TEST_USER_KEY[32] = {
    0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18, 0x19, 0x1a, 0x1b,
    0x1c, 0x1d, 0x1e, 0x1f, 0x20, 0x21, 0x22, 0x23, 0x24, 0x25, 0x26, 0x27,
    0x28, 0x29, 0x2a, 0x2b, 0x2c, 0x2d, 0x2e, 0x2f
};

static void fresh_store(void)
{
    mw_host_store_set_dir(STORE_DIR);
    mw_host_store_reset();
    CHECK_EQ_INT(mw_secure_key_provision(), MW_OK);
    CHECK_EQ_INT(mw_secure_key_status(), MW_OK);
    CHECK_EQ_INT(mw_secure_user_key_set(TEST_USER_KEY), MW_OK);
    CHECK_EQ_INT(mw_wallet_store_init(), MW_OK);
}

// ---------------------------------------------------------------------------
// AES-256 / AES-256-GCM known-answer tests
// ---------------------------------------------------------------------------

MW_TEST(test_aes256_block_fips197)
{
    // FIPS-197 Appendix C.3, AES-256.
    uint8_t key[32], in[16], want[16], got[16];
    mw_test_hex("000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f", key, sizeof key);
    mw_test_hex("00112233445566778899aabbccddeeff", in, sizeof in);
    mw_test_hex("8ea2b7ca516745bfeafc49904b496089", want, sizeof want);
    mw_aes256_encrypt_block(key, in, got);
    CHECK_EQ_MEM(got, want, 16);
}

typedef struct {
    const char* name;
    const char* key;
    const char* iv;
    const char* aad;
    const char* pt;
    const char* ct;
    const char* tag;
} gcm_vector_t;

// NIST SP 800-38D / McGrew-Viega GCM test cases 13..18 (the AES-256 set), plus
// two extra cases covering GMAC (no plaintext, with AAD) and the 16-byte IV the
// sealing layer uses.  Cross-checked against OpenSSL.
static const gcm_vector_t kGcmVectors[] = {
    {   // Test case 13 - zero-length plaintext, zero-length AAD
        "gcm-tc13", "00000000000000000000000000000000""00000000000000000000000000000000",
        "000000000000000000000000", "", "", "",
        "530f8afbc74536b9a963b4f1c4cb738b"
    },
    {   // Test case 14 - single all-zero block
        "gcm-tc14", "00000000000000000000000000000000""00000000000000000000000000000000",
        "000000000000000000000000", "", "00000000000000000000000000000000",
        "cea7403d4d606b6e074ec5d3baf39d18",
        "d0d1c8a799996bf0265b98b5d48ab919"
    },
    {   // Test case 15 - 64-byte plaintext, no AAD
        "gcm-tc15", "feffe9928665731c6d6a8f9467308308feffe9928665731c6d6a8f9467308308",
        "cafebabefacedbaddecaf888", "",
        "d9313225f88406e5a55909c5aff5269a86a7a9531534f7da2e4c303d8a318a72"
        "1c3c0c95956809532fcf0e2449a6b525b16aedf5aa0de657ba637b391aafd255",
        "522dc1f099567d07f47f37a32a84427d643a8cdcbfe5c0c97598a2bd2555d1aa"
        "8cb08e48590dbb3da7b08b1056828838c5f61e6393ba7a0abcc9f662898015ad",
        "b094dac5d93471bdec1a502270e3cc6c"
    },
    {   // Test case 16 - 60-byte plaintext WITH 20-byte AAD
        "gcm-tc16", "feffe9928665731c6d6a8f9467308308feffe9928665731c6d6a8f9467308308",
        "cafebabefacedbaddecaf888", "feedfacedeadbeeffeedfacedeadbeefabaddad2",
        "d9313225f88406e5a55909c5aff5269a86a7a9531534f7da2e4c303d8a318a72"
        "1c3c0c95956809532fcf0e2449a6b525b16aedf5aa0de657ba637b39",
        "522dc1f099567d07f47f37a32a84427d643a8cdcbfe5c0c97598a2bd2555d1aa"
        "8cb08e48590dbb3da7b08b1056828838c5f61e6393ba7a0abcc9f662",
        "76fc6ece0f4e1768cddf8853bb2d551b"
    },
    {   // Test case 17 - short (8-byte) IV, exercises the GHASH-based J0 path
        "gcm-tc17", "feffe9928665731c6d6a8f9467308308feffe9928665731c6d6a8f9467308308",
        "cafebabefacedbad", "feedfacedeadbeeffeedfacedeadbeefabaddad2",
        "d9313225f88406e5a55909c5aff5269a86a7a9531534f7da2e4c303d8a318a72"
        "1c3c0c95956809532fcf0e2449a6b525b16aedf5aa0de657ba637b39",
        "c3762df1ca787d32ae47c13bf19844cbaf1ae14d0b976afac52ff7d79bba9de0"
        "feb582d33934a4f0954cc2363bc73f7862ac430e64abe499f47c9b1f",
        "3a337dbf46a792c45e454913fe2ea8f2"
    },
    {   // Test case 18 - 60-byte IV
        "gcm-tc18", "feffe9928665731c6d6a8f9467308308feffe9928665731c6d6a8f9467308308",
        "9313225df88406e555909c5aff5269aa6a7a9538534f7da1e4c303d2a318a728"
        "c3c0c95156809539fcf0e2429a6b525416aedbf5a0de6a57a637b39b",
        "feedfacedeadbeeffeedfacedeadbeefabaddad2",
        "d9313225f88406e5a55909c5aff5269a86a7a9531534f7da2e4c303d8a318a72"
        "1c3c0c95956809532fcf0e2449a6b525b16aedf5aa0de657ba637b39",
        "5a8def2f0c9e53f1f75d7853659e2a20eeb2b22aafde6419a058ab4f6f746bf4"
        "0fc0c3b780f244452da3ebf1c5d82cdea2418997200ef82e44ae7e3f",
        "a44a8266ee1c8eb0c8b5d4cf5ae9f19a"
    },
    {   // GMAC: AAD only, zero-length plaintext
        "gcm-gmac", "00000000000000000000000000000000""00000000000000000000000000000000",
        "000000000000000000000000", "feedfacedeadbeeffeedfacedeadbeefabaddad2", "", "",
        "6605ba8cc3d0e5864e8d04e07bfc8b36"
    },
    {   // 16-byte IV - exactly how mw_seal() calls the layer
        "gcm-iv16", "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f",
        "000102030405060708090a0b0c0d0e0f", "6d772e7365616c",
        "0102030405060708090a0b0c0d0e0f1011121314",
        "666ea3723ce24d2094f5d02558aa23a345a178b5",
        "54f37ca37125b6cf77c6a667ef9c15fc"
    },
};

MW_TEST(test_aes_gcm_nist_vectors)
{
    for (size_t i = 0; i < sizeof kGcmVectors / sizeof kGcmVectors[0]; i++) {
        const gcm_vector_t* v = &kGcmVectors[i];
        uint8_t key[32], iv[80], aad[32], pt[80], want_ct[80], want_tag[16];
        uint8_t ct[80], tag[16], back[80];
        size_t iv_len, aad_len, pt_len, ct_len;
        int rc;

        mw_test_current = v->name;
        CHECK_EQ_INT(mw_test_hex(v->key, key, sizeof key), 32u);
        iv_len  = mw_test_hex(v->iv,  iv,  sizeof iv);
        aad_len = mw_test_hex(v->aad, aad, sizeof aad);
        pt_len  = mw_test_hex(v->pt,  pt,  sizeof pt);
        ct_len  = mw_test_hex(v->ct,  want_ct, sizeof want_ct);
        CHECK_EQ_INT(mw_test_hex(v->tag, want_tag, sizeof want_tag), 16u);
        CHECK_EQ_INT(pt_len, ct_len);

        rc = mw_aes256_gcm_encrypt(key, iv, iv_len,
                                   aad_len ? aad : NULL, aad_len,
                                   pt_len ? pt : NULL, pt_len,
                                   ct, tag);
        CHECK_EQ_INT(rc, MW_AES_GCM_OK);
        if (pt_len) CHECK_EQ_MEM(ct, want_ct, pt_len);
        CHECK_EQ_MEM(tag, want_tag, 16);

        rc = mw_aes256_gcm_decrypt(key, iv, iv_len,
                                   aad_len ? aad : NULL, aad_len,
                                   pt_len ? want_ct : NULL, pt_len,
                                   want_tag, back);
        CHECK_EQ_INT(rc, MW_AES_GCM_OK);
        if (pt_len) CHECK_EQ_MEM(back, pt, pt_len);

        // Flip one bit of the tag: authentication must fail.
        memcpy(tag, want_tag, 16);
        tag[7] ^= 0x01u;
        rc = mw_aes256_gcm_decrypt(key, iv, iv_len,
                                   aad_len ? aad : NULL, aad_len,
                                   pt_len ? want_ct : NULL, pt_len, tag, back);
        CHECK_EQ_INT(rc, MW_AES_GCM_BAD_TAG);

        // Flip one bit of the ciphertext: authentication must fail.
        if (pt_len) {
            memcpy(ct, want_ct, pt_len);
            ct[0] ^= 0x80u;
            rc = mw_aes256_gcm_decrypt(key, iv, iv_len,
                                       aad_len ? aad : NULL, aad_len,
                                       ct, pt_len, want_tag, back);
            CHECK_EQ_INT(rc, MW_AES_GCM_BAD_TAG);
        }
        // Flip one bit of the AAD: authentication must fail.
        if (aad_len) {
            aad[0] ^= 0x40u;
            rc = mw_aes256_gcm_decrypt(key, iv, iv_len, aad, aad_len,
                                       pt_len ? want_ct : NULL, pt_len,
                                       want_tag, back);
            CHECK_EQ_INT(rc, MW_AES_GCM_BAD_TAG);
        }
    }
}

MW_TEST(test_aes_gcm_inplace_and_long)
{
    // In-place operation (ct aliases pt) must work in both directions.
    uint8_t key[32], iv[16], buf[200], ref[200], tag[16];
    for (size_t i = 0; i < sizeof key; i++) key[i] = (uint8_t)(i * 7u + 1u);
    for (size_t i = 0; i < sizeof iv;  i++) iv[i]  = (uint8_t)(i * 13u);
    for (size_t i = 0; i < sizeof buf; i++) buf[i] = (uint8_t)(i * 31u + 5u);
    memcpy(ref, buf, sizeof buf);

    CHECK_EQ_INT(mw_aes256_gcm_encrypt(key, iv, sizeof iv, NULL, 0,
                                       buf, sizeof buf, buf, tag), MW_AES_GCM_OK);
    CHECK(memcmp(buf, ref, sizeof buf) != 0);
    CHECK_EQ_INT(mw_aes256_gcm_decrypt(key, iv, sizeof iv, NULL, 0,
                                       buf, sizeof buf, tag, buf), MW_AES_GCM_OK);
    CHECK_EQ_MEM(buf, ref, sizeof buf);
}

// ---------------------------------------------------------------------------
// Sealing layer
// ---------------------------------------------------------------------------

MW_TEST(test_seal_unseal_roundtrip)
{
    uint8_t pt[64], ct[64], back[64], iv[16], tag[16];
    fresh_store();
    for (size_t i = 0; i < sizeof pt; i++) pt[i] = (uint8_t)(0xa0u + i);

    CHECK_EQ_INT(mw_seal("mw.test.label", pt, sizeof pt, iv, tag, ct, sizeof ct), MW_OK);
    CHECK(memcmp(ct, pt, sizeof pt) != 0);
    CHECK_EQ_INT(mw_unseal("mw.test.label", ct, sizeof ct, iv, tag, back, sizeof back), MW_OK);
    CHECK_EQ_MEM(back, pt, sizeof pt);

    // A different label derives a different key -> the tag check must fail.
    CHECK_EQ_INT(mw_unseal("mw.other.label", ct, sizeof ct, iv, tag, back, sizeof back),
                 MW_ERR_DECRYPT);
    // Tampered ciphertext must fail.
    ct[3] ^= 0x10u;
    CHECK_EQ_INT(mw_unseal("mw.test.label", ct, sizeof ct, iv, tag, back, sizeof back),
                 MW_ERR_DECRYPT);

    // Two seals of the same plaintext must differ (fresh random IV each time).
    {
        uint8_t ct2[64], iv2[16], tag2[16];
        CHECK_EQ_INT(mw_seal("mw.test.label", pt, sizeof pt, iv2, tag2, ct2, sizeof ct2), MW_OK);
        CHECK(memcmp(iv, iv2, sizeof iv) != 0);
    }

    // task2 item 1: a different user key (= a different device password)
    // cannot open the record, and no user key at all refuses outright.
    {
        uint8_t other[32];
        memcpy(other, TEST_USER_KEY, 32);
        other[0] ^= 0x01u;
        ct[3] ^= 0x10u;                                    // undo the tamper above
        CHECK_EQ_INT(mw_secure_user_key_set(other), MW_OK);
        CHECK_EQ_INT(mw_unseal("mw.test.label", ct, sizeof ct, iv, tag, back, sizeof back),
                     MW_ERR_DECRYPT);
        mw_secure_user_key_clear();
        CHECK(!mw_secure_user_key_present());
        CHECK_EQ_INT(mw_unseal("mw.test.label", ct, sizeof ct, iv, tag, back, sizeof back),
                     MW_ERR_NOT_SUPPORTED);
        CHECK_EQ_INT(mw_secure_user_key_set(TEST_USER_KEY), MW_OK);
        CHECK_EQ_INT(mw_unseal("mw.test.label", ct, sizeof ct, iv, tag, back, sizeof back),
                     MW_OK);
        CHECK_EQ_MEM(back, pt, sizeof pt);
    }
}

MW_TEST(test_seal_requires_provisioned_key)
{
    uint8_t pt[16] = {0}, ct[16], iv[16], tag[16];
    mw_host_store_set_dir(STORE_DIR);
    mw_host_store_reset();
    CHECK_EQ_INT(mw_secure_user_key_set(TEST_USER_KEY), MW_OK);
    CHECK_EQ_INT(mw_secure_key_status(), MW_ERR_NOT_SUPPORTED);
    CHECK_EQ_INT(mw_seal("mw.x", pt, sizeof pt, iv, tag, ct, sizeof ct),
                 MW_ERR_NOT_SUPPORTED);
    CHECK_EQ_INT(mw_secure_key_provision(), MW_OK);
    CHECK_EQ_INT(mw_secure_key_status(), MW_OK);
    // Provisioning twice is a no-op, never a re-key (mirrors the eFuse).
    CHECK_EQ_INT(mw_secure_key_provision(), MW_OK);
    // An all-zero user key is refused, so a bug that forgets to derive one
    // cannot silently seal under a constant.
    {
        uint8_t zero[32];
        memset(zero, 0, sizeof zero);
        CHECK_EQ_INT(mw_secure_user_key_set(zero), MW_ERR_INVALID_ARG);
    }
}

// ---------------------------------------------------------------------------
// Wallet lifecycle (TZ 7)
// ---------------------------------------------------------------------------

static void fill_seed(uint8_t* seed, size_t len, uint8_t salt)
{
    for (size_t i = 0; i < len; i++) seed[i] = (uint8_t)(i * 3u + salt);
}

MW_TEST(test_wallet_create_and_read_back)
{
    uint8_t seed[32], got[32];
    uint32_t id = 0;
    size_t got_len = 0;
    const wallet_entry_t* w;
    wallet_store_t st;

    fresh_store();
    fill_seed(seed, sizeof seed, 0x11u);

    CHECK_EQ_INT(mw_wallet_create("Main", MW_SEED_MONERO_LEGACY, seed, sizeof seed,
                                  2500000u, &id), MW_OK);
    CHECK(id != 0);

    w = mw_wallet_get(id);
    CHECK(w != NULL);
    if (w) {
        CHECK_EQ_STR(w->name, "Main");
        CHECK_EQ_INT(w->restore_height, 2500000u);
        CHECK_EQ_INT(w->wallet_type, 0);
        CHECK_EQ_INT(w->is_view_only, 0);
        // The seed must NOT be recoverable from the record without unsealing.
        CHECK(memcmp(w->encrypted_seed, seed, sizeof seed) != 0);
        CHECK(!mw_ct_is_zero(w->seed_iv, 16));
        CHECK(!mw_ct_is_zero(w->seed_tag, 16));
    }

    CHECK_EQ_INT(mw_wallet_store_load(&st), MW_OK);
    CHECK_EQ_INT(st.count, 1u);
    CHECK_EQ_INT(st.active_wallet_id, id);

    CHECK_EQ_INT(mw_wallet_unseal_seed(id, got, sizeof got, &got_len), MW_OK);
    CHECK_EQ_INT(got_len, 32u);
    CHECK_EQ_MEM(got, seed, 32);

    // Unknown id.
    CHECK_EQ_INT(mw_wallet_unseal_seed(id + 999u, got, sizeof got, &got_len),
                 MW_ERR_INVALID_ARG);
}

MW_TEST(test_wallet_persistence_across_reload)
{
    uint8_t seed[32], got[32];
    uint32_t id = 0;
    size_t got_len = 0;
    wallet_store_t st;

    fresh_store();
    fill_seed(seed, sizeof seed, 0x42u);
    CHECK_EQ_INT(mw_wallet_create("Cold", MW_SEED_MONERO_LEGACY, seed, sizeof seed,
                                  1u, &id), MW_OK);

    // Simulate a reboot: drop the cache and re-read the blob from storage.
    CHECK_EQ_INT(mw_wallet_store_init(), MW_OK);
    CHECK_EQ_INT(mw_wallet_store_load(&st), MW_OK);
    CHECK_EQ_INT(st.count, 1u);
    CHECK_EQ_INT(st.wallets[0].id, id);
    CHECK_EQ_STR(st.wallets[0].name, "Cold");
    CHECK_EQ_INT(mw_wallet_unseal_seed(id, got, sizeof got, &got_len), MW_OK);
    CHECK_EQ_INT(got_len, 32u);
    CHECK_EQ_MEM(got, seed, 32);
}

// ---------------------------------------------------------------------------
// Polyseed storage (D1): the sealed record must carry the birthday and the
// feature bits, because mw_polyseed_keygen() salts the spend-key PBKDF2 with
// both. A record that keeps only the 19 secret bytes derives the wallet that
// the same phrase with birthday 0 would produce - a different address, whose
// coins cannot be recovered from the phrase that was written down.
// ---------------------------------------------------------------------------

// tevador/polyseed's own English test phrase. Its birthday is 1 (NOT 0), which
// is exactly what the old storage format threw away.
#define POLYSEED_PHRASE                                                      \
    "raven tail swear infant grief assist regular lamp duck valid "          \
    "someone little harsh puppy airport language"

// Expected primary address, derived independently of this codebase from the
// Polyseed reference algorithm (PBKDF2-HMAC-SHA256 over the zero-padded
// 32-byte secret with salt "POLYSEED key"\0\xff\xff\xff || coin || birthday ||
// features, 10000 rounds -> sc_reduce32 -> spend key; view = Hs(spend);
// Monero base58 with the 0x12 mainnet prefix).
#define POLYSEED_ADDRESS                                                     \
    "47AjPj7DVPQVGGXJXbbTMZWcKQDejGHYZChVkeujy8qPLjKkgdsxge4DzvkRMgU4sDUig"  \
    "GLuBN9stKBMowhuXH2HJHWAuRf"

// What the discarded-birthday bug produced instead: the same phrase taken with
// birthday 0. Asserted explicitly so a regression cannot pass by accident.
#define POLYSEED_ADDRESS_BIRTHDAY0                                           \
    "47526p41Exh89HrA7Bk6xqjko5vwL8tc27NZcFr9GphsQ28skPLGYty1TAcGEaABpe9dU"  \
    "N8qrmBbKhBHb8VZHHhUR2qfKhy"

static void polyseed_from_phrase(const char* phrase, mw_polyseed_t* out)
{
    const mw_wordlist_t* wl = mw_wordlist(MW_WL_POLYSEED_EN);
    uint16_t idx[MW_POLYSEED_WORDS];
    int n = 0;
    const char* p = phrase;

    while (*p != '\0' && n < MW_POLYSEED_WORDS) {
        char word[32];
        size_t len = 0;
        while (*p == ' ') p++;
        while (p[len] != '\0' && p[len] != ' ' && len < sizeof word - 1) {
            word[len] = p[len];
            len++;
        }
        word[len] = '\0';
        p += len;
        int found = mw_wordlist_find(wl, word);
        CHECK(found >= 0);
        idx[n++] = (uint16_t)(found < 0 ? 0 : found);
    }
    CHECK_EQ_INT(n, MW_POLYSEED_WORDS);
    CHECK_EQ_INT(mw_polyseed_decode(idx, wl, out), MW_OK);
}

static void address_of(const mw_account_keys_t* keys, char* out, size_t cap)
{
    mw_address_t addr;
    out[0] = '\0';
    CHECK_EQ_INT(mw_address_from_keys(keys, MW_NET_MAINNET, &addr), MW_OK);
    CHECK_EQ_INT(mw_address_encode(&addr, out, cap), MW_OK);
}

MW_TEST(test_wallet_polyseed_context_roundtrip)
{
    uint8_t blob[MW_POLYSEED_BLOB_MAX], got[64];
    size_t blob_len = 0, got_len = 0;
    uint32_t id = 0;
    const wallet_entry_t* w;
    mw_polyseed_t seed;

    fresh_store();
    polyseed_from_phrase(POLYSEED_PHRASE, &seed);
    CHECK_EQ_INT(seed.birthday, 1);

    CHECK_EQ_INT(mw_polyseed_pack(&seed, blob, sizeof blob, &blob_len), MW_OK);
    CHECK_EQ_INT(blob_len, MW_POLYSEED_BLOB_MIN);

    CHECK_EQ_INT(mw_wallet_create("Poly", MW_SEED_POLYSEED, blob, blob_len,
                                  0u, &id), MW_OK);
    w = mw_wallet_get(id);
    CHECK(w != NULL);
    if (w) CHECK_EQ_INT(w->wallet_type, 1);

    // What comes back out is the whole context, birthday included.
    CHECK_EQ_INT(mw_wallet_unseal_seed(id, got, sizeof got, &got_len), MW_OK);
    CHECK_EQ_INT(got_len, blob_len);
    CHECK_EQ_MEM(got, blob, blob_len);

    mw_polyseed_t back;
    CHECK_EQ_INT(mw_polyseed_unpack(got, got_len, &back), MW_OK);
    CHECK_EQ_INT(back.birthday, seed.birthday);
    CHECK_EQ_INT(back.features, seed.features);
    CHECK_EQ_MEM(back.secret, seed.secret, 32);

    // Wrong length for the declared type is rejected up front. In particular a
    // BARE 19-byte secret - the old payload - is now refused outright rather
    // than being sealed without its birthday.
    CHECK_EQ_INT(mw_wallet_create("Bad", MW_SEED_MONERO_LEGACY, blob, 19u, 0u, &id),
                 MW_ERR_INVALID_ARG);
    CHECK_EQ_INT(mw_wallet_create("Bad", MW_SEED_POLYSEED, blob, 4u, 0u, &id),
                 MW_ERR_INVALID_ARG);
    CHECK_EQ_INT(mw_wallet_create("Bad", MW_SEED_POLYSEED, seed.secret,
                                  MW_POLYSEED_SECRET_SIZE, 0u, &id),
                 MW_ERR_INVALID_ARG);
}

// The regression test for D1: phrase -> mw_wallet_create -> mw_wallet_load_keys
// must land on the address the Polyseed reference algorithm produces.
MW_TEST(test_wallet_polyseed_birthday_survives_storage)
{
    uint8_t blob[MW_POLYSEED_BLOB_MAX];
    size_t blob_len = 0;
    uint32_t id = 0;
    mw_polyseed_t seed;
    mw_account_keys_t keys;
    char addr[MW_ADDRESS_STR_MAX];

    fresh_store();
    polyseed_from_phrase(POLYSEED_PHRASE, &seed);
    CHECK_EQ_INT(seed.birthday, 1);
    CHECK_EQ_INT(seed.features, 0);

    CHECK_EQ_INT(mw_polyseed_pack(&seed, blob, sizeof blob, &blob_len), MW_OK);
    CHECK_EQ_INT(mw_wallet_create("Imported", MW_SEED_POLYSEED, blob, blob_len,
                                  0u, &id), MW_OK);

    // Straight after creation ...
    memset(&keys, 0, sizeof keys);
    CHECK_EQ_INT(mw_wallet_load_keys(id, "", &keys), MW_OK);
    address_of(&keys, addr, sizeof addr);
    CHECK_EQ_STR(addr, POLYSEED_ADDRESS);
    CHECK(strcmp(addr, POLYSEED_ADDRESS_BIRTHDAY0) != 0);

    // ... and after a reboot, from the bytes that really went to storage.
    CHECK_EQ_INT(mw_wallet_store_init(), MW_OK);
    memset(&keys, 0, sizeof keys);
    CHECK_EQ_INT(mw_wallet_load_keys(id, "", &keys), MW_OK);
    address_of(&keys, addr, sizeof addr);
    CHECK_EQ_STR(addr, POLYSEED_ADDRESS);

    // The passphrase path still goes through Polyseed's own encryption.
    {
        mw_account_keys_t with_pp;
        memset(&with_pp, 0, sizeof with_pp);
        CHECK_EQ_INT(mw_wallet_load_keys(id, "password", &with_pp), MW_OK);
        CHECK(memcmp(&with_pp.sec, &keys.sec, sizeof keys.sec) != 0);
    }
}

// A version-1 record (bare length + secret, no birthday) must be refused, not
// reinterpreted: parsing those bytes as a v2 context would silently hand back
// yet another wallet.
MW_TEST(test_wallet_polyseed_v1_record_refused)
{
    uint8_t blob[MW_POLYSEED_BLOB_MAX], got[64];
    size_t blob_len = 0, got_len = 0;
    uint32_t id = 0;
    wallet_store_t st;
    mw_polyseed_t seed;
    mw_account_keys_t keys;

    fresh_store();
    polyseed_from_phrase(POLYSEED_PHRASE, &seed);
    CHECK_EQ_INT(mw_polyseed_pack(&seed, blob, sizeof blob, &blob_len), MW_OK);
    CHECK_EQ_INT(mw_wallet_create("Old", MW_SEED_POLYSEED, blob, blob_len,
                                  0u, &id), MW_OK);

    // Forge the old plaintext in place: [0] = secret length, then the secret.
    uint8_t v1[64];
    char label[40];
    memset(v1, 0xa5, sizeof v1);
    v1[0] = MW_POLYSEED_SECRET_SIZE;
    memcpy(v1 + 1, seed.secret, MW_POLYSEED_SECRET_SIZE);
    snprintf(label, sizeof label, "mw.seed.v1.%08lx", (unsigned long)id);

    CHECK_EQ_INT(mw_wallet_store_load(&st), MW_OK);
    CHECK_EQ_INT(mw_seal(label, v1, sizeof v1, st.wallets[0].seed_iv,
                         st.wallets[0].seed_tag, st.wallets[0].encrypted_seed,
                         sizeof st.wallets[0].encrypted_seed), MW_OK);
    CHECK_EQ_INT(mw_wallet_store_save(&st), MW_OK);

    // It decrypts and authenticates, and is still refused on format grounds.
    CHECK_EQ_INT(mw_wallet_unseal_seed(id, got, sizeof got, &got_len),
                 MW_ERR_VERSION);
    memset(&keys, 0xcc, sizeof keys);
    CHECK_EQ_INT(mw_wallet_load_keys(id, "", &keys), MW_ERR_VERSION);
    CHECK(mw_ct_is_zero(&keys, sizeof keys));
}

MW_TEST(test_wallet_name_rules)
{
    uint8_t seed[32];
    uint32_t id = 0, id2 = 0;
    char too_long[WALLET_NAME_LEN + 4];

    fresh_store();
    fill_seed(seed, sizeof seed, 0x01u);

    CHECK_EQ_INT(mw_wallet_create("", MW_SEED_MONERO_LEGACY, seed, 32, 0, &id),
                 MW_ERR_INVALID_ARG);
    CHECK_EQ_INT(mw_wallet_create("   ", MW_SEED_MONERO_LEGACY, seed, 32, 0, &id),
                 MW_ERR_INVALID_ARG);
    CHECK_EQ_INT(mw_wallet_create("bad\nname", MW_SEED_MONERO_LEGACY, seed, 32, 0, &id),
                 MW_ERR_INVALID_ARG);
    CHECK_EQ_INT(mw_wallet_create("bad\tname", MW_SEED_MONERO_LEGACY, seed, 32, 0, &id),
                 MW_ERR_INVALID_ARG);
    CHECK_EQ_INT(mw_wallet_create("del\x7f", MW_SEED_MONERO_LEGACY, seed, 32, 0, &id),
                 MW_ERR_INVALID_ARG);

    memset(too_long, 'x', sizeof too_long);
    too_long[sizeof too_long - 1] = '\0';
    CHECK_EQ_INT(mw_wallet_create(too_long, MW_SEED_MONERO_LEGACY, seed, 32, 0, &id),
                 MW_ERR_INVALID_ARG);

    // UTF-8 (Cyrillic) names are fine - only control characters are refused.
    CHECK_EQ_INT(mw_wallet_create("\xd0\x9a\xd0\xbe\xd1\x88\xd0\xb5\xd0\xbb\xd1\x91\xd0\xba",
                                  MW_SEED_MONERO_LEGACY, seed, 32, 0, &id), MW_OK);

    // Duplicate names are refused, on create and on rename.
    CHECK_EQ_INT(mw_wallet_create("Alpha", MW_SEED_MONERO_LEGACY, seed, 32, 0, &id2), MW_OK);
    CHECK_EQ_INT(mw_wallet_create("Alpha", MW_SEED_MONERO_LEGACY, seed, 32, 0, &id), 
                 MW_ERR_INVALID_ARG);
    CHECK_EQ_INT(mw_wallet_rename(id2, "Alpha"), MW_OK);      // renaming to itself is ok
    CHECK_EQ_INT(mw_wallet_rename(id2, "Beta"), MW_OK);
    CHECK_EQ_STR(mw_wallet_get(id2)->name, "Beta");
    CHECK_EQ_INT(mw_wallet_rename(id2, ""), MW_ERR_INVALID_ARG);
    CHECK_EQ_INT(mw_wallet_rename(9999u, "Gamma"), MW_ERR_INVALID_ARG);
}

MW_TEST(test_wallet_max_wallets)
{
    uint8_t seed[32];
    uint32_t id = 0;
    char name[16];
    wallet_store_t st;

    fresh_store();
    for (int i = 0; i < MAX_WALLETS; i++) {
        fill_seed(seed, sizeof seed, (uint8_t)i);
        snprintf(name, sizeof name, "w%02d", i);
        CHECK_EQ_INT(mw_wallet_create(name, MW_SEED_MONERO_LEGACY, seed, 32, 0, &id), MW_OK);
    }
    CHECK_EQ_INT(mw_wallet_store_load(&st), MW_OK);
    CHECK_EQ_INT(st.count, (uint32_t)MAX_WALLETS);

    fill_seed(seed, sizeof seed, 0xffu);
    CHECK_EQ_INT(mw_wallet_create("overflow", MW_SEED_MONERO_LEGACY, seed, 32, 0, &id),
                 MW_ERR_TOO_MANY);

    // Every one of them must still unseal to its own distinct seed.
    for (uint32_t i = 0; i < st.count; i++) {
        uint8_t got[32], want[32];
        size_t got_len = 0;
        fill_seed(want, sizeof want, (uint8_t)i);
        CHECK_EQ_INT(mw_wallet_unseal_seed(st.wallets[i].id, got, sizeof got, &got_len), MW_OK);
        CHECK_EQ_INT(got_len, 32u);
        CHECK_EQ_MEM(got, want, 32);
    }
}

MW_TEST(test_wallet_set_active)
{
    uint8_t seed[32];
    uint32_t a = 0, b = 0;
    wallet_store_t st;

    fresh_store();
    fill_seed(seed, sizeof seed, 1);
    CHECK_EQ_INT(mw_wallet_create("A", MW_SEED_MONERO_LEGACY, seed, 32, 0, &a), MW_OK);
    fill_seed(seed, sizeof seed, 2);
    CHECK_EQ_INT(mw_wallet_create("B", MW_SEED_MONERO_LEGACY, seed, 32, 0, &b), MW_OK);

    CHECK_EQ_INT(mw_wallet_store_load(&st), MW_OK);
    CHECK_EQ_INT(st.active_wallet_id, a);       // first wallet becomes active
    CHECK_EQ_INT(mw_wallet_set_active(b), MW_OK);
    CHECK_EQ_INT(mw_wallet_store_load(&st), MW_OK);
    CHECK_EQ_INT(st.active_wallet_id, b);
    CHECK_EQ_INT(mw_wallet_set_active(12345u), MW_ERR_INVALID_ARG);
}

MW_TEST(test_wallet_secure_delete)
{
    uint8_t seed_a[32], seed_b[32], got[32];
    uint32_t a = 0, b = 0;
    size_t got_len = 0;
    wallet_store_t st;
    uint8_t saved_ct[64];

    fresh_store();
    fill_seed(seed_a, sizeof seed_a, 0xa1u);
    fill_seed(seed_b, sizeof seed_b, 0xb2u);
    CHECK_EQ_INT(mw_wallet_create("A", MW_SEED_MONERO_LEGACY, seed_a, 32, 100u, &a), MW_OK);
    CHECK_EQ_INT(mw_wallet_create("B", MW_SEED_MONERO_LEGACY, seed_b, 32, 200u, &b), MW_OK);
    memcpy(saved_ct, mw_wallet_get(a)->encrypted_seed, 64);

    CHECK_EQ_INT(mw_wallet_delete(a), MW_OK);
    CHECK(mw_wallet_get(a) == NULL);
    CHECK_EQ_INT(mw_wallet_unseal_seed(a, got, sizeof got, &got_len), MW_ERR_INVALID_ARG);

    // B survived, is intact and became the active wallet.
    CHECK_EQ_INT(mw_wallet_store_load(&st), MW_OK);
    CHECK_EQ_INT(st.count, 1u);
    CHECK_EQ_INT(st.wallets[0].id, b);
    CHECK_EQ_STR(st.wallets[0].name, "B");
    CHECK_EQ_INT(st.active_wallet_id, b);
    CHECK_EQ_INT(mw_wallet_unseal_seed(b, got, sizeof got, &got_len), MW_OK);
    CHECK_EQ_MEM(got, seed_b, 32);

    // The deleted record is gone from the persisted blob after a reload, and
    // its ciphertext is nowhere in the freshly loaded directory.
    CHECK_EQ_INT(mw_wallet_store_init(), MW_OK);
    CHECK_EQ_INT(mw_wallet_store_load(&st), MW_OK);
    CHECK_EQ_INT(st.count, 1u);
    for (uint32_t i = 0; i < st.count; i++)
        CHECK(memcmp(st.wallets[i].encrypted_seed, saved_ct, 64) != 0);

    // Deleting the last wallet clears the active id.
    CHECK_EQ_INT(mw_wallet_delete(b), MW_OK);
    CHECK_EQ_INT(mw_wallet_store_load(&st), MW_OK);
    CHECK_EQ_INT(st.count, 0u);
    CHECK_EQ_INT(st.active_wallet_id, 0u);
    CHECK_EQ_INT(mw_wallet_delete(b), MW_ERR_INVALID_ARG);
}

MW_TEST(test_wallet_id_not_reused_after_delete)
{
    uint8_t seed[32];
    uint32_t a = 0, b = 0;

    fresh_store();
    fill_seed(seed, sizeof seed, 5);
    CHECK_EQ_INT(mw_wallet_create("A", MW_SEED_MONERO_LEGACY, seed, 32, 0, &a), MW_OK);
    CHECK_EQ_INT(mw_wallet_delete(a), MW_OK);
    CHECK_EQ_INT(mw_wallet_create("A", MW_SEED_MONERO_LEGACY, seed, 32, 0, &b), MW_OK);
    CHECK(b != a);
}

MW_TEST(test_wallet_tampered_record_fails_closed)
{
    uint8_t seed[32], got[32];
    uint32_t id = 0;
    size_t got_len = 0;
    wallet_store_t st;

    fresh_store();
    fill_seed(seed, sizeof seed, 0x33u);
    CHECK_EQ_INT(mw_wallet_create("T", MW_SEED_MONERO_LEGACY, seed, 32, 0, &id), MW_OK);

    // Flip a ciphertext bit behind the store's back and save it again.
    CHECK_EQ_INT(mw_wallet_store_load(&st), MW_OK);
    st.wallets[0].encrypted_seed[10] ^= 0x01u;
    CHECK_EQ_INT(mw_wallet_store_save(&st), MW_OK);
    CHECK_EQ_INT(mw_wallet_unseal_seed(id, got, sizeof got, &got_len), MW_ERR_DECRYPT);

    // Re-labelling the record (changing its id) must also fail: the sealing key
    // is derived from the wallet id.
    CHECK_EQ_INT(mw_wallet_store_load(&st), MW_OK);
    st.wallets[0].encrypted_seed[10] ^= 0x01u;   // undo
    st.wallets[0].id = id + 7u;
    CHECK_EQ_INT(mw_wallet_store_save(&st), MW_OK);
    CHECK_EQ_INT(mw_wallet_unseal_seed(id + 7u, got, sizeof got, &got_len), MW_ERR_DECRYPT);
}

MW_TEST(test_wallet_load_keys)
{
    uint8_t seed[32];
    uint32_t id = 0;
    mw_account_keys_t keys, direct;

    fresh_store();
    fill_seed(seed, sizeof seed, 0x5au);
    CHECK_EQ_INT(mw_wallet_create("Signer", MW_SEED_MONERO_LEGACY, seed, 32, 0, &id), MW_OK);

    memset(&keys, 0, sizeof keys);
    CHECK_EQ_INT(mw_wallet_load_keys(id, "", &keys), MW_OK);

    // Must equal deriving straight from the seed with the same passphrase.
    memset(&direct, 0, sizeof direct);
    CHECK_EQ_INT(mw_seed_to_keys(MW_SEED_MONERO_LEGACY, seed, 32, "", &direct), MW_OK);
    CHECK_EQ_MEM(&keys.sec, &direct.sec, sizeof keys.sec);
    CHECK_EQ_MEM(&keys.pub, &direct.pub, sizeof keys.pub);

    // A different passphrase must give different keys (TZ 5.2).
    {
        mw_account_keys_t with_pp;
        memset(&with_pp, 0, sizeof with_pp);
        CHECK_EQ_INT(mw_wallet_load_keys(id, "correct horse", &with_pp), MW_OK);
        CHECK(memcmp(&with_pp.sec, &keys.sec, sizeof keys.sec) != 0);
    }

    // Error paths must leave the output wiped.
    memset(&keys, 0xcc, sizeof keys);
    CHECK_EQ_INT(mw_wallet_load_keys(id + 500u, "", &keys), MW_ERR_INVALID_ARG);
    CHECK(mw_ct_is_zero(&keys, sizeof keys));
    CHECK_EQ_INT(mw_wallet_load_keys(id, NULL, &keys), MW_ERR_INVALID_ARG);
    CHECK_EQ_INT(mw_wallet_load_keys(id, "", NULL), MW_ERR_INVALID_ARG);
}

// ---------------------------------------------------------------------------
// Import from raw spend/view keys (TZ 4.2) and the hidden flag (TZ 7.1)
// ---------------------------------------------------------------------------

// Builds a valid, canonical spend scalar, its matching view = Hs(spend) and
// the public spend key spend*G.
static void make_keypair(uint8_t salt, mw_seckey_t* spend, mw_seckey_t* view,
                         mw_pubkey_t* spend_pub)
{
    uint8_t raw[32];
    for (size_t i = 0; i < sizeof raw; i++) raw[i] = (uint8_t)(i * 5u + salt);
    memcpy(spend->b, raw, 32);
    mw_sc_reduce32(spend);
    mw_hash_to_scalar(spend->b, 32, view);
    mw_point_scalarmult_base(spend_pub, spend);
}

MW_TEST(test_wallet_create_from_keys_full)
{
    mw_seckey_t spend, view;
    mw_pubkey_t spend_pub;
    mw_account_keys_t keys, expected;
    uint32_t id = 0;
    const wallet_entry_t* w;

    fresh_store();
    make_keypair(0x21u, &spend, &view, &spend_pub);

    CHECK_EQ_INT(mw_wallet_create_from_keys("Imported", &spend, &view, &spend_pub,
                                            3000000u, &id), MW_OK);
    w = mw_wallet_get(id);
    CHECK(w != NULL);
    if (w) {
        CHECK_EQ_INT(w->is_view_only, 0);
        CHECK_EQ_INT(w->restore_height, 3000000u);
        CHECK(memcmp(w->encrypted_seed, spend.b, 32) != 0);   // sealed, not stored
    }

    memset(&keys, 0, sizeof keys);
    CHECK_EQ_INT(mw_wallet_load_keys(id, "", &keys), MW_OK);
    CHECK_EQ_INT(keys.view_only, 0);
    CHECK_EQ_MEM(keys.sec.spend.b, spend.b, 32);
    CHECK_EQ_MEM(keys.sec.view.b,  view.b,  32);
    CHECK_EQ_MEM(keys.pub.spend.b, spend_pub.b, 32);

    // Public halves must match a straight derivation from the same spend key.
    memset(&expected, 0, sizeof expected);
    mw_keys_from_legacy_seed(spend.b, &expected);
    CHECK_EQ_INT(mw_keys_derive_public(&expected), MW_OK);
    CHECK_EQ_MEM(keys.pub.spend.b, expected.pub.spend.b, 32);
    CHECK_EQ_MEM(keys.pub.view.b,  expected.pub.view.b,  32);

    // The passphrase must NOT alter an imported key pair.
    {
        mw_account_keys_t with_pp;
        memset(&with_pp, 0, sizeof with_pp);
        CHECK_EQ_INT(mw_wallet_load_keys(id, "irrelevant", &with_pp), MW_OK);
        CHECK_EQ_MEM(with_pp.sec.spend.b, spend.b, 32);
    }

    // Both `view` and `spend_pub` are optional when the spend secret is given.
    {
        uint32_t id2 = 0;
        mw_account_keys_t k2;
        CHECK_EQ_INT(mw_wallet_create_from_keys("SpendOnly", &spend, NULL, NULL,
                                                0, &id2), MW_OK);
        memset(&k2, 0, sizeof k2);
        CHECK_EQ_INT(mw_wallet_load_keys(id2, "", &k2), MW_OK);
        CHECK_EQ_MEM(k2.sec.view.b, view.b, 32);
        CHECK_EQ_MEM(k2.pub.spend.b, spend_pub.b, 32);
    }
}

MW_TEST(test_wallet_create_from_keys_mismatch_rejected)
{
    mw_seckey_t spend, view, wrong, wrong_view;
    mw_pubkey_t spend_pub, wrong_pub;
    uint32_t id = 0;

    fresh_store();
    make_keypair(0x31u, &spend, &view, &spend_pub);
    make_keypair(0x99u, &wrong, &wrong_view, &wrong_pub);   // an unrelated pair

    // view != Hs(spend)
    CHECK_EQ_INT(mw_wallet_create_from_keys("Bad", &spend, &wrong, NULL, 0, &id),
                 MW_ERR_KEY_MISMATCH);
    // spend_pub != spend*G
    CHECK_EQ_INT(mw_wallet_create_from_keys("Bad", &spend, &view, &wrong_pub, 0, &id),
                 MW_ERR_KEY_MISMATCH);
    CHECK(mw_wallet_get(id) == NULL);                        // nothing stored

    // Neither key supplied.
    CHECK_EQ_INT(mw_wallet_create_from_keys("None", NULL, NULL, NULL, 0, &id),
                 MW_ERR_INVALID_ARG);
    // A zero scalar is not a key.
    {
        mw_seckey_t zero;
        memset(&zero, 0, sizeof zero);
        CHECK_EQ_INT(mw_wallet_create_from_keys("Zero", &zero, NULL, NULL, 0, &id),
                     MW_ERR_INVALID_ARG);
        CHECK_EQ_INT(mw_wallet_create_from_keys("Zero", NULL, &zero, &spend_pub, 0, &id),
                     MW_ERR_INVALID_ARG);
    }
    // A non-canonical scalar (>= l) is rejected too (TZ 8.3).
    {
        mw_seckey_t noncanon;
        memset(noncanon.b, 0xff, 32);
        CHECK_EQ_INT(mw_wallet_create_from_keys("NonCanon", &noncanon, NULL, NULL,
                                                0, &id), MW_ERR_INVALID_ARG);
    }
    // Bad name still wins over everything else.
    CHECK_EQ_INT(mw_wallet_create_from_keys("", &spend, &view, NULL, 0, &id),
                 MW_ERR_INVALID_ARG);
}

MW_TEST(test_wallet_view_only_requires_public_spend_key)
{
    mw_seckey_t spend, view;
    mw_pubkey_t spend_pub, bad;
    uint32_t id = 0;

    fresh_store();
    make_keypair(0x51u, &spend, &view, &spend_pub);

    // The private view key alone is not a wallet: without the public spend key
    // the address cannot even be computed.
    CHECK_EQ_INT(mw_wallet_create_from_keys("Watch", NULL, &view, NULL, 0, &id),
                 MW_ERR_INVALID_ARG);

    // The public spend key goes through mw_point_check_public(), which returns
    // a BOOLEAN - these must all be refused, not silently accepted.
    memset(bad.b, 0, 32); bad.b[0] = 1;                  // the identity point
    CHECK(!mw_point_check_public(&bad));
    CHECK_EQ_INT(mw_wallet_create_from_keys("Watch", NULL, &view, &bad, 0, &id),
                 MW_ERR_SUBGROUP);

    memset(bad.b, 0xff, 32);                             // not a valid encoding
    CHECK(!mw_point_check_public(&bad));
    CHECK_EQ_INT(mw_wallet_create_from_keys("Watch", NULL, &view, &bad, 0, &id),
                 MW_ERR_SUBGROUP);

    // A small-order (order-8) point: on the curve, but outside the main
    // subgroup. This is the case a naive `== MW_OK` check would let through.
    mw_test_hex("c7176a703d4dd84fba3c0b760d10670f2a2053fa2c39ccc64ec7fd7792ac03fa",
                bad.b, 32);
    CHECK(mw_point_is_valid(&bad));
    CHECK(!mw_point_in_main_subgroup(&bad));
    CHECK(!mw_point_check_public(&bad));
    CHECK_EQ_INT(mw_wallet_create_from_keys("Watch", NULL, &view, &bad, 0, &id),
                 MW_ERR_SUBGROUP);

    CHECK(mw_wallet_get(id) == NULL);                    // nothing was stored
    // The real public spend key is accepted.
    CHECK_EQ_INT(mw_wallet_create_from_keys("Watch", NULL, &view, &spend_pub, 0, &id),
                 MW_OK);
    CHECK(mw_wallet_get(id) != NULL);
}

MW_TEST(test_wallet_view_only_roundtrip)
{
    mw_seckey_t spend, view;
    mw_pubkey_t spend_pub;
    mw_account_keys_t keys, full;
    uint32_t id = 0;
    const wallet_entry_t* w;
    wallet_store_t st;
    uint8_t got[64];
    size_t  got_len = 0;

    fresh_store();
    make_keypair(0x41u, &spend, &view, &spend_pub);

    CHECK_EQ_INT(mw_wallet_create_from_keys("Watch", NULL, &view, &spend_pub,
                                            1234u, &id), MW_OK);
    w = mw_wallet_get(id);
    CHECK(w != NULL);
    if (w) {
        CHECK_EQ_INT(w->is_view_only, 1);
        CHECK_EQ_INT(w->restore_height, 1234u);
        CHECK(memcmp(w->encrypted_seed, view.b, 32) != 0);      // sealed
        CHECK(memcmp(w->encrypted_seed + 32, spend_pub.b, 32) != 0);
    }

    memset(&keys, 0, sizeof keys);
    CHECK_EQ_INT(mw_wallet_load_keys(id, "", &keys), MW_OK);
    CHECK_EQ_INT(keys.view_only, 1);
    CHECK_EQ_MEM(keys.sec.view.b, view.b, 32);
    // Signing AND key-image sync must both be able to refuse early: the flag is
    // set and the private spend key is genuinely absent.
    CHECK(mw_ct_is_zero(keys.sec.spend.b, 32));
    // ...but the PUBLIC spend key is present, so the address is computable.
    CHECK_EQ_MEM(keys.pub.spend.b, spend_pub.b, 32);
    CHECK(!mw_ct_is_zero(keys.pub.spend.b, 32));

    memset(&full, 0, sizeof full);
    mw_keys_from_legacy_seed(spend.b, &full);
    CHECK_EQ_INT(mw_keys_derive_public(&full), MW_OK);
    CHECK_EQ_MEM(keys.pub.view.b,  full.pub.view.b,  32);
    CHECK_EQ_MEM(keys.pub.spend.b, full.pub.spend.b, 32);

    // The view-only wallet's primary address must equal the full wallet's.
    {
        mw_address_t a_view, a_full;
        char s_view[MW_ADDRESS_STR_MAX], s_full[MW_ADDRESS_STR_MAX];
        CHECK_EQ_INT(mw_address_from_keys(&keys, MW_NET_MAINNET, &a_view), MW_OK);
        CHECK_EQ_INT(mw_address_from_keys(&full, MW_NET_MAINNET, &a_full), MW_OK);
        CHECK_EQ_INT(mw_address_encode(&a_view, s_view, sizeof s_view), MW_OK);
        CHECK_EQ_INT(mw_address_encode(&a_full, s_full, sizeof s_full), MW_OK);
        CHECK_EQ_STR(s_view, s_full);
    }

    // The sealed payload is view || spend_pub, so it needs a 64-byte buffer.
    CHECK_EQ_INT(mw_wallet_unseal_seed(id, got, sizeof got, &got_len), MW_OK);
    CHECK_EQ_INT(got_len, 64u);
    CHECK_EQ_MEM(got, view.b, 32);
    CHECK_EQ_MEM(got + 32, spend_pub.b, 32);
    CHECK_EQ_INT(mw_wallet_unseal_seed(id, got, 32u, &got_len), MW_ERR_INVALID_ARG);

    // Survives a reload with the flag and both halves intact.
    CHECK_EQ_INT(mw_wallet_store_init(), MW_OK);
    CHECK_EQ_INT(mw_wallet_store_load(&st), MW_OK);
    CHECK_EQ_INT(st.count, 1u);
    CHECK_EQ_INT(st.wallets[0].is_view_only, 1);
    memset(&keys, 0, sizeof keys);
    CHECK_EQ_INT(mw_wallet_load_keys(id, "", &keys), MW_OK);
    CHECK_EQ_INT(keys.view_only, 1);
    CHECK_EQ_MEM(keys.pub.spend.b, spend_pub.b, 32);
    CHECK(mw_ct_is_zero(keys.sec.spend.b, 32));
}

MW_TEST(test_wallet_hidden_flag_persists)
{
    uint8_t seed[32];
    uint32_t a = 0, b = 0;
    wallet_store_t st;

    fresh_store();
    fill_seed(seed, sizeof seed, 0x61u);
    CHECK_EQ_INT(mw_wallet_create("Visible", MW_SEED_MONERO_LEGACY, seed, 32, 0, &a),
                 MW_OK);
    fill_seed(seed, sizeof seed, 0x62u);
    CHECK_EQ_INT(mw_wallet_create("Secret", MW_SEED_MONERO_LEGACY, seed, 32, 0, &b),
                 MW_OK);

    CHECK_EQ_INT(mw_wallet_get(b)->is_hidden, 0);
    CHECK_EQ_INT(mw_wallet_set_hidden(b, true), MW_OK);
    CHECK_EQ_INT(mw_wallet_get(b)->is_hidden, 1);
    CHECK_EQ_INT(mw_wallet_get(a)->is_hidden, 0);

    // Idempotent, and unknown ids are refused.
    CHECK_EQ_INT(mw_wallet_set_hidden(b, true), MW_OK);
    CHECK_EQ_INT(mw_wallet_set_hidden(4242u, true), MW_ERR_INVALID_ARG);

    // Survives a reboot.
    CHECK_EQ_INT(mw_wallet_store_init(), MW_OK);
    CHECK_EQ_INT(mw_wallet_store_load(&st), MW_OK);
    CHECK_EQ_INT(st.count, 2u);
    for (uint32_t i = 0; i < st.count; i++) {
        if (st.wallets[i].id == b) CHECK_EQ_INT(st.wallets[i].is_hidden, 1);
        else                       CHECK_EQ_INT(st.wallets[i].is_hidden, 0);
    }
    // A hidden wallet is still fully usable once selected.
    CHECK_EQ_INT(mw_wallet_set_hidden(b, false), MW_OK);
    CHECK_EQ_INT(mw_wallet_get(b)->is_hidden, 0);
}

// ---------------------------------------------------------------------------
// Settings (TZ 4.2, 5.5)
// ---------------------------------------------------------------------------

MW_TEST(test_settings_default_keyboard_auto_rule)
{
    // TZ 5.5: no touch -> SCROLL, regardless of resolution.
    mw_settings_test_set_display(0, 320, 480);
    CHECK_EQ_INT(mw_settings_default_keyboard(), KEYBOARD_SCROLL);
    mw_settings_test_set_display(0, 128, 64);
    CHECK_EQ_INT(mw_settings_default_keyboard(), KEYBOARD_SCROLL);

    // touch and >= 240x240 -> FULL.
    mw_settings_test_set_display(1, 240, 240);
    CHECK_EQ_INT(mw_settings_default_keyboard(), KEYBOARD_FULL);
    mw_settings_test_set_display(1, 240, 320);
    CHECK_EQ_INT(mw_settings_default_keyboard(), KEYBOARD_FULL);
    mw_settings_test_set_display(1, 480, 320);   // 320 >= 240 on both axes
    CHECK_EQ_INT(mw_settings_default_keyboard(), KEYBOARD_FULL);

    // touch and < 240x240 -> SCROLL (either axis below 240).
    mw_settings_test_set_display(1, 239, 240);
    CHECK_EQ_INT(mw_settings_default_keyboard(), KEYBOARD_SCROLL);
    mw_settings_test_set_display(1, 240, 239);
    CHECK_EQ_INT(mw_settings_default_keyboard(), KEYBOARD_SCROLL);
    mw_settings_test_set_display(1, 128, 64);
    CHECK_EQ_INT(mw_settings_default_keyboard(), KEYBOARD_SCROLL);
}

MW_TEST(test_settings_persist_and_version)
{
    mw_settings_t s, r;

    mw_host_store_set_dir(STORE_DIR);
    mw_host_store_reset();
    mw_settings_test_set_display(1, 240, 320);

    // First boot: defaults, with the AUTO keyboard rule applied.
    CHECK_EQ_INT(mw_settings_load(&s), MW_OK);
    CHECK_EQ_INT(s.keyboard, KEYBOARD_FULL);
    CHECK_EQ_INT(s.kb_layout, KB_LAYOUT_QWERTY);
    CHECK_EQ_INT(s.debug_log, 0);
    CHECK_EQ_INT(s.autolock_min, MW_AUTOLOCK_DEFAULT_MIN);
    CHECK_EQ_INT(s.touch_calibrated, 0);
    CHECK_EQ_INT(s.version, 2);

    s.keyboard         = KEYBOARD_SCROLL;
    s.kb_layout        = KB_LAYOUT_ABC;
    s.debug_log        = true;
    s.brightness       = 42;
    s.autolock_min     = 15;
    s.network          = MW_NET_STAGENET;
    s.touch_calibrated = true;
    for (int i = 0; i < 6; i++) s.touch_calib[i] = -1000 * (i + 1);
    CHECK_EQ_INT(mw_settings_save(&s), MW_OK);

    CHECK_EQ_INT(mw_settings_load(&r), MW_OK);
    CHECK_EQ_INT(r.keyboard, KEYBOARD_SCROLL);
    CHECK_EQ_INT(r.kb_layout, KB_LAYOUT_ABC);
    CHECK_EQ_INT(r.debug_log, 1);
    CHECK_EQ_INT(r.brightness, 42);
    CHECK_EQ_INT(r.autolock_min, 15);
    CHECK_EQ_INT(r.network, MW_NET_STAGENET);
    CHECK_EQ_INT(r.touch_calibrated, 1);
    for (int i = 0; i < 6; i++) CHECK_EQ_INT(r.touch_calib[i], -1000 * (i + 1));

    // Out-of-range brightness is refused.
    s.brightness = 200;
    CHECK_EQ_INT(mw_settings_save(&s), MW_ERR_RANGE);
}

MW_TEST(test_settings_bad_blob_falls_back_to_defaults)
{
    mw_settings_t s;
    // A blob from a "future" firmware version must not be interpreted.
    extern mw_err_t mw_store_blob_write(const char* key, const void* data, size_t len);
    uint8_t bogus[40];
    memset(bogus, 0xa5, sizeof bogus);
    bogus[0] = 'M'; bogus[1] = 'W'; bogus[2] = 'S'; bogus[3] = 'T';
    bogus[4] = 99;   // unknown version

    mw_host_store_set_dir(STORE_DIR);
    mw_host_store_reset();
    mw_settings_test_set_display(0, 128, 64);
    CHECK_EQ_INT(mw_store_blob_write("settings", bogus, sizeof bogus), MW_OK);
    CHECK_EQ_INT(mw_settings_load(&s), MW_OK);
    CHECK_EQ_INT(s.version, 2);

    // A v1 blob (36 bytes, usb_mode at [6]) from the previous firmware is
    // rejected on length and version alike and falls back to defaults.
    bogus[4] = 1;
    CHECK_EQ_INT(mw_store_blob_write("settings", bogus, 36), MW_OK);
    CHECK_EQ_INT(mw_settings_load(&s), MW_OK);
    CHECK_EQ_INT(s.kb_layout, KB_LAYOUT_QWERTY);
    CHECK_EQ_INT(s.keyboard, KEYBOARD_SCROLL);
    CHECK_EQ_INT(s.autolock_min, MW_AUTOLOCK_DEFAULT_MIN);

    // Truncated blob -> defaults as well.
    CHECK_EQ_INT(mw_store_blob_write("settings", bogus, 4), MW_OK);
    CHECK_EQ_INT(mw_settings_load(&s), MW_OK);
    CHECK_EQ_INT(s.autolock_min, MW_AUTOLOCK_DEFAULT_MIN);
}

// v5: the touch calibration geometry tag lives in the reserved bytes 37..39
// of the v2 blob - no version or length change.
MW_TEST(test_settings_touch_cal_tag)
{
    extern mw_err_t mw_store_blob_write(const char* key, const void* data, size_t len);
    extern mw_err_t mw_store_blob_read(const char* key, void* out, size_t cap, size_t* len_out);
    mw_settings_t s, r;
    uint8_t b[64];
    size_t  len = 0;

    mw_host_store_set_dir(STORE_DIR);
    mw_host_store_reset();
    mw_settings_test_set_display(1, 320, 240);

    CHECK_EQ_INT(mw_settings_load(&s), MW_OK);
    CHECK_EQ_INT(s.touch_cal_tag[0], 0);
    CHECK_EQ_INT(s.touch_cal_tag[1], 0);
    CHECK_EQ_INT(s.touch_cal_tag[2], 0);

    s.touch_calibrated = true;
    for (int i = 0; i < 6; i++) s.touch_calib[i] = 7 * (i + 1);
    s.touch_cal_tag[0] = 0x85;
    s.touch_cal_tag[1] = 40;
    s.touch_cal_tag[2] = 30;
    s.network = MW_NET_TESTNET;
    CHECK_EQ_INT(mw_settings_save(&s), MW_OK);

    CHECK_EQ_INT(mw_store_blob_read("settings", b, sizeof b, &len), MW_OK);
    CHECK_EQ_INT((int)len, 40);
    CHECK_EQ_INT(b[4], 2);                    // still version 2
    CHECK_EQ_INT(b[37], 0x85);
    CHECK_EQ_INT(b[38], 40);
    CHECK_EQ_INT(b[39], 30);

    CHECK_EQ_INT(mw_settings_load(&r), MW_OK);
    CHECK_EQ_MEM(r.touch_cal_tag, s.touch_cal_tag, 3);
    CHECK_EQ_INT(r.touch_calibrated, 1);
    for (int i = 0; i < 6; i++) CHECK_EQ_INT(r.touch_calib[i], 7 * (i + 1));

    // A record written before the tag existed (bytes 37..39 zero) loads
    // every other field unchanged, network included.
    memset(b, 0, sizeof b);
    b[0] = 'M'; b[1] = 'W'; b[2] = 'S'; b[3] = 'T'; b[4] = 2;
    b[5] = (uint8_t)KEYBOARD_SCROLL;
    b[6] = (uint8_t)KB_LAYOUT_ABC;
    b[7] = 55;
    b[8] = 10; b[9] = 0;                      // autolock 10 min
    b[10] = 1;                                // calibrated
    b[11] = (uint8_t)MW_NET_STAGENET;
    for (int i = 0; i < 6; i++) b[12 + 4 * i] = (uint8_t)(i + 1);
    b[36] = 1;                                // debug log
    CHECK_EQ_INT(mw_store_blob_write("settings", b, 40), MW_OK);
    memset(&r, 0xee, sizeof r);
    CHECK_EQ_INT(mw_settings_load(&r), MW_OK);
    CHECK_EQ_INT(r.keyboard, KEYBOARD_SCROLL);
    CHECK_EQ_INT(r.kb_layout, KB_LAYOUT_ABC);
    CHECK_EQ_INT(r.brightness, 55);
    CHECK_EQ_INT(r.autolock_min, 10);
    CHECK_EQ_INT(r.touch_calibrated, 1);
    CHECK_EQ_INT(r.network, MW_NET_STAGENET);
    CHECK_EQ_INT(r.debug_log, 1);
    for (int i = 0; i < 6; i++) CHECK_EQ_INT(r.touch_calib[i], i + 1);
    CHECK_EQ_INT(r.touch_cal_tag[0], 0);
    CHECK_EQ_INT(r.touch_cal_tag[1], 0);
    CHECK_EQ_INT(r.touch_cal_tag[2], 0);
}

int main(void)
{
    mw_random_init();
    mw_host_store_set_dir(STORE_DIR);

    RUN_TEST(test_aes256_block_fips197);
    RUN_TEST(test_aes_gcm_nist_vectors);
    RUN_TEST(test_aes_gcm_inplace_and_long);

    RUN_TEST(test_seal_unseal_roundtrip);
    RUN_TEST(test_seal_requires_provisioned_key);

    RUN_TEST(test_wallet_create_and_read_back);
    RUN_TEST(test_wallet_persistence_across_reload);
    RUN_TEST(test_wallet_polyseed_context_roundtrip);
    RUN_TEST(test_wallet_polyseed_birthday_survives_storage);
    RUN_TEST(test_wallet_polyseed_v1_record_refused);
    RUN_TEST(test_wallet_name_rules);
    RUN_TEST(test_wallet_max_wallets);
    RUN_TEST(test_wallet_set_active);
    RUN_TEST(test_wallet_secure_delete);
    RUN_TEST(test_wallet_id_not_reused_after_delete);
    RUN_TEST(test_wallet_tampered_record_fails_closed);
    RUN_TEST(test_wallet_load_keys);
    RUN_TEST(test_wallet_create_from_keys_full);
    RUN_TEST(test_wallet_create_from_keys_mismatch_rejected);
    RUN_TEST(test_wallet_view_only_requires_public_spend_key);
    RUN_TEST(test_wallet_view_only_roundtrip);
    RUN_TEST(test_wallet_hidden_flag_persists);

    RUN_TEST(test_settings_default_keyboard_auto_rule);
    RUN_TEST(test_settings_persist_and_version);
    RUN_TEST(test_settings_bad_blob_falls_back_to_defaults);
    RUN_TEST(test_settings_touch_cal_tag);

    mw_host_store_reset();
    return mw_test_summary();
}
