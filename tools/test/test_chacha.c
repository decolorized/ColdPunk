// Monero's ChaCha20 (8-byte IV, 64-bit counter) and the CryptoNight slow hash
// used by generate_chacha_key.
#include "test_framework.h"
#include "crypto/chacha.h"
#include "crypto/memzero.h"

#include <string.h>

static void hexbuf(const char* h, uint8_t* out, size_t cap) {
    (void)mw_test_hex(h, out, cap);
}

// ---------------------------------------------------------------------------
// ChaCha20
// ---------------------------------------------------------------------------

// RFC 8439 uses a 32-bit counter plus a 96-bit nonce; Monero uses a 64-bit
// counter plus a 64-bit nonce. With an all-zero key, nonce and counter the two
// layouts coincide, so RFC 8439 test vector #1 applies directly. The remaining
// vectors below were produced with OpenSSL's ChaCha20 by mapping Monero's
// (counter = 0, iv) onto OpenSSL's 16-byte IV as 00000000 00000000 || iv.
MW_TEST(test_chacha20_keystream_vectors) {
    mw_chacha_key key;
    mw_chacha_iv  iv;
    uint8_t       zeros[128], out[128], want[128];

    memset(zeros, 0, sizeof(zeros));

    // Vector 1: all-zero key and nonce (RFC 8439 A.1 #1, counter 0).
    memset(&key, 0, sizeof(key));
    memset(&iv, 0, sizeof(iv));
    mw_chacha20(zeros, 64, &key, &iv, out);
    hexbuf("76b8e0ada0f13d90405d6ae55386bd28bdd219b8a08ded1aa836efcc8b770dc7"
           "da41597c5157488d7724e03fb8d84a376a43b8f41518a11cc387b669b2ee6586",
           want, 64);
    CHECK_EQ_MEM(out, want, 64);

    // Vector 2: key = 00..1f, iv = 00 00 00 4a 00 00 00 00, two blocks. This
    // also proves the 64-bit counter increments correctly between blocks.
    for (int i = 0; i < 32; ++i) { key.data[i] = (uint8_t)i; }
    memset(&iv, 0, sizeof(iv));
    iv.data[3] = 0x4a;
    mw_chacha20(zeros, 128, &key, &iv, out);
    hexbuf("af051e40bba0354981329a806a140eafd258a22a6dcb4bb9f6569cb3efe2deaf"
           "837bd87ca20b5ba12081a306af0eb35c41a239d20dfc74c81771560d9c9c1e4b"
           "224f51f3401bd9e12fde276fb8631ded8c131f823d2c06e27e4fcaec9ef3cf78"
           "8a3b0aa372600a92b57974cded2b9334794cba40c63e34cdea212c4cf07d41b7",
           want, 128);
    CHECK_EQ_MEM(out, want, 128);
}

MW_TEST(test_chacha20_roundtrip_and_partial_blocks) {
    mw_chacha_key key;
    mw_chacha_iv  iv;
    uint8_t       plain[200], cipher[200], back[200];

    for (int i = 0; i < 32; ++i) { key.data[i] = (uint8_t)(i * 7 + 1); }
    for (int i = 0; i < 8;  ++i) { iv.data[i]  = (uint8_t)(i * 11 + 3); }
    for (size_t i = 0; i < sizeof(plain); ++i) { plain[i] = (uint8_t)(i * 3 + 5); }

    // Encryption and decryption are the same operation.
    mw_chacha20(plain, sizeof(plain), &key, &iv, cipher);
    CHECK(memcmp(plain, cipher, sizeof(plain)) != 0);
    mw_chacha20(cipher, sizeof(cipher), &key, &iv, back);
    CHECK_EQ_MEM(back, plain, sizeof(plain));

    // Any prefix length must produce the same bytes as the full-length call.
    static const size_t lens[] = { 1, 7, 63, 64, 65, 127, 128, 129, 199 };
    for (size_t l = 0; l < sizeof(lens) / sizeof(lens[0]); ++l) {
        uint8_t part[200];
        mw_chacha20(plain, lens[l], &key, &iv, part);
        CHECK_EQ_MEM(part, cipher, lens[l]);
    }

    // Zero length must be a no-op.
    uint8_t canary = 0xa5;
    mw_chacha20(plain, 0, &key, &iv, &canary);
    CHECK_EQ_INT(canary, 0xa5);

    // In-place operation must work.
    memcpy(back, plain, sizeof(plain));
    mw_chacha20(back, sizeof(back), &key, &iv, back);
    CHECK_EQ_MEM(back, cipher, sizeof(cipher));
}

MW_TEST(test_chacha20_key_iv_sensitivity) {
    mw_chacha_key k1, k2;
    mw_chacha_iv  i1, i2;
    uint8_t       zeros[64], a[64], b[64];

    memset(zeros, 0, sizeof(zeros));
    memset(&k1, 0x11, sizeof(k1));
    k2 = k1;
    k2.data[31] ^= 0x01;
    memset(&i1, 0x22, sizeof(i1));
    i2 = i1;
    i2.data[7] ^= 0x01;

    mw_chacha20(zeros, 64, &k1, &i1, a);
    mw_chacha20(zeros, 64, &k2, &i1, b);
    CHECK(memcmp(a, b, 64) != 0);

    mw_chacha20(zeros, 64, &k1, &i2, b);
    CHECK(memcmp(a, b, 64) != 0);
}

// ---------------------------------------------------------------------------
// CryptoNight (variant 0)
// ---------------------------------------------------------------------------

MW_TEST(test_cn_slow_hash_vectors) {
    uint8_t got[32], want[32];

    CHECK_EQ_INT(mw_cn_slow_hash_init(), 0);

    // The canonical CryptoNight v0 vector.
    const char* t = "This is a test";
    CHECK_EQ_INT(mw_cn_slow_hash(t, strlen(t), got), 0);
    hexbuf("a084f01d1437a09c6985401b60d43554ae105802c5f5d8a9b3253649c0be6605", want, 32);
    CHECK_EQ_MEM(got, want, 32);

    // Monero tests/hash/tests-slow.txt. Between them these exercise all four
    // finalizers (Blake / Groestl / JH / Skein).
    struct { const char* in_hex; const char* out_hex; } v[] = {
        { "6465206f6d6e69627573206475626974616e64756d",
          "2f8e3df40bd11f9ac90c743ca8e32bb391da4fb98612aa3b6cdc639ee00b31f5" },
        { "6162756e64616e732063617574656c61206e6f6e206e6f636574",
          "722fa8ccd594d40e4a41f3822734304c8d5eff7e1b528408e2229da38ba553c4" },
        { "63617665617420656d70746f72",
          "bbec2cacf69866a8e740380fe7b818fc78f8571221742d729d9d02d7f8989b87" },
        { "6578206e6968696c6f206e6968696c20666974",
          "b1257de4efc5ce28c6b40ceb1c6c8f812a64634eb3e81c5220bee9b2b76a6f05" }
    };
    for (size_t i = 0; i < sizeof(v) / sizeof(v[0]); ++i) {
        uint8_t in[64];
        size_t  n = mw_test_hex(v[i].in_hex, in, sizeof(in));
        CHECK_EQ_INT(mw_cn_slow_hash(in, n, got), 0);
        hexbuf(v[i].out_hex, want, 32);
        CHECK_EQ_MEM(got, want, 32);
    }

    // The empty input must also work and be deterministic.
    uint8_t e1[32], e2[32];
    CHECK_EQ_INT(mw_cn_slow_hash("", 0, e1), 0);
    CHECK_EQ_INT(mw_cn_slow_hash("", 0, e2), 0);
    CHECK_EQ_MEM(e1, e2, 32);
    CHECK(!mw_ct_is_zero(e1, 32));

    mw_cn_slow_hash_free();
}

MW_TEST(test_cn_slow_hash_without_preinit) {
    // Without an explicit init the scratchpad is allocated on demand and
    // released afterwards; the answer must be identical.
    uint8_t got[32], want[32];
    const char* t = "This is a test";
    CHECK_EQ_INT(mw_cn_slow_hash(t, strlen(t), got), 0);
    hexbuf("a084f01d1437a09c6985401b60d43554ae105802c5f5d8a9b3253649c0be6605", want, 32);
    CHECK_EQ_MEM(got, want, 32);

    // Repeated init/free must be idempotent.
    CHECK_EQ_INT(mw_cn_slow_hash_init(), 0);
    CHECK_EQ_INT(mw_cn_slow_hash_init(), 0);
    mw_cn_slow_hash_free();
    mw_cn_slow_hash_free();
}

MW_TEST(test_generate_chacha_key) {
    mw_chacha_key k1, k2;
    uint8_t       expect[32];
    const char*   material = "This is a test";

    // kdf_rounds == 1 is plain cn_slow_hash over the key material.
    mw_generate_chacha_key(material, strlen(material), &k1, 1);
    hexbuf("a084f01d1437a09c6985401b60d43554ae105802c5f5d8a9b3253649c0be6605", expect, 32);
    CHECK_EQ_MEM(k1.data, expect, 32);

    // 0 rounds is treated as 1 (Monero never passes 0).
    mw_generate_chacha_key(material, strlen(material), &k2, 0);
    CHECK_EQ_MEM(k2.data, k1.data, 32);

    // Two rounds must equal cn_slow_hash applied to the first result.
    uint8_t second[32];
    CHECK_EQ_INT(mw_cn_slow_hash(k1.data, 32, second), 0);
    mw_generate_chacha_key(material, strlen(material), &k2, 2);
    CHECK_EQ_MEM(k2.data, second, 32);

    // Different material gives a different key.
    mw_generate_chacha_key("This is a tesT", 14, &k2, 1);
    CHECK(memcmp(k1.data, k2.data, 32) != 0);
}

MW_TEST(test_generate_chacha_key_then_encrypt) {
    // End-to-end: derive a key the way Monero does, then round-trip a buffer.
    mw_chacha_key key;
    mw_chacha_iv  iv;
    uint8_t       plain[96], cipher[96], back[96];

    mw_generate_chacha_key("view key material", 17, &key, 1);
    for (int i = 0; i < 8; ++i) { iv.data[i] = (uint8_t)(0xf0 + i); }
    for (size_t i = 0; i < sizeof(plain); ++i) { plain[i] = (uint8_t)(i ^ 0x5a); }

    mw_chacha20(plain, sizeof(plain), &key, &iv, cipher);
    mw_chacha20(cipher, sizeof(cipher), &key, &iv, back);
    CHECK_EQ_MEM(back, plain, sizeof(plain));
    CHECK(memcmp(cipher, plain, sizeof(plain)) != 0);
}

int main(void) {
    printf("== test_chacha ==\n");
    RUN_TEST(test_chacha20_keystream_vectors);
    RUN_TEST(test_chacha20_roundtrip_and_partial_blocks);
    RUN_TEST(test_chacha20_key_iv_sensitivity);
    RUN_TEST(test_cn_slow_hash_vectors);
    RUN_TEST(test_cn_slow_hash_without_preinit);
    RUN_TEST(test_generate_chacha_key);
    RUN_TEST(test_generate_chacha_key_then_encrypt);
    return mw_test_summary();
}
