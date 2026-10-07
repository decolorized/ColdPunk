// Hash primitives: Keccak-256 (Monero cn_fast_hash), SHA-256/512, HMAC,
// PBKDF2 and CRC32.
#include "test_framework.h"
#include "crypto/hash.h"
#include "crypto/memzero.h"

#include <string.h>

static void hex(const char* h, uint8_t* out, size_t cap) {
    size_t n = mw_test_hex(h, out, cap);
    (void)n;
}

// ---------------------------------------------------------------------------
MW_TEST(test_keccak256_vectors) {
    uint8_t got[32], want[32];

    // The canonical Monero vector: keccak256("") (ORIGINAL padding, not SHA3).
    mw_keccak256((const uint8_t*)"", 0, got);
    hex("c5d2460186f7233c927e7db2dcc703c0e500b653ca82273b7bfad8045d85a470", want, 32);
    CHECK_EQ_MEM(got, want, 32);

    mw_keccak256((const uint8_t*)"abc", 3, got);
    hex("4e03657aea45a94fc7d47ba826c8d667c0d1e6e33a64a036ec44f58fa12d6c45", want, 32);
    CHECK_EQ_MEM(got, want, 32);

    const char* fox = "The quick brown fox jumps over the lazy dog";
    mw_keccak256((const uint8_t*)fox, strlen(fox), got);
    hex("4d741b6f1eb29cb2a9b9911c82f56fa8d73b04959d3d9d222895df6c0b28aa15", want, 32);
    CHECK_EQ_MEM(got, want, 32);

    // Exactly one rate block (136 bytes) plus a multi-block message.
    uint8_t big[200];
    memset(big, 0x61, sizeof(big));
    mw_keccak256(big, 200, got);
    hex("96ea54061def936c4be90b518992fdc6f12f535068a256229aca54267b4d084d", want, 32);
    CHECK_EQ_MEM(got, want, 32);

    // mw_cn_fast_hash must be the same function.
    uint8_t alias[32];
    mw_cn_fast_hash((const uint8_t*)"abc", 3, alias);
    mw_keccak256((const uint8_t*)"abc", 3, got);
    CHECK_EQ_MEM(alias, got, 32);
}

MW_TEST(test_keccak_streaming_matches_oneshot) {
    uint8_t data[512];
    for (size_t i = 0; i < sizeof(data); ++i) { data[i] = (uint8_t)(i * 31 + 7); }

    // Split the same message at every plausible boundary around the rate.
    static const size_t splits[] = { 1, 64, 135, 136, 137, 271, 272, 400 };
    uint8_t one[32], inc[32];
    mw_keccak256(data, sizeof(data), one);

    for (size_t s = 0; s < sizeof(splits) / sizeof(splits[0]); ++s) {
        mw_keccak_ctx ctx;
        mw_keccak_init(&ctx);
        mw_keccak_update(&ctx, data, splits[s]);
        mw_keccak_update(&ctx, data + splits[s], sizeof(data) - splits[s]);
        mw_keccak_final(&ctx, inc);
        CHECK_EQ_MEM(inc, one, 32);
    }
}

MW_TEST(test_keccak_xof) {
    uint8_t out[300], head[32];

    // The first 32 bytes of the XOF must equal keccak256 of the same input.
    mw_keccak_xof((const uint8_t*)"abc", 3, out, sizeof(out));
    mw_keccak256((const uint8_t*)"abc", 3, head);
    CHECK_EQ_MEM(out, head, 32);

    // Different lengths must agree on their common prefix.
    uint8_t shorter[64];
    mw_keccak_xof((const uint8_t*)"abc", 3, shorter, sizeof(shorter));
    CHECK_EQ_MEM(out, shorter, sizeof(shorter));

    // The tail past the first rate block must not be all zeros.
    int nonzero = 0;
    for (size_t i = 136; i < sizeof(out); ++i) { nonzero |= out[i]; }
    CHECK(nonzero != 0);
}

// ---------------------------------------------------------------------------
MW_TEST(test_sha256_nist_vectors) {
    uint8_t got[32], want[32];

    mw_sha256((const uint8_t*)"abc", 3, got);
    hex("ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad", want, 32);
    CHECK_EQ_MEM(got, want, 32);

    const char* m2 = "abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq";
    mw_sha256((const uint8_t*)m2, strlen(m2), got);
    hex("248d6a61d20638b8e5c026930c3e6039a33ce45964ff2167f6ecedd419db06c1", want, 32);
    CHECK_EQ_MEM(got, want, 32);

    mw_sha256((const uint8_t*)"", 0, got);
    hex("e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855", want, 32);
    CHECK_EQ_MEM(got, want, 32);

    // One million 'a' - streamed so the test stays allocation free.
    {
        mw_sha256_ctx ctx;
        uint8_t chunk[1000];
        memset(chunk, 'a', sizeof(chunk));
        mw_sha256_init(&ctx);
        for (int i = 0; i < 1000; ++i) { mw_sha256_update(&ctx, chunk, sizeof(chunk)); }
        mw_sha256_final(&ctx, got);
        hex("cdc76e5c9914fb9281a1c7e284d73e67f1809a48a497200e046d39ccc7112cd0", want, 32);
        CHECK_EQ_MEM(got, want, 32);
    }
}

MW_TEST(test_sha512_nist_vectors) {
    uint8_t got[64], want[64];

    mw_sha512((const uint8_t*)"abc", 3, got);
    hex("ddaf35a193617abacc417349ae20413112e6fa4e89a97ea20a9eeee64b55d39a"
        "2192992a274fc1a836ba3c23a3feebbd454d4423643ce80e2a9ac94fa54ca49f", want, 64);
    CHECK_EQ_MEM(got, want, 64);

    const char* m2 = "abcdefghbcdefghicdefghijdefghijkefghijklfghijklmghijklmn"
                     "hijklmnoijklmnopjklmnopqklmnopqrlmnopqrsmnopqrstnopqrstu";
    mw_sha512((const uint8_t*)m2, strlen(m2), got);
    hex("8e959b75dae313da8cf4f72814fc143f8f7779c6eb9f7fa17299aeadb6889018"
        "501d289e4900f7e4331b99dec4b5433ac7d329eeb6dd26545e96e55b874be909", want, 64);
    CHECK_EQ_MEM(got, want, 64);

    mw_sha512((const uint8_t*)"", 0, got);
    hex("cf83e1357eefb8bdf1542850d66d8007d620e4050b5715dc83f4a921d36ce9ce"
        "47d0d13c5d85f2b0ff8318d2877eec2f63b931bd47417a81a538327af927da3e", want, 64);
    CHECK_EQ_MEM(got, want, 64);
}

MW_TEST(test_sha_streaming_matches_oneshot) {
    uint8_t data[300];
    for (size_t i = 0; i < sizeof(data); ++i) { data[i] = (uint8_t)(i * 13 + 5); }

    static const size_t splits[] = { 1, 55, 56, 63, 64, 65, 111, 112, 127, 128, 200 };
    for (size_t s = 0; s < sizeof(splits) / sizeof(splits[0]); ++s) {
        uint8_t a[64], b[64];
        {
            mw_sha256_ctx c1, c2;
            mw_sha256_init(&c1);
            mw_sha256_update(&c1, data, sizeof(data));
            mw_sha256_final(&c1, a);
            mw_sha256_init(&c2);
            mw_sha256_update(&c2, data, splits[s]);
            mw_sha256_update(&c2, data + splits[s], sizeof(data) - splits[s]);
            mw_sha256_final(&c2, b);
            CHECK_EQ_MEM(a, b, 32);
        }
        {
            mw_sha512_ctx c1, c2;
            mw_sha512_init(&c1);
            mw_sha512_update(&c1, data, sizeof(data));
            mw_sha512_final(&c1, a);
            mw_sha512_init(&c2);
            mw_sha512_update(&c2, data, splits[s]);
            mw_sha512_update(&c2, data + splits[s], sizeof(data) - splits[s]);
            mw_sha512_final(&c2, b);
            CHECK_EQ_MEM(a, b, 64);
        }
    }
}

// ---------------------------------------------------------------------------
// RFC 4231 HMAC test cases.
MW_TEST(test_hmac_rfc4231) {
    uint8_t key[131], msg[153], got[64], want[64];

    // Case 1
    memset(key, 0x0b, 20);
    mw_hmac_sha256(key, 20, (const uint8_t*)"Hi There", 8, got);
    hex("b0344c61d8db38535ca8afceaf0bf12b881dc200c9833da726e9376c2e32cff7", want, 32);
    CHECK_EQ_MEM(got, want, 32);
    mw_hmac_sha512(key, 20, (const uint8_t*)"Hi There", 8, got);
    hex("87aa7cdea5ef619d4ff0b4241a1d6cb02379f4e2ce4ec2787ad0b30545e17cde"
        "daa833b7d6b8a702038b274eaea3f4e4be9d914eeb61f1702e696c203a126854", want, 64);
    CHECK_EQ_MEM(got, want, 64);

    // Case 2 (short key)
    mw_hmac_sha256((const uint8_t*)"Jefe", 4,
                   (const uint8_t*)"what do ya want for nothing?", 28, got);
    hex("5bdcc146bf60754e6a042426089575c75a003f089d2739839dec58b964ec3843", want, 32);
    CHECK_EQ_MEM(got, want, 32);
    mw_hmac_sha512((const uint8_t*)"Jefe", 4,
                   (const uint8_t*)"what do ya want for nothing?", 28, got);
    hex("164b7a7bfcf819e2e395fbe73b56e0a387bd64222e831fd610270cd7ea250554"
        "9758bf75c05a994a6d034f65f8f0e6fdcaeab1a34d4a6b4b636e070a38bce737", want, 64);
    CHECK_EQ_MEM(got, want, 64);

    // Case 3 (0xdd * 50)
    memset(key, 0xaa, 20);
    memset(msg, 0xdd, 50);
    mw_hmac_sha256(key, 20, msg, 50, got);
    hex("773ea91e36800e46854db8ebd09181a72959098b3ef8c122d9635514ced565fe", want, 32);
    CHECK_EQ_MEM(got, want, 32);

    // Case 6 (key longer than the block size)
    memset(key, 0xaa, 131);
    const char* m6 = "Test Using Larger Than Block-Size Key - Hash Key First";
    mw_hmac_sha256(key, 131, (const uint8_t*)m6, strlen(m6), got);
    hex("60e431591ee0b67f0d8a26aacbf5b77f8e0bc6213728c5140546040f0ee37f54", want, 32);
    CHECK_EQ_MEM(got, want, 32);
    mw_hmac_sha512(key, 131, (const uint8_t*)m6, strlen(m6), got);
    hex("80b24263c7c1a3ebb71493c1dd7be8b49b46d1f41b4aeec1121b013783f8f352"
        "6b56d037e05f2598bd0fd2215d6a1e5295e64f73f63f0aec8b915a985d786598", want, 64);
    CHECK_EQ_MEM(got, want, 64);
}

// PBKDF2-HMAC-SHA256: the RFC 6070 parameter set, re-derived for SHA-256
// (RFC 6070 itself only lists SHA-1 outputs; these are the widely published
// SHA-256 answers for the same inputs, also used by RFC 7914).
MW_TEST(test_pbkdf2_sha256_vectors) {
    uint8_t dk[40], want[40];

    mw_pbkdf2_sha256((const uint8_t*)"password", 8, (const uint8_t*)"salt", 4, 1, dk, 32);
    hex("120fb6cffcf8b32c43e7225256c4f837a86548c92ccc35480805987cb70be17b", want, 32);
    CHECK_EQ_MEM(dk, want, 32);

    mw_pbkdf2_sha256((const uint8_t*)"password", 8, (const uint8_t*)"salt", 4, 2, dk, 32);
    hex("ae4d0c95af6b46d32d0adff928f06dd02a303f8ef3c251dfd6e2d85a95474c43", want, 32);
    CHECK_EQ_MEM(dk, want, 32);

    mw_pbkdf2_sha256((const uint8_t*)"password", 8, (const uint8_t*)"salt", 4, 4096, dk, 32);
    hex("c5e478d59288c841aa530db6845c4c8d962893a001ce4e11a4963873aa98134a", want, 32);
    CHECK_EQ_MEM(dk, want, 32);

    // Multi-block output with long password and salt.
    mw_pbkdf2_sha256((const uint8_t*)"passwordPASSWORDpassword", 24,
                     (const uint8_t*)"saltSALTsaltSALTsaltSALTsaltSALTsalt", 36,
                     4096, dk, 40);
    hex("348c89dbcbd32b2f32d814b8116e84cf2b17347ebc1800181c4e2a1fb8dd53e1"
        "c635518c7dac47e9", want, 40);
    CHECK_EQ_MEM(dk, want, 40);
}

MW_TEST(test_pbkdf2_sha512_vectors) {
    uint8_t dk[64], want[64];

    mw_pbkdf2_sha512((const uint8_t*)"password", 8, (const uint8_t*)"salt", 4, 1, dk, 64);
    hex("867f70cf1ade02cff3752599a3a53dc4af34c7a669815ae5d513554e1c8cf252"
        "c02d470a285a0501bad999bfe943c08f050235d7d68b1da55e63f73b60a57fce", want, 64);
    CHECK_EQ_MEM(dk, want, 64);

    mw_pbkdf2_sha512((const uint8_t*)"password", 8, (const uint8_t*)"salt", 4, 4096, dk, 64);
    hex("d197b1b33db0143e018b12f3d1d1479e6cdebdcc97c5c0f87f6902e072f457b5"
        "143f30602641b3d55cd335988cb36b84376060ecd532e039b742a239434af2d5", want, 64);
    CHECK_EQ_MEM(dk, want, 64);

    // Partial-block output must be a prefix of the full-block output.
    uint8_t half[20];
    mw_pbkdf2_sha512((const uint8_t*)"password", 8, (const uint8_t*)"salt", 4, 1, half, 20);
    mw_pbkdf2_sha512((const uint8_t*)"password", 8, (const uint8_t*)"salt", 4, 1, dk, 64);
    CHECK_EQ_MEM(half, dk, 20);
}

MW_TEST(test_pbkdf2_long_salt) {
    // Exercises the heap fallback path for salts longer than the stack buffer.
    uint8_t salt[300], dk[32], dk2[32];
    for (size_t i = 0; i < sizeof(salt); ++i) { salt[i] = (uint8_t)i; }
    mw_pbkdf2_sha256((const uint8_t*)"pw", 2, salt, sizeof(salt), 3, dk, 32);
    mw_pbkdf2_sha256((const uint8_t*)"pw", 2, salt, sizeof(salt), 3, dk2, 32);
    CHECK_EQ_MEM(dk, dk2, 32);
    CHECK(!mw_ct_is_zero(dk, 32));
}

// ---------------------------------------------------------------------------
MW_TEST(test_crc32) {
    CHECK_EQ_INT(mw_crc32((const uint8_t*)"123456789", 9), 0xCBF43926u);
    CHECK_EQ_INT(mw_crc32((const uint8_t*)"", 0), 0u);
    CHECK_EQ_INT(mw_crc32((const uint8_t*)"a", 1), 0xE8B7BE43u);
    const char* fox = "The quick brown fox jumps over the lazy dog";
    CHECK_EQ_INT(mw_crc32((const uint8_t*)fox, strlen(fox)), 0x414FA339u);
}

// ---------------------------------------------------------------------------
MW_TEST(test_memzero_and_ct) {
    uint8_t a[32], b[32];
    for (int i = 0; i < 32; ++i) { a[i] = (uint8_t)i; b[i] = (uint8_t)i; }

    CHECK_EQ_INT(mw_ct_equal(a, b, 32), 1);
    b[31] ^= 0x01;
    CHECK_EQ_INT(mw_ct_equal(a, b, 32), 0);
    b[31] ^= 0x01;
    b[0] ^= 0x80;
    CHECK_EQ_INT(mw_ct_equal(a, b, 32), 0);

    CHECK_EQ_INT(mw_ct_is_zero(a, 32), 0);
    mw_memzero(a, sizeof(a));
    CHECK_EQ_INT(mw_ct_is_zero(a, 32), 1);
    for (int i = 0; i < 32; ++i) { CHECK_EQ_INT(a[i], 0); }

    // Zero length and NULL must be harmless.
    mw_memzero(NULL, 0);
    mw_memzero(a, 0);
    CHECK_EQ_INT(mw_ct_equal(a, a, 0), 1);
    CHECK_EQ_INT(mw_ct_is_zero(a, 0), 1);
}

int main(void) {
    printf("== test_hash ==\n");
    RUN_TEST(test_keccak256_vectors);
    RUN_TEST(test_keccak_streaming_matches_oneshot);
    RUN_TEST(test_keccak_xof);
    RUN_TEST(test_sha256_nist_vectors);
    RUN_TEST(test_sha512_nist_vectors);
    RUN_TEST(test_sha_streaming_matches_oneshot);
    RUN_TEST(test_hmac_rfc4231);
    RUN_TEST(test_pbkdf2_sha256_vectors);
    RUN_TEST(test_pbkdf2_sha512_vectors);
    RUN_TEST(test_pbkdf2_long_salt);
    RUN_TEST(test_crc32);
    RUN_TEST(test_memzero_and_ct);
    return mw_test_summary();
}
