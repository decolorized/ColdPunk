// QR Code generator (ISO/IEC 18004) - conformance and bounds tests.
//
// The golden matrices come from Nayuki's `qrcodegen`, the canonical reference
// implementation of the standard. Matching it byte for byte - including the
// automatic mask choice - means real scanners read what we put on the screen.
//
// SPDX-License-Identifier: MIT

#include "test_framework.h"
#include "transfer/qr_encode.h"

#include <string.h>
#include <stdio.h>
#include <stdlib.h>

// Golden vectors: matrices produced by Nayuki's `qrcodegen` reference
// implementation (ISO/IEC 18004), including its automatic mask choice.
// `crc` is CRC-32 over the '0'/'1' characters of the matrix, row major.
typedef struct {
    const char* payload;   // NULL: the payload is 'A' repeated `len` times
    uint16_t    len;
    uint8_t     ecc;       // 0 = L, 1 = M
    uint8_t     version;
    uint8_t     mask;
    uint32_t    crc;
} qr_golden_t;

static const qr_golden_t QR_GOLDEN[] = {
    { "HELLO WORLD", 11, 0, 1, 0, 0x004C9CE7u },
    { "HELLO WORLD", 11, 1, 1, 4, 0x2A6F7154u },
    { "ur:bytes/1-9/lpadascfadaxcywenbpljkhdcahkadaemejtswhhylkepmykhhtsytsnoyoyaxaedsuttydmmhhpktpmsrjtdkgslpgh", 105, 0, 5, 2, 0x9C38155Fu },
    { "ur:bytes/hdeymejtswhhylkepmykhhtsytsnoyoyaxaedsuttydmmhhpktpmsrjtgwdpfnsboxgwlbaawzuefywkdplrsrjynbvygabwjldapfcsdwkbrkch", 121, 0, 6, 2, 0x9EDA38A5u },
    { "4AdUndXHHZ6cfufTMvppY6JwXNouMBzSkbLYfpAV5Usx3skxNgYeYTRj5UzqtReoS44qo9mtmXCqY45DJ852K5Jv2684Rge", 95, 1, 6, 3, 0x9358EC5Fu },
    { NULL, 17, 0, 1, 7, 0x53152904u },
    { NULL, 14, 1, 1, 3, 0xECFF5213u },
    { NULL, 32, 0, 2, 0, 0xF66C9758u },
    { NULL, 26, 1, 2, 0, 0x179D3333u },
    { NULL, 53, 0, 3, 0, 0x19A4B17Cu },
    { NULL, 42, 1, 3, 0, 0xFBB62134u },
    { NULL, 78, 0, 4, 0, 0xA383B4A1u },
    { NULL, 62, 1, 4, 0, 0xAEA10700u },
    { NULL, 106, 0, 5, 0, 0x36184730u },
    { NULL, 84, 1, 5, 0, 0xE31B7184u },
    { NULL, 134, 0, 6, 0, 0xF2DAE55Bu },
    { NULL, 106, 1, 6, 0, 0xF2999815u },
    { NULL, 154, 0, 7, 3, 0x2BB53311u },
    { NULL, 122, 1, 7, 3, 0x56903AD5u },
    { NULL, 192, 0, 8, 3, 0x32EDDBB7u },
    { NULL, 152, 1, 8, 3, 0xA9EAFCE4u },
    { NULL, 230, 0, 9, 3, 0xA8D5F43Au },
    { NULL, 180, 1, 9, 3, 0xF9CF419Bu },
    { NULL, 271, 0, 10, 3, 0x9CB074E1u },
    { NULL, 213, 1, 10, 3, 0xC8D107F6u },
    { NULL, 321, 0, 11, 3, 0xC7A00AA9u },
    { NULL, 251, 1, 11, 3, 0x6CEDB4E0u },
    { NULL, 367, 0, 12, 3, 0xCDF0BC7Fu },
    { NULL, 287, 1, 12, 3, 0xACB17C3Au },
    { NULL, 425, 0, 13, 3, 0x8B269421u },
    { NULL, 331, 1, 13, 3, 0xDF839D7Eu },
    { NULL, 458, 0, 14, 0, 0xBCC689DFu },
    { NULL, 362, 1, 14, 0, 0x4CB5CDA3u },
    { NULL, 520, 0, 15, 0, 0x1F00C7E2u },
    { NULL, 412, 1, 15, 0, 0xFD0AD22Fu },
    { NULL, 586, 0, 16, 0, 0x55031AD1u },
    { NULL, 450, 1, 16, 0, 0xBABB6E1Fu },
    { NULL, 644, 0, 17, 1, 0x7BA404FBu },
    { NULL, 504, 1, 17, 0, 0x9ADDAFC9u },
    { NULL, 718, 0, 18, 1, 0xFEA2FB83u },
    { NULL, 560, 1, 18, 1, 0xCF7B611Eu },
    { NULL, 792, 0, 19, 0, 0x4FE0ACF1u },
    { NULL, 624, 1, 19, 1, 0xF38428FCu },
    { NULL, 858, 0, 20, 1, 0x7D14D364u },
    { NULL, 666, 1, 20, 1, 0xED581103u },
};

// Byte-mode capacity per (version, ecc) from ISO/IEC 18004 tables 7 and 13-22.
static const uint16_t QR_CAPACITY[2][21] = {
    { 0, 17, 32, 53, 78, 106, 134, 154, 192, 230, 271, 321, 367, 425, 458, 520, 586, 644, 718, 792, 858 },
    { 0, 14, 26, 42, 62, 84, 106, 122, 152, 180, 213, 251, 287, 331, 362, 412, 450, 504, 560, 624, 666 },
};

static const char* const QR_HELLO_L1[] = {
    "111111100101101111111",
    "100000100111001000001",
    "101110101101101011101",
    "101110100101001011101",
    "101110100010101011101",
    "100000100000101000001",
    "111111101010101111111",
    "000000001101100000000",
    "111011111111011000100",
    "100110000010001100010",
    "011111101010110111111",
    "111000010110000010010",
    "110110111010111110100",
    "000000001001010000110",
    "111111101011000110111",
    "100000101001100100001",
    "101110101001001010100",
    "101110100101001110110",
    "101110101000101010101",
    "100000101001000010010",
    "111111101001101100111",
};

// ---------------------------------------------------------------------------
// helpers
// ---------------------------------------------------------------------------

// CRC-32 (IEEE) over the '0'/'1' characters of the matrix, row major - the
// same reduction the golden generator used.
static uint32_t matrix_crc(const mw_qr_t* q) {
    uint32_t crc = 0xFFFFFFFFu;
    for (int y = 0; y < q->size; y++) {
        for (int x = 0; x < q->size; x++) {
            uint8_t c = mw_qr_get(q, x, y) ? (uint8_t)'1' : (uint8_t)'0';
            crc ^= c;
            for (int k = 0; k < 8; k++)
                crc = (crc >> 1) ^ (0xEDB88320u & (uint32_t)(-(int32_t)(crc & 1u)));
        }
    }
    return crc ^ 0xFFFFFFFFu;
}

static mw_qr_t g_qr;

// ---------------------------------------------------------------------------
// capacity tables
// ---------------------------------------------------------------------------

MW_TEST(test_capacity_table) {
    for (uint8_t v = 1; v <= MW_QR_MAX_VERSION; v++) {
        CHECK_EQ_INT(mw_qr_byte_capacity(v, MW_QR_ECC_L), QR_CAPACITY[0][v]);
        CHECK_EQ_INT(mw_qr_byte_capacity(v, MW_QR_ECC_M), QR_CAPACITY[1][v]);
    }
    CHECK_EQ_INT(mw_qr_byte_capacity(0, MW_QR_ECC_L), 0);
    CHECK_EQ_INT(mw_qr_byte_capacity(MW_QR_MAX_VERSION + 1, MW_QR_ECC_L), 0);
    CHECK_EQ_INT(mw_qr_byte_capacity(1, (mw_qr_ecc_t)9), 0);
}

MW_TEST(test_min_version) {
    CHECK_EQ_INT(mw_qr_min_version(1, MW_QR_ECC_L), 1);
    CHECK_EQ_INT(mw_qr_min_version(QR_CAPACITY[0][1], MW_QR_ECC_L), 1);
    CHECK_EQ_INT(mw_qr_min_version(QR_CAPACITY[0][1] + 1, MW_QR_ECC_L), 2);
    CHECK_EQ_INT(mw_qr_min_version(QR_CAPACITY[0][20], MW_QR_ECC_L), 20);
    CHECK_EQ_INT(mw_qr_min_version(QR_CAPACITY[0][20] + 1, MW_QR_ECC_L), 0);
    CHECK_EQ_INT(mw_qr_min_version(QR_CAPACITY[1][20] + 1, MW_QR_ECC_M), 0);
    // Every version boundary is exact.
    for (uint8_t v = 2; v <= MW_QR_MAX_VERSION; v++) {
        CHECK_EQ_INT(mw_qr_min_version(QR_CAPACITY[0][v - 1] + 1, MW_QR_ECC_L), v);
        CHECK_EQ_INT(mw_qr_min_version(QR_CAPACITY[1][v - 1] + 1, MW_QR_ECC_M), v);
    }
}

// ---------------------------------------------------------------------------
// golden matrices
// ---------------------------------------------------------------------------

MW_TEST(test_golden_matrices) {
    uint8_t* payload = (uint8_t*)malloc(1024);
    CHECK(payload != NULL);
    if (!payload) return;

    for (size_t i = 0; i < sizeof QR_GOLDEN / sizeof QR_GOLDEN[0]; i++) {
        const qr_golden_t* g = &QR_GOLDEN[i];
        const uint8_t* data;
        if (g->payload) {
            data = (const uint8_t*)g->payload;
            CHECK_EQ_INT(strlen(g->payload), g->len);
        } else {
            memset(payload, 'A', g->len);
            data = payload;
        }
        mw_err_t err = mw_qr_encode_version(data, g->len, (mw_qr_ecc_t)g->ecc,
                                            g->version, &g_qr);
        CHECK_EQ_INT(err, MW_OK);
        if (err != MW_OK) continue;
        CHECK_EQ_INT(g_qr.version, g->version);
        CHECK_EQ_INT(g_qr.size, 4 * g->version + 17);
        CHECK_EQ_INT(g_qr.mask, g->mask);
        CHECK_EQ_INT(matrix_crc(&g_qr), g->crc);

        // Auto-sizing must land on the same version for a full-capacity payload.
        if (!g->payload && g->len == QR_CAPACITY[g->ecc][g->version]) {
            CHECK_EQ_INT(mw_qr_encode(data, g->len, (mw_qr_ecc_t)g->ecc, &g_qr),
                         MW_OK);
            CHECK_EQ_INT(g_qr.version, g->version);
            CHECK_EQ_INT(matrix_crc(&g_qr), g->crc);
        }
    }
    free(payload);
}

MW_TEST(test_golden_matrix_readable) {
    // The same v1-L code again, compared row by row so a regression prints
    // something a human can look at.
    CHECK_EQ_INT(mw_qr_encode_text("HELLO WORLD", MW_QR_ECC_L, &g_qr), MW_OK);
    CHECK_EQ_INT(g_qr.size, 21);
    for (int y = 0; y < 21; y++) {
        char row[22];
        for (int x = 0; x < 21; x++) row[x] = mw_qr_get(&g_qr, x, y) ? '1' : '0';
        row[21] = '\0';
        CHECK_EQ_STR(row, QR_HELLO_L1[y]);
    }
}

// ---------------------------------------------------------------------------
// structural invariants (independent of the golden data)
// ---------------------------------------------------------------------------

static void check_structure(const mw_qr_t* q) {
    const int n = q->size;
    CHECK_EQ_INT(n, 4 * q->version + 17);
    CHECK(q->mask < 8);

    // Three finder patterns, each 7x7 with a 1-module light separator.
    const int corners[3][2] = { { 0, 0 }, { n - 7, 0 }, { 0, n - 7 } };
    for (int c = 0; c < 3; c++) {
        int ox = corners[c][0], oy = corners[c][1];
        for (int dy = 0; dy < 7; dy++) {
            for (int dx = 0; dx < 7; dx++) {
                int d = (dx > 3 ? 6 - dx : dx);
                int e = (dy > 3 ? 6 - dy : dy);
                int ring = d < e ? d : e;
                bool want = (ring != 1);
                CHECK_EQ_INT(mw_qr_get(q, ox + dx, oy + dy), want);
            }
        }
    }

    // Timing patterns alternate, starting dark at index 6.
    for (int i = 8; i < n - 8; i++) {
        CHECK_EQ_INT(mw_qr_get(q, i, 6), i % 2 == 0);
        CHECK_EQ_INT(mw_qr_get(q, 6, i), i % 2 == 0);
    }

    // The module at (8, n - 8) is always dark (clause 7.9.1).
    CHECK(mw_qr_get(q, 8, n - 8));

    // Reading outside the symbol is defined and light.
    CHECK(!mw_qr_get(q, -1, 0));
    CHECK(!mw_qr_get(q, 0, -1));
    CHECK(!mw_qr_get(q, n, 0));
    CHECK(!mw_qr_get(q, 0, n));
    CHECK(!mw_qr_get(NULL, 0, 0));

    // The symbol is never uniform, and the dark ratio stays sane - this is what
    // penalty rule 4 buys us.
    int dark = 0;
    for (int y = 0; y < n; y++)
        for (int x = 0; x < n; x++)
            if (mw_qr_get(q, x, y)) dark++;
    int total = n * n;
    CHECK(dark * 100 > total * 30);
    CHECK(dark * 100 < total * 70);
}

MW_TEST(test_structure_all_versions) {
    uint8_t* payload = (uint8_t*)malloc(1024);
    CHECK(payload != NULL);
    if (!payload) return;
    for (uint8_t v = 1; v <= MW_QR_MAX_VERSION; v++) {
        for (int e = 0; e < 2; e++) {
            size_t cap = QR_CAPACITY[e][v];
            size_t lens[3] = { 1, cap / 2 ? cap / 2 : 1, cap };
            for (int i = 0; i < 3; i++) {
                for (size_t k = 0; k < lens[i]; k++)
                    payload[k] = (uint8_t)('0' + (k % 43));
                CHECK_EQ_INT(mw_qr_encode_version(payload, lens[i],
                                                  (mw_qr_ecc_t)e, v, &g_qr),
                             MW_OK);
                check_structure(&g_qr);
            }
        }
    }
    free(payload);
}

// ---------------------------------------------------------------------------
// bounds and argument validation
// ---------------------------------------------------------------------------

MW_TEST(test_rejects_oversized) {
    uint8_t* payload = (uint8_t*)malloc(2048);
    CHECK(payload != NULL);
    if (!payload) return;
    memset(payload, 'A', 2048);

    for (uint8_t v = 1; v <= MW_QR_MAX_VERSION; v++) {
        for (int e = 0; e < 2; e++) {
            size_t cap = QR_CAPACITY[e][v];
            CHECK_EQ_INT(mw_qr_encode_version(payload, cap, (mw_qr_ecc_t)e, v,
                                              &g_qr), MW_OK);
            CHECK_EQ_INT(mw_qr_encode_version(payload, cap + 1, (mw_qr_ecc_t)e,
                                              v, &g_qr), MW_ERR_TOO_MANY);
        }
    }
    // Beyond version 20 there is nowhere to go.
    CHECK_EQ_INT(mw_qr_encode(payload, QR_CAPACITY[0][20] + 1, MW_QR_ECC_L,
                              &g_qr), MW_ERR_TOO_MANY);
    CHECK_EQ_INT(mw_qr_encode(payload, 2048, MW_QR_ECC_M, &g_qr),
                 MW_ERR_TOO_MANY);
    free(payload);
}

MW_TEST(test_argument_validation) {
    const uint8_t data[4] = { 1, 2, 3, 4 };
    CHECK_EQ_INT(mw_qr_encode(data, 4, MW_QR_ECC_L, NULL), MW_ERR_INVALID_ARG);
    CHECK_EQ_INT(mw_qr_encode_version(NULL, 4, MW_QR_ECC_L, 1, &g_qr),
                 MW_ERR_INVALID_ARG);
    CHECK_EQ_INT(mw_qr_encode_version(data, 4, (mw_qr_ecc_t)7, 1, &g_qr),
                 MW_ERR_INVALID_ARG);
    CHECK_EQ_INT(mw_qr_encode_version(data, 4, MW_QR_ECC_L, 0, &g_qr),
                 MW_ERR_INVALID_ARG);
    CHECK_EQ_INT(mw_qr_encode_version(data, 4, MW_QR_ECC_L,
                                      MW_QR_MAX_VERSION + 1, &g_qr),
                 MW_ERR_INVALID_ARG);
    CHECK_EQ_INT(mw_qr_encode_text(NULL, MW_QR_ECC_L, &g_qr),
                 MW_ERR_INVALID_ARG);

    // A zero-length payload is still a valid (if pointless) symbol.
    CHECK_EQ_INT(mw_qr_encode_text("", MW_QR_ECC_L, &g_qr), MW_OK);
    check_structure(&g_qr);
}

MW_TEST(test_no_write_past_bitmap) {
    // Encode the largest possible symbol into a guarded buffer and make sure
    // nothing outside mw_qr_t::modules moved.
    struct { mw_qr_t qr; uint8_t guard[64]; } g;
    memset(&g, 0xA5, sizeof g);
    uint8_t* payload = (uint8_t*)malloc(QR_CAPACITY[0][20]);
    CHECK(payload != NULL);
    if (!payload) return;
    memset(payload, 'Z', QR_CAPACITY[0][20]);
    CHECK_EQ_INT(mw_qr_encode_version(payload, QR_CAPACITY[0][20], MW_QR_ECC_L,
                                      20, &g.qr), MW_OK);
    for (size_t i = 0; i < sizeof g.guard; i++) CHECK_EQ_INT(g.guard[i], 0xA5);
    check_structure(&g.qr);
    free(payload);
}

MW_TEST(test_binary_payload) {
    // Byte mode must carry NUL bytes and high bytes unchanged; we can only
    // check structurally here, but the golden vectors above pin the encoding.
    uint8_t data[200];
    for (size_t i = 0; i < sizeof data; i++) data[i] = (uint8_t)(i * 13 + 7);
    data[0] = 0x00;
    data[1] = 0xFF;
    CHECK_EQ_INT(mw_qr_encode(data, sizeof data, MW_QR_ECC_M, &g_qr), MW_OK);
    check_structure(&g_qr);
    // Determinism: the same input always produces the same symbol.
    uint32_t a = matrix_crc(&g_qr);
    CHECK_EQ_INT(mw_qr_encode(data, sizeof data, MW_QR_ECC_M, &g_qr), MW_OK);
    CHECK_EQ_INT(matrix_crc(&g_qr), a);
}

MW_TEST(test_ur_frames) {
    // The shape the wallet actually puts on screen: an animated ur:bytes frame
    // at the TZ 3.7 fragment size fits comfortably inside a small version.
    static const char* const frames[] = {
        "ur:bytes/1-9/lpadascfadaxcywenbpljkhdcahkadaemejtswhhylkepmykhhtsytsn"
        "oyoyaxaedsuttydmmhhpktpmsrjtdkgslpgh",
        "ur:bytes/10-9/lpbkascfadaxcywenbpljkhdcahkadaemejtswhhylkepmykhhtsyts"
        "noyoyaxaedsuttydmmhhpktpmsrjtwdkiplzs",
    };
    for (size_t i = 0; i < 2; i++) {
        CHECK_EQ_INT(mw_qr_encode_text(frames[i], MW_QR_ECC_L, &g_qr), MW_OK);
        CHECK(g_qr.version <= 6);           // fits a 240x240 display at 3 px
        check_structure(&g_qr);
    }
    // A whole animated sequence must fit one fixed version so the module size
    // on screen never jumps mid-animation.
    uint8_t v = mw_qr_min_version(strlen(frames[0]), MW_QR_ECC_L);
    CHECK(v > 0);
    for (size_t i = 0; i < 2; i++)
        CHECK_EQ_INT(mw_qr_encode_version((const uint8_t*)frames[i],
                                          strlen(frames[i]), MW_QR_ECC_L, v,
                                          &g_qr), MW_OK);
}

int main(void) {
    printf("=== QR encoder (ISO/IEC 18004) ===\n");
    RUN_TEST(test_capacity_table);
    RUN_TEST(test_min_version);
    RUN_TEST(test_golden_matrices);
    RUN_TEST(test_golden_matrix_readable);
    RUN_TEST(test_structure_all_versions);
    RUN_TEST(test_rejects_oversized);
    RUN_TEST(test_argument_validation);
    RUN_TEST(test_no_write_past_bitmap);
    RUN_TEST(test_binary_payload);
    RUN_TEST(test_ur_frames);
    return mw_test_summary();
}
