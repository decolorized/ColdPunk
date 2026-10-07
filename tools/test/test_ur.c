// Uniform Resources (TZ 3.7) - conformance and hostile-input tests.
//
// The fixed vectors below are the official BCR-2020-005 / BCR-2020-012 test
// vectors taken from the Blockchain Commons `bc-ur` reference suite. Passing
// them means a real Feather / ANON / NERO can decode our animated QR frames and
// we can decode theirs, bit for bit.
//
// SPDX-License-Identifier: MIT

#include "test_framework.h"
#include "transfer/ur.h"

#include <stdlib.h>
#include <string.h>
#include <stdio.h>

// ---- internals exposed by ur.c for the host build -------------------------
void     mw_ur_test_xoshiro(const uint8_t* seed, size_t seed_len,
                            uint64_t* out, size_t n);
void     mw_ur_test_xoshiro_int(const uint8_t* seed, size_t seed_len,
                                uint64_t low, uint64_t high,
                                uint64_t* out, size_t n);
size_t   mw_ur_test_nominal_fragment_len(size_t message_len, size_t min_len,
                                         size_t max_len);
uint32_t mw_ur_test_choose_degree(uint32_t seq_len, const uint8_t* seed,
                                  size_t seed_len);
size_t   mw_ur_test_choose_fragments(uint32_t seq_num, uint32_t seq_len,
                                     uint32_t checksum, uint32_t* out,
                                     size_t out_cap);

static const char VEC_MSG50_HEX[] =
    "916ec65cf77cadf55cd7f9cda1a1030026ddd42e905b77adc36e4f2d3ccba44f7f04f2de"
    "44f42d84c374a0e149136f25b018"
    ;

static const char VEC_MSG256_HEX[] =
    "916ec65cf77cadf55cd7f9cda1a1030026ddd42e905b77adc36e4f2d3ccba44f7f04f2de"
    "44f42d84c374a0e149136f25b01852545961d55f7f7a8cde6d0e2ec43f3b2dcb644a2209"
    "e8c9e34af5c4747984a5e873c9cf5f965e25ee29039fdf8ca74f1c769fc07eb7ebaec46e"
    "0695aea6cbd60b3ec4bbff1b9ffe8a9e7240129377b9d3711ed38d412fbb4442256f1e6f"
    "595e0fc57fed451fb0a0101fb76b1fb1e1b88cfdfdaa946294a47de8fff173f021c0e6f6"
    "5b05c0a494e50791270a0050a73ae69b6725505a2ec8a5791457c9876dd34aadd192a53a"
    "a0dc66b556c0c215c7ceb8248b717c22951e65305b56a3706e3e86eb01c803bbf915d80e"
    "dcd64d4d"
    ;

static const char VEC_SINGLE_UR[] =
    "ur:bytes/hdeymejtswhhylkepmykhhtsytsnoyoyaxaedsuttydmmhhpktpmsrjtgwdpfns"
    "boxgwlbaawzuefywkdplrsrjynbvygabwjldapfcsdwkbrkch"
    ;

static const uint64_t VEC_RNG1[] = {
    42, 81, 85, 8, 82, 84, 76, 73, 70, 88, 2, 74, 40, 48, 77, 54,
    88, 7, 5, 88, 37, 25, 82, 13, 69, 59, 30, 39, 11, 82, 19, 99,
    45, 87, 30, 15, 32, 22, 89, 44, 92, 77, 29, 78, 4, 92, 44, 68,
    92, 69, 1, 42, 89, 50, 37, 84, 63, 34, 32, 3, 17, 62, 40, 98,
    82, 89, 24, 43, 85, 39, 15, 3, 99, 29, 20, 42, 27, 10, 85, 66,
    50, 35, 69, 70, 70, 74, 30, 13, 72, 54, 11, 5, 70, 55, 91, 52,
    10, 43, 43, 52,
};

static const uint64_t VEC_RNG3[] = {
    6, 5, 8, 4, 10, 5, 7, 10, 4, 9, 10, 9, 7, 7, 1, 1,
    2, 9, 9, 2, 6, 4, 5, 7, 8, 5, 4, 2, 3, 8, 7, 4,
    5, 1, 10, 9, 3, 10, 2, 6, 8, 5, 7, 9, 3, 1, 5, 2,
    7, 1, 4, 4, 4, 4, 9, 4, 5, 5, 6, 9, 5, 1, 2, 8,
    3, 3, 2, 8, 4, 3, 2, 1, 10, 8, 9, 3, 10, 8, 5, 5,
    6, 7, 10, 5, 8, 9, 4, 6, 4, 2, 10, 2, 1, 7, 9, 6,
    7, 4, 2, 5,
};

static const uint32_t VEC_DEGREE[] = {
    11, 3, 6, 5, 2, 1, 2, 11, 1, 3, 9, 10, 10, 4, 2, 1, 1, 2, 1, 1,
    5, 2, 4, 10, 3, 2, 1, 1, 3, 11, 2, 6, 2, 9, 9, 2, 6, 7, 2, 5,
    2, 4, 3, 1, 6, 11, 2, 11, 3, 1, 6, 3, 1, 4, 5, 3, 6, 1, 1, 3,
    1, 2, 2, 1, 4, 5, 1, 1, 9, 1, 1, 6, 4, 1, 5, 1, 2, 2, 3, 1,
    1, 5, 2, 6, 1, 7, 11, 1, 8, 1, 5, 1, 1, 2, 2, 6, 4, 10, 1, 2,
    5, 5, 5, 1, 1, 4, 1, 1, 1, 3, 5, 5, 5, 1, 4, 3, 3, 5, 1, 11,
    3, 2, 8, 1, 2, 1, 1, 4, 5, 2, 1, 1, 1, 5, 6, 11, 10, 7, 4, 7,
    1, 5, 3, 1, 1, 9, 1, 2, 5, 5, 2, 2, 3, 10, 1, 3, 2, 3, 3, 1,
    1, 2, 1, 3, 2, 2, 1, 3, 8, 4, 1, 11, 6, 3, 1, 1, 1, 1, 1, 3,
    1, 2, 1, 10, 1, 1, 8, 2, 7, 1, 2, 1, 9, 2, 10, 2, 1, 3, 4, 10,
};

static const uint8_t VEC_BW2_IN[] = {
    245, 215, 20, 198, 241, 235, 69, 59, 209, 205, 165, 18,
    150, 158, 116, 135, 229, 212, 19, 159, 17, 37, 239, 240,
    253, 11, 109, 191, 37, 242, 38, 120, 223, 41, 156, 189,
    242, 254, 147, 204, 66, 163, 216, 175, 191, 72, 169, 54,
    32, 60, 144, 230, 210, 137, 184, 197, 33, 113, 88, 14,
    157, 31, 177, 46, 1, 115, 205, 69, 225, 150, 65, 235,
    58, 144, 65, 240, 133, 69, 113, 247, 63, 53, 242, 165,
    160, 144, 26, 13, 79, 237, 133, 71, 82, 69, 254, 165,
    138, 41, 85, 24,
};
static const char VEC_BW2_MIN[] = "yktsbbswwnwmfefrttsnonbgmtnnjyltvwtybwnebydawswtzcbdjnrsdawzdsksurdtnsrywzzemusffwottppersfdptencxfnmhvatdldroskcljshdbantctpadmadjksnfevymtfpwmftmhfpwtlpfejsylfhecwzonnbmhcybtgwwelpflgmfezeonledtgocsfzhycypf";
static const uint8_t VEC_FRAGS[30][12] = {
    { 1, 0 },
    { 1, 1 },
    { 1, 2 },
    { 1, 3 },
    { 1, 4 },
    { 1, 5 },
    { 1, 6 },
    { 1, 7 },
    { 1, 8 },
    { 1, 9 },
    { 1, 10 },
    { 1, 9 },
    { 6, 2, 5, 6, 8, 9, 10 },
    { 1, 8 },
    { 2, 1, 5 },
    { 1, 1 },
    { 6, 0, 2, 4, 5, 8, 10 },
    { 1, 5 },
    { 1, 2 },
    { 1, 2 },
    { 8, 0, 1, 3, 4, 5, 7, 9, 10 },
    { 9, 0, 1, 2, 3, 5, 6, 8, 9, 10 },
    { 8, 0, 2, 4, 5, 7, 8, 9, 10 },
    { 2, 3, 5 },
    { 1, 4 },
    { 11, 0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10 },
    { 9, 0, 1, 3, 4, 5, 6, 7, 9, 10 },
    { 1, 6 },
    { 2, 5, 6 },
    { 1, 7 },
};
static const char* const VEC_PARTS_256_30[20] = {
    "ur:bytes/1-9/lpadascfadaxcywenbpljkhdcahkadaemejtswhhylkepmykhhtsytsnoyoyaxaedsuttydmmhhpktpmsrjtdkgslpgh",
    "ur:bytes/2-9/lpaoascfadaxcywenbpljkhdcagwdpfnsboxgwlbaawzuefywkdplrsrjynbvygabwjldapfcsgmghhkhstlrdcxaefz",
    "ur:bytes/3-9/lpaxascfadaxcywenbpljkhdcahelbknlkuejnbadmssfhfrdpsbiegecpasvssovlgeykssjykklronvsjksopdzmol",
    "ur:bytes/4-9/lpaaascfadaxcywenbpljkhdcasotkhemthydawydtaxneurlkosgwcekonertkbrlwmplssjtammdplolsbrdzcrtas",
    "ur:bytes/5-9/lpahascfadaxcywenbpljkhdcatbbdfmssrkzmcwnezelennjpfzbgmuktrhtejscktelgfpdlrkfyfwdajldejokbwf",
    "ur:bytes/6-9/lpamascfadaxcywenbpljkhdcackjlhkhybssklbwefectpfnbbectrljectpavyrolkzczcpkmwidmwoxkilghdsowp",
    "ur:bytes/7-9/lpatascfadaxcywenbpljkhdcavszmwnjkwtclrtvaynhpahrtoxmwvwatmedibkaegdosftvandiodagdhthtrlnnhy",
    "ur:bytes/8-9/lpayascfadaxcywenbpljkhdcadmsponkkbbhgsoltjntegepmttmoonftnbuoiyrehfrtsabzsttorodklubbuyaetk",
    "ur:bytes/9-9/lpasascfadaxcywenbpljkhdcajskecpmdckihdyhphfotjojtfmlnwmadspaxrkytbztpbauotbgtgtaeaevtgavtny",
    "ur:bytes/10-9/lpbkascfadaxcywenbpljkhdcahkadaemejtswhhylkepmykhhtsytsnoyoyaxaedsuttydmmhhpktpmsrjtwdkiplzs",
    "ur:bytes/11-9/lpbdascfadaxcywenbpljkhdcahelbknlkuejnbadmssfhfrdpsbiegecpasvssovlgeykssjykklronvsjkvetiiapk",
    "ur:bytes/12-9/lpbnascfadaxcywenbpljkhdcarllaluzmdmgstospeyiefmwejlwtpedamktksrvlcygmzemovovllarodtmtbnptrs",
    "ur:bytes/13-9/lpbtascfadaxcywenbpljkhdcamtkgtpknghchchyketwsvwgwfdhpgmgtylctotzopdrpayoschcmhplffziachrfgd",
    "ur:bytes/14-9/lpbaascfadaxcywenbpljkhdcapazewnvonnvdnsbyleynwtnsjkjndeoldydkbkdslgjkbbkortbelomueekgvstegt",
    "ur:bytes/15-9/lpbsascfadaxcywenbpljkhdcaynmhpddpzmversbdqdfyrehnqzlugmjzmnmtwmrouohtstgsbsahpawkditkckynwt",
    "ur:bytes/16-9/lpbeascfadaxcywenbpljkhdcawygekobamwtlihsnpalnsghenskkiynthdzotsimtojetprsttmukirlrsbtamjtpd",
    "ur:bytes/17-9/lpbyascfadaxcywenbpljkhdcamklgftaxykpewyrtqzhydntpnytyisincxmhtbceaykolduortotiaiaiafhiaoyce",
    "ur:bytes/18-9/lpbgascfadaxcywenbpljkhdcahkadaemejtswhhylkepmykhhtsytsnoyoyaxaedsuttydmmhhpktpmsrjtntwkbkwy",
    "ur:bytes/19-9/lpbwascfadaxcywenbpljkhdcadekicpaajootjzpsdrbalpeywllbdsnbinaerkurspbncxgslgftvtsrjtksplcpeo",
    "ur:bytes/20-9/lpbbascfadaxcywenbpljkhdcayapmrleeleaxpasfrtrdkncffwjyjzgyetdmlewtkpktgllepfrltataztksmhkbot",
};

// ---------------------------------------------------------------------------
// helpers
// ---------------------------------------------------------------------------

#define MAX_UR_STR 8192

static size_t unhex(const char* hex, uint8_t* out, size_t cap) {
    size_t n = strlen(hex) / 2;
    if (n > cap) n = cap;
    for (size_t i = 0; i < n; i++) {
        unsigned v = 0;
        sscanf(hex + 2 * i, "%2x", &v);
        out[i] = (uint8_t)v;
    }
    return n;
}

// Deterministic PRNG for the shuffle / fuzz drivers (not the UR one).
static uint32_t rnd_state = 0x12345678u;
static uint32_t rnd(void) {
    rnd_state ^= rnd_state << 13;
    rnd_state ^= rnd_state >> 17;
    rnd_state ^= rnd_state << 5;
    return rnd_state;
}

// ---------------------------------------------------------------------------
// CRC-32
// ---------------------------------------------------------------------------

MW_TEST(test_crc32) {
    CHECK_EQ_INT(mw_ur_crc32((const uint8_t*)"Hello, world!", 13), 0xEBE6C6E6u);
    CHECK_EQ_INT(mw_ur_crc32((const uint8_t*)"Wolf", 4), 0x598C84DCu);
    CHECK_EQ_INT(mw_ur_crc32((const uint8_t*)"", 0), 0u);
}

// ---------------------------------------------------------------------------
// Bytewords (BCR-2020-012)
// ---------------------------------------------------------------------------

MW_TEST(test_bytewords_known_vector) {
    const uint8_t in[] = { 0, 1, 2, 128, 255 };
    char out[64];
    size_t n = mw_bytewords_encode_minimal(in, sizeof in, out, sizeof out);
    CHECK_EQ_INT(n, 18);
    CHECK_EQ_STR(out, "aeadaolazmjendeoti");

    uint8_t back[64];
    size_t back_len = 0;
    CHECK_EQ_INT(mw_bytewords_decode_minimal("aeadaolazmjendeoti", back,
                                             sizeof back, &back_len), MW_OK);
    CHECK_EQ_INT(back_len, sizeof in);
    CHECK_EQ_MEM(back, in, sizeof in);

    // Upper case must decode identically (QR alphanumeric mode).
    CHECK_EQ_INT(mw_bytewords_decode_minimal("AEADAOLAZMJENDEOTI", back,
                                             sizeof back, &back_len), MW_OK);
    CHECK_EQ_INT(back_len, sizeof in);
    CHECK_EQ_MEM(back, in, sizeof in);

    // Corrupted CRC ("zo" instead of "zm", "wf" instead of "ti").
    CHECK_EQ_INT(mw_bytewords_decode_minimal("aeadaolazojendeowf", back,
                                             sizeof back, &back_len),
                 MW_ERR_CHECKSUM);
    // Too short / odd length / unknown pair.
    CHECK_EQ_INT(mw_bytewords_decode_minimal("wolf", back, sizeof back,
                                             &back_len), MW_ERR_FORMAT);
    CHECK_EQ_INT(mw_bytewords_decode_minimal("", back, sizeof back,
                                             &back_len), MW_ERR_FORMAT);
    CHECK_EQ_INT(mw_bytewords_decode_minimal("aeadaolazmjendeot", back,
                                             sizeof back, &back_len),
                 MW_ERR_FORMAT);
    CHECK_EQ_INT(mw_bytewords_decode_minimal("zzzzzzzzzzzzzzzzzz", back,
                                             sizeof back, &back_len),
                 MW_ERR_FORMAT);
    CHECK_EQ_INT(mw_bytewords_decode_minimal("ae..ao..zm..nd..ot..", back,
                                             sizeof back, &back_len),
                 MW_ERR_FORMAT);
}

MW_TEST(test_bytewords_100_bytes) {
    char out[512];
    size_t n = mw_bytewords_encode_minimal(VEC_BW2_IN, sizeof VEC_BW2_IN,
                                           out, sizeof out);
    CHECK_EQ_INT(n, strlen(VEC_BW2_MIN));
    CHECK_EQ_STR(out, VEC_BW2_MIN);

    uint8_t back[256];
    size_t back_len = 0;
    CHECK_EQ_INT(mw_bytewords_decode_minimal(VEC_BW2_MIN, back, sizeof back,
                                             &back_len), MW_OK);
    CHECK_EQ_INT(back_len, sizeof VEC_BW2_IN);
    CHECK_EQ_MEM(back, VEC_BW2_IN, sizeof VEC_BW2_IN);
}

MW_TEST(test_bytewords_output_bounds) {
    const uint8_t in[8] = { 1, 2, 3, 4, 5, 6, 7, 8 };
    char out[8];
    // (8 + 4) * 2 + 1 = 25 needed; must refuse, not overflow.
    CHECK_EQ_INT(mw_bytewords_encode_minimal(in, sizeof in, out, sizeof out), 0);

    char big[64];
    CHECK(mw_bytewords_encode_minimal(in, sizeof in, big, sizeof big) == 24);
    uint8_t tiny[4];
    size_t len = 0;
    // Payload is 8 bytes but the sink only holds 4.
    CHECK_EQ_INT(mw_bytewords_decode_minimal(big, tiny, sizeof tiny, &len),
                 MW_ERR_TOO_MANY);
}

// ---------------------------------------------------------------------------
// Xoshiro256** and the fountain helpers
// ---------------------------------------------------------------------------

MW_TEST(test_xoshiro) {
    uint64_t got[100];
    mw_ur_test_xoshiro((const uint8_t*)"Wolf", 4, got, 100);
    for (int i = 0; i < 100; i++) CHECK_EQ_INT(got[i] % 100, VEC_RNG1[i]);

    mw_ur_test_xoshiro_int((const uint8_t*)"Wolf", 4, 1, 10, got, 100);
    for (int i = 0; i < 100; i++) CHECK_EQ_INT(got[i], VEC_RNG3[i]);
}

MW_TEST(test_nominal_fragment_length) {
    CHECK_EQ_INT(mw_ur_test_nominal_fragment_len(12345, 1005, 1955), 1764);
    CHECK_EQ_INT(mw_ur_test_nominal_fragment_len(12345, 1005, 30000), 12345);
    CHECK_EQ_INT(mw_ur_test_nominal_fragment_len(1024, 10, 100), 94);
}

MW_TEST(test_choose_degree) {
    // seq_len 11 == the fragment count of a 1024-byte message at 100 bytes max.
    for (int nonce = 1; nonce <= 200; nonce++) {
        char seed[32];
        int n = snprintf(seed, sizeof seed, "Wolf-%d", nonce);
        uint32_t deg = mw_ur_test_choose_degree(11, (const uint8_t*)seed,
                                                (size_t)n);
        CHECK_EQ_INT(deg, VEC_DEGREE[nonce - 1]);
    }
}

MW_TEST(test_choose_fragments) {
    const uint32_t checksum = 790229947u;      // crc32(make_message(1024))
    for (uint32_t seq = 1; seq <= 30; seq++) {
        uint32_t got[16];
        size_t n = mw_ur_test_choose_fragments(seq, 11, checksum, got, 16);
        CHECK_EQ_INT(n, VEC_FRAGS[seq - 1][0]);
        if (n != VEC_FRAGS[seq - 1][0]) continue;
        for (size_t i = 0; i < n; i++)
            CHECK_EQ_INT(got[i], VEC_FRAGS[seq - 1][i + 1]);
    }
}

// ---------------------------------------------------------------------------
// UR encoder - official vectors
// ---------------------------------------------------------------------------

MW_TEST(test_single_part_ur) {
    uint8_t msg[64];
    size_t msg_len = unhex(VEC_MSG50_HEX, msg, sizeof msg);
    CHECK_EQ_INT(msg_len, 50);

    mw_ur_encoder* e = mw_ur_encoder_new("bytes", msg, msg_len, 1000);
    CHECK(e != NULL);
    if (!e) return;
    CHECK(mw_ur_encoder_is_single_part(e));
    CHECK_EQ_INT(mw_ur_encoder_seq_len(e), 1);

    char out[MAX_UR_STR];
    size_t n = mw_ur_encoder_next(e, out, sizeof out);
    CHECK_EQ_INT(n, strlen(VEC_SINGLE_UR));
    CHECK_EQ_STR(out, VEC_SINGLE_UR);
    // Cycles forever, always the same string for a single-part UR.
    CHECK_EQ_INT(mw_ur_encoder_next(e, out, sizeof out), strlen(VEC_SINGLE_UR));
    CHECK_EQ_STR(out, VEC_SINGLE_UR);
    mw_ur_encoder_free(e);

    // ... and it round-trips through the decoder.
    uint8_t buf[256];
    mw_ur_decoder* d = mw_ur_decoder_new(buf, sizeof buf);
    CHECK(d != NULL);
    CHECK_EQ_INT(mw_ur_decoder_receive(d, VEC_SINGLE_UR), MW_OK);
    CHECK(mw_ur_decoder_complete(d));
    CHECK_EQ_INT(mw_ur_decoder_progress_permille(d), 1000);
    const uint8_t* data = NULL;
    size_t len = 0;
    char type[40];
    CHECK_EQ_INT(mw_ur_decoder_result(d, &data, &len, type, sizeof type), MW_OK);
    CHECK_EQ_STR(type, "bytes");
    CHECK_EQ_INT(len, msg_len);
    if (len == msg_len) CHECK_EQ_MEM(data, msg, msg_len);
    mw_ur_decoder_free(d);
}

MW_TEST(test_multipart_encoder_vectors) {
    uint8_t msg[256];
    size_t msg_len = unhex(VEC_MSG256_HEX, msg, sizeof msg);
    CHECK_EQ_INT(msg_len, 256);

    mw_ur_encoder* e = mw_ur_encoder_new("bytes", msg, msg_len, 30);
    CHECK(e != NULL);
    if (!e) return;
    CHECK(!mw_ur_encoder_is_single_part(e));
    CHECK_EQ_INT(mw_ur_encoder_seq_len(e), 9);

    char out[MAX_UR_STR];
    for (int i = 0; i < 20; i++) {
        size_t n = mw_ur_encoder_next(e, out, sizeof out);
        CHECK(n > 0);
        CHECK_EQ_STR(out, VEC_PARTS_256_30[i]);
    }
    mw_ur_encoder_free(e);
}

// ---------------------------------------------------------------------------
// Fountain round trips
// ---------------------------------------------------------------------------

// Encodes `len` bytes at `frag` bytes per fragment, feeds `count` parts to a
// decoder in shuffled order with duplicates, and checks the recovered payload.
static void roundtrip(size_t len, size_t frag, int extra_cycles, int dup_every) {
    uint8_t* payload = (uint8_t*)malloc(len);
    CHECK(payload != NULL);
    if (!payload) return;
    for (size_t i = 0; i < len; i++) payload[i] = (uint8_t)(rnd() >> 11);

    mw_ur_encoder* e = mw_ur_encoder_new("bytes", payload, len, frag);
    CHECK(e != NULL);
    if (!e) { free(payload); return; }

    uint32_t seq_len = mw_ur_encoder_seq_len(e);
    size_t nparts = (size_t)seq_len * (size_t)(1 + extra_cycles);
    char (*parts)[MAX_UR_STR] = malloc(nparts * MAX_UR_STR);
    CHECK(parts != NULL);
    if (!parts) { mw_ur_encoder_free(e); free(payload); return; }

    for (size_t i = 0; i < nparts; i++) {
        size_t n = mw_ur_encoder_next(e, parts[i], MAX_UR_STR);
        CHECK(n > 0);
    }
    mw_ur_encoder_free(e);

    // Fisher-Yates shuffle of the transmission order.
    size_t* order = (size_t*)malloc(nparts * 2 * sizeof(size_t));
    CHECK(order != NULL);
    if (!order) { free(parts); free(payload); return; }
    size_t norder = 0;
    for (size_t i = 0; i < nparts; i++) {
        order[norder++] = i;
        if (dup_every && (i % (size_t)dup_every) == 0) order[norder++] = i;
    }
    for (size_t i = norder; i > 1; i--) {
        size_t j = rnd() % i;
        size_t t = order[i - 1]; order[i - 1] = order[j]; order[j] = t;
    }

    uint8_t* buf = (uint8_t*)malloc(len + 64);
    CHECK(buf != NULL);
    if (!buf) { free(order); free(parts); free(payload); return; }
    mw_ur_decoder* d = mw_ur_decoder_new(buf, len + 64);
    CHECK(d != NULL);

    int last_progress = 0;
    size_t consumed = 0;
    for (size_t i = 0; i < norder && !mw_ur_decoder_complete(d); i++) {
        CHECK_EQ_INT(mw_ur_decoder_receive(d, parts[order[i]]), MW_OK);
        int p = mw_ur_decoder_progress_permille(d);
        CHECK(p >= last_progress);          // progress never goes backwards
        CHECK(p >= 0 && p <= 1000);
        last_progress = p;
        consumed++;
    }
    CHECK(mw_ur_decoder_complete(d));
    CHECK_EQ_INT(mw_ur_decoder_progress_permille(d), 1000);

    const uint8_t* got = NULL;
    size_t got_len = 0;
    char type[40];
    CHECK_EQ_INT(mw_ur_decoder_result(d, &got, &got_len, type, sizeof type),
                 MW_OK);
    CHECK_EQ_STR(type, "bytes");
    CHECK_EQ_INT(got_len, len);
    if (got_len == len) CHECK_EQ_MEM(got, payload, len);

    mw_ur_decoder_free(d);
    free(buf); free(order); free(parts); free(payload);
    (void)consumed;
}

MW_TEST(test_roundtrip_2kb_50byte_fragments) {
    // TZ 3.7: the shipping configuration - ~50 bytes per animated QR frame.
    roundtrip(2048, MW_UR_DEFAULT_FRAGMENT, 3, 5);
}

MW_TEST(test_roundtrip_sizes) {
    roundtrip(1, 50, 2, 0);
    roundtrip(9, 50, 2, 0);
    roundtrip(10, 10, 2, 3);
    roundtrip(64, 50, 2, 2);
    roundtrip(100, 10, 3, 7);
    roundtrip(1024, MW_UR_MAX_FRAGMENT, 2, 4);
    roundtrip(8192, MW_UR_DEFAULT_FRAGMENT, 2, 11);
}

MW_TEST(test_roundtrip_mixed_parts_only) {
    // Feed only the "mixed" parts (seqNum > seqLen); the decoder must still
    // converge through XOR reduction with a bounded mixed-part pool.
    const size_t len = 1000;
    uint8_t payload[1000];
    for (size_t i = 0; i < len; i++) payload[i] = (uint8_t)(i * 7 + 3);

    mw_ur_encoder* e = mw_ur_encoder_new("bytes", payload, len, 50);
    CHECK(e != NULL);
    if (!e) return;
    uint32_t seq_len = mw_ur_encoder_seq_len(e);

    uint8_t buf[1100];
    mw_ur_decoder* d = mw_ur_decoder_new(buf, sizeof buf);
    CHECK(d != NULL);

    char part[MAX_UR_STR];
    for (int i = 0; i < 20000 && !mw_ur_decoder_complete(d); i++) {
        CHECK(mw_ur_encoder_next(e, part, sizeof part) > 0);
        if ((uint32_t)(i + 1) <= seq_len) continue;      // skip the pure parts
        mw_ur_decoder_receive(d, part);
    }
    CHECK(mw_ur_decoder_complete(d));
    const uint8_t* got = NULL;
    size_t got_len = 0;
    CHECK_EQ_INT(mw_ur_decoder_result(d, &got, &got_len, NULL, 0), MW_OK);
    CHECK_EQ_INT(got_len, len);
    if (got_len == len) CHECK_EQ_MEM(got, payload, len);
    mw_ur_decoder_free(d);
    mw_ur_encoder_free(e);
}

MW_TEST(test_decoder_rejects_mismatched_headers) {
    uint8_t payload[600];
    for (size_t i = 0; i < sizeof payload; i++) payload[i] = (uint8_t)i;

    char a[MAX_UR_STR], b[MAX_UR_STR];
    mw_ur_encoder* e1 = mw_ur_encoder_new("bytes", payload, sizeof payload, 50);
    mw_ur_encoder* e2 = mw_ur_encoder_new("bytes", payload, 400, 50);
    CHECK(e1 && e2);
    if (!e1 || !e2) return;
    CHECK(mw_ur_encoder_next(e1, a, sizeof a) > 0);
    CHECK(mw_ur_encoder_next(e2, b, sizeof b) > 0);

    uint8_t buf[1024];
    mw_ur_decoder* d = mw_ur_decoder_new(buf, sizeof buf);
    CHECK_EQ_INT(mw_ur_decoder_receive(d, a), MW_OK);
    // Different messageLen/checksum for the same session: rejected.
    CHECK_EQ_INT(mw_ur_decoder_receive(d, b), MW_ERR_FORMAT);
    CHECK(!mw_ur_decoder_complete(d));
    mw_ur_decoder_free(d);
    mw_ur_encoder_free(e1);
    mw_ur_encoder_free(e2);
}

MW_TEST(test_decoder_rejects_foreign_type) {
    uint8_t payload[300];
    memset(payload, 0xA5, sizeof payload);
    char a[MAX_UR_STR];
    mw_ur_encoder* e = mw_ur_encoder_new("crypto-keyimage", payload,
                                         sizeof payload, 50);
    CHECK(e != NULL);
    if (!e) return;
    CHECK(mw_ur_encoder_next(e, a, sizeof a) > 0);
    CHECK(strncmp(a, "ur:crypto-keyimage/", 19) == 0);

    uint8_t buf[512];
    mw_ur_decoder* d = mw_ur_decoder_new(buf, sizeof buf);
    CHECK_EQ_INT(mw_ur_decoder_receive(d, a), MW_OK);
    char other[MAX_UR_STR];
    memcpy(other, a, strlen(a) + 1);
    memcpy(other, "ur:bytes", 8);
    CHECK_EQ_INT(mw_ur_decoder_receive(d, other), MW_ERR_FORMAT);
    mw_ur_decoder_free(d);
    mw_ur_encoder_free(e);
}

MW_TEST(test_encoder_argument_validation) {
    uint8_t payload[32];
    memset(payload, 1, sizeof payload);
    CHECK(mw_ur_encoder_new(NULL, payload, sizeof payload, 50) == NULL);
    CHECK(mw_ur_encoder_new("bytes", NULL, 10, 50) == NULL);
    CHECK(mw_ur_encoder_new("bytes", payload, 0, 50) == NULL);
    CHECK(mw_ur_encoder_new("BYTES", payload, sizeof payload, 50) == NULL);
    CHECK(mw_ur_encoder_new("byt es", payload, sizeof payload, 50) == NULL);
    CHECK(mw_ur_encoder_new("", payload, sizeof payload, 50) == NULL);
    CHECK(mw_ur_encoder_new(
              "0123456789012345678901234567890123456789",
              payload, sizeof payload, 50) == NULL);
    CHECK(mw_ur_decoder_new(NULL, 100) == NULL);
    CHECK(mw_ur_decoder_new(payload, 0) == NULL);

    // Output buffer far too small: refuse rather than truncate.
    mw_ur_encoder* e = mw_ur_encoder_new("bytes", payload, sizeof payload, 50);
    CHECK(e != NULL);
    if (!e) return;
    char tiny[8];
    CHECK_EQ_INT(mw_ur_encoder_next(e, tiny, sizeof tiny), 0);
    mw_ur_encoder_free(e);
    mw_ur_encoder_free(NULL);
    mw_ur_decoder_free(NULL);
}

MW_TEST(test_decoder_rejects_oversized_message) {
    uint8_t payload[4000];
    memset(payload, 0x5A, sizeof payload);
    mw_ur_encoder* e = mw_ur_encoder_new("bytes", payload, sizeof payload, 50);
    CHECK(e != NULL);
    if (!e) return;
    char part[MAX_UR_STR];
    CHECK(mw_ur_encoder_next(e, part, sizeof part) > 0);

    uint8_t small[128];                    // way below messageLen
    mw_ur_decoder* d = mw_ur_decoder_new(small, sizeof small);
    CHECK_EQ_INT(mw_ur_decoder_receive(d, part), MW_ERR_TOO_MANY);
    CHECK(!mw_ur_decoder_complete(d));
    mw_ur_decoder_free(d);
    mw_ur_encoder_free(e);
}

// ---------------------------------------------------------------------------
// Hostile input
// ---------------------------------------------------------------------------

MW_TEST(test_decoder_junk_input) {
    uint8_t buf[4096];
    static const char* const junk[] = {
        "", "u", "ur", "ur:", "ur:/", "ur:bytes", "ur:bytes/", "ur:bytes//",
        "ur:bytes/1-2", "ur:bytes/1-2/", "ur:bytes/0-9/aeadaolazmjendeoti",
        "ur:bytes/1-0/aeadaolazmjendeoti", "ur:bytes/-1-2/aeadaolazmjendeoti",
        "ur:bytes/1-2/3/aeadaolazmjendeoti", "ur:bytes/a-b/aeadaolazmjendeoti",
        "ur:bytes/99999999999999999999-2/aeadaolazmjendeoti",
        "ur:bytes/1-99999/aeadaolazmjendeoti",
        "ur:bytes/1-2/zzzz", "ur:bytes/1-2/aeadaolazmjendeoti",
        "ur:BYTES!/1-2/aeadaolazmjendeoti",
        "xr:bytes/aeadaolazmjendeoti", "ur;bytes/aeadaolazmjendeoti",
        "ur:bytes/aeadaolazmjendeot", "ur:bytes/aeadaolazmjendeotiX",
        "ur:by tes/aeadaolazmjendeoti",
    };
    for (size_t i = 0; i < sizeof junk / sizeof junk[0]; i++) {
        mw_ur_decoder* d = mw_ur_decoder_new(buf, sizeof buf);
        CHECK(d != NULL);
        mw_err_t err = mw_ur_decoder_receive(d, junk[i]);
        CHECK(err != MW_OK);
        CHECK(!mw_ur_decoder_complete(d));
        const uint8_t* p = NULL;
        size_t l = 0;
        CHECK(mw_ur_decoder_result(d, &p, &l, NULL, 0) != MW_OK);
        mw_ur_decoder_free(d);
    }
    CHECK_EQ_INT(mw_ur_decoder_receive(NULL, "ur:bytes/x"), MW_ERR_INVALID_ARG);
}

MW_TEST(test_decoder_fuzz) {
    // Mutate valid frames: flip characters, truncate, extend, splice. Nothing
    // may crash, read out of bounds (run under ASan) or report a bogus success.
    uint8_t payload[512];
    for (size_t i = 0; i < sizeof payload; i++) payload[i] = (uint8_t)(i ^ 0x3C);

    mw_ur_encoder* e = mw_ur_encoder_new("bytes", payload, sizeof payload, 50);
    CHECK(e != NULL);
    if (!e) return;

    char good[MAX_UR_STR];
    uint8_t buf[1024];
    rnd_state = 0xC0FFEEu;

    for (int iter = 0; iter < 4000; iter++) {
        CHECK(mw_ur_encoder_next(e, good, sizeof good) > 0);
        char mutated[MAX_UR_STR];
        size_t n = strlen(good);
        memcpy(mutated, good, n + 1);

        switch (rnd() % 6) {
            case 0: {                                   // flip one character
                size_t pos = rnd() % n;
                mutated[pos] = (char)(32 + (rnd() % 95));
                break;
            }
            case 1: {                                   // truncate
                size_t cut = rnd() % (n + 1);
                mutated[cut] = '\0';
                break;
            }
            case 2: {                                   // extend with garbage
                size_t add = rnd() % 64;
                if (n + add + 1 < sizeof mutated) {
                    for (size_t i = 0; i < add; i++)
                        mutated[n + i] = (char)('a' + (rnd() % 26));
                    mutated[n + add] = '\0';
                }
                break;
            }
            case 3: {                                   // drop a character
                size_t pos = rnd() % n;
                memmove(mutated + pos, mutated + pos + 1, n - pos);
                break;
            }
            case 4: {                                   // huge body
                size_t add = 3000;
                if (n + add + 1 < sizeof mutated) {
                    for (size_t i = 0; i < add; i++)
                        mutated[n + i] = "aeadaolazm"[rnd() % 10];
                    mutated[n + add] = '\0';
                }
                break;
            }
            default:                                    // unmodified
                break;
        }

        mw_ur_decoder* d = mw_ur_decoder_new(buf, sizeof buf);
        if (!d) continue;
        (void)mw_ur_decoder_receive(d, mutated);
        const uint8_t* p = NULL;
        size_t l = 0;
        char t[40] = { 0 };
        if (mw_ur_decoder_result(d, &p, &l, t, sizeof t) == MW_OK) {
            // A lone `ur:bytes` multi-part frame can never complete a message.
            // (Deleting the '/' before the sequence turns the frame into a
            // single-part UR of type "bytes<seq>-<len>", which legitimately
            // decodes - the UR grammar allows digits and '-' in a type.)
            CHECK(strcmp(t, "bytes") != 0);
            CHECK(l <= sizeof buf);
            CHECK(p >= buf && p + l <= buf + sizeof buf);
        }
        mw_ur_decoder_free(d);
    }
    mw_ur_encoder_free(e);
}

MW_TEST(test_decoder_random_strings) {
    uint8_t buf[2048];
    rnd_state = 0xDEADBEEFu;
    char s[600];
    for (int iter = 0; iter < 3000; iter++) {
        size_t n = rnd() % (sizeof s - 1);
        for (size_t i = 0; i < n; i++) s[i] = (char)(1 + (rnd() % 127));
        s[n] = '\0';
        mw_ur_decoder* d = mw_ur_decoder_new(buf, sizeof buf);
        if (!d) continue;
        (void)mw_ur_decoder_receive(d, s);
        const uint8_t* p = NULL;
        size_t l = 0;
        if (mw_ur_decoder_result(d, &p, &l, NULL, 0) == MW_OK) CHECK(l <= sizeof buf);
        mw_ur_decoder_free(d);
    }
    // Same, but always well-formed prefixes so the bytewords path is hit hard.
    for (int iter = 0; iter < 3000; iter++) {
        size_t n = 8 + (rnd() % 400);
        memcpy(s, "ur:bytes/1-9/", 13);
        for (size_t i = 0; i < n; i++) s[13 + i] = (char)('a' + (rnd() % 26));
        s[13 + n] = '\0';
        mw_ur_decoder* d = mw_ur_decoder_new(buf, sizeof buf);
        if (!d) continue;
        (void)mw_ur_decoder_receive(d, s);
        mw_ur_decoder_free(d);
    }
}

int main(void) {
    printf("=== UR (TZ 3.7) ===\n");
    RUN_TEST(test_crc32);
    RUN_TEST(test_bytewords_known_vector);
    RUN_TEST(test_bytewords_100_bytes);
    RUN_TEST(test_bytewords_output_bounds);
    RUN_TEST(test_xoshiro);
    RUN_TEST(test_nominal_fragment_length);
    RUN_TEST(test_choose_degree);
    RUN_TEST(test_choose_fragments);
    RUN_TEST(test_single_part_ur);
    RUN_TEST(test_multipart_encoder_vectors);
    RUN_TEST(test_roundtrip_2kb_50byte_fragments);
    RUN_TEST(test_roundtrip_sizes);
    RUN_TEST(test_roundtrip_mixed_parts_only);
    RUN_TEST(test_decoder_rejects_mismatched_headers);
    RUN_TEST(test_decoder_rejects_foreign_type);
    RUN_TEST(test_decoder_rejects_oversized_message);
    RUN_TEST(test_encoder_argument_validation);
    RUN_TEST(test_decoder_junk_input);
    RUN_TEST(test_decoder_fuzz);
    RUN_TEST(test_decoder_random_strings);
    return mw_test_summary();
}
