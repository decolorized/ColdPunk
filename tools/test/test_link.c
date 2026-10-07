// USB link protocol (TZ 2.0 stage 1) - framing, dispatcher and the
// transfer-layer channel, all on the host.
//
// What is covered:
//   * COBS: known vectors, zero-heavy and 254/255-byte runs, in-place
//     decoding, malformed input;
//   * message build/parse: CRC, length and magic checks, off-by-one lengths;
//   * HID chunking: report count, "?##"/"?" markers, zero padding, reassembly,
//     stray and interleaved reports, frame start only on "?##" + 8-byte
//     magic + valid header CRC (protocol 3);
//   * busy refusal and the INFO crash diagnostics (bytes 92..97);
//   * serial receiver: split frames, two frames in one chunk, resync on
//     garbage, oversize frames;
//   * dispatcher: PING, INFO, STATUS, PUT/GET/CLEAR round trips, every error
//     code, 64 KiB payloads end to end through both transports;
//   * mw_transfer_receive/send over MW_CHANNEL_USB_LINK, including the
//     cancellable wait and the timeout.
//
// SPDX-License-Identifier: MIT

#include "test_framework.h"
#include "transfer/link.h"
#include "transfer/transfer.h"
#include "crypto/hash.h"
#include "hal/hal.h"

#include <stdlib.h>
#include <string.h>

// ---------------------------------------------------------------------------
// helpers
// ---------------------------------------------------------------------------
static void fill_pattern(uint8_t* p, size_t n, uint32_t seed) {
    uint32_t x = seed ? seed : 1;
    for (size_t i = 0; i < n; ++i) {
        x ^= x << 13; x ^= x >> 17; x ^= x << 5;
        p[i] = (uint8_t)x;
    }
}

static bool memmem_simple(const uint8_t* hay, size_t n, const char* needle) {
    const size_t k = strlen(needle);
    for (size_t i = 0; i + k <= n; ++i)
        if (memcmp(hay + i, needle, k) == 0) return true;
    return false;
}

static uint32_t rd32(const uint8_t* p) {
    return (uint32_t)p[0] | ((uint32_t)p[1] << 8) | ((uint32_t)p[2] << 16) | ((uint32_t)p[3] << 24);
}

static void wr32(uint8_t* p, uint32_t v) {
    p[0] = (uint8_t)v; p[1] = (uint8_t)(v >> 8); p[2] = (uint8_t)(v >> 16); p[3] = (uint8_t)(v >> 24);
}

// A protocol-3 header with an arbitrary (even out-of-range) length and a
// correct header CRC: lets the tests hand-craft hostile headers.
static void make_hdr(uint8_t* h, uint8_t cmd, uint8_t arg, uint32_t len) {
    memcpy(h, mw_link_magic, MW_LINK_MAGIC_LEN);
    h[8] = MW_LINK_PROTO_VERSION; h[9] = cmd; h[10] = arg; h[11] = 0;
    wr32(h + 12, len);
    wr32(h + MW_LINK_HDR_CRC_OFF, mw_crc32(h, MW_LINK_HDR_CRC_OFF));
}

// Runs a request through the dispatcher and parses the reply.
static size_t roundtrip(uint8_t cmd, uint8_t arg, const uint8_t* payload, uint32_t len,
                        uint8_t* req, size_t req_cap, uint8_t* rsp, size_t rsp_cap,
                        mw_link_msg_t* out) {
    size_t n = 0;
    CHECK_EQ_INT(mw_link_msg_build(cmd, arg, payload, len, req, req_cap, &n), MW_OK);
    size_t r = mw_link_handle(req, n, rsp, rsp_cap);
    CHECK(r > 0);
    CHECK_EQ_INT(mw_link_msg_parse(rsp, r, out), MW_OK);
    return r;
}

// Pushes a full message through the serial framing and receiver.
static bool serial_deliver(mw_link_rx_t* rx, const uint8_t* msg, size_t len,
                           uint8_t* wire, size_t wire_cap, size_t chunk) {
    size_t n = mw_link_serial_frame(msg, len, wire, wire_cap);
    CHECK(n > 0);
    size_t off = 0;
    bool ready = false;
    while (off < n) {
        size_t take = n - off < chunk ? n - off : chunk;
        size_t used = 0;
        ready = mw_link_rx_feed(rx, wire + off, take, &used);
        CHECK(used > 0);
        off += used;
        if (ready) break;
    }
    return ready;
}

// Pushes a full message through the HID framing and receiver.
static bool hid_deliver(mw_link_rx_t* rx, const uint8_t* msg, size_t len) {
    size_t reports = mw_link_hid_report_count(len);
    uint8_t rep[MW_LINK_HID_DATA];
    bool ready = false;
    for (size_t i = 0; i < reports; ++i) {
        mw_link_hid_report(msg, len, i, rep);
        size_t used = 0;
        ready = mw_link_rx_feed(rx, rep, MW_LINK_HID_DATA, &used);
        CHECK_EQ_INT(used, MW_LINK_HID_DATA);
        if (ready) { CHECK_EQ_INT(i, reports - 1); break; }
    }
    return ready;
}

// ---------------------------------------------------------------------------
// COBS
// ---------------------------------------------------------------------------
MW_TEST(test_cobs_vectors) {
    // Wikipedia examples.
    struct { const char* in_hex; const char* out_hex; } v[] = {
        { "",                 "01" },
        { "00",               "0101" },
        { "0000",             "010101" },
        { "1122003344",       "0311220333 44" },
        { "11223344",         "0511223344" },
        { "11000000",         "021101 0101" },
    };
    for (size_t i = 0; i < sizeof v / sizeof v[0]; ++i) {
        uint8_t in[16], want[16], out[32], back[16];
        size_t in_len   = mw_test_hex(v[i].in_hex, in, sizeof in);
        char clean[32]; size_t k = 0;
        for (const char* c = v[i].out_hex; *c; ++c) if (*c != ' ') clean[k++] = *c;
        clean[k] = 0;
        size_t want_len = mw_test_hex(clean, want, sizeof want);

        size_t n = mw_cobs_encode(in, in_len, out, sizeof out);
        CHECK_EQ_INT(n, want_len);
        CHECK_EQ_MEM(out, want, want_len);
        for (size_t j = 0; j < n; ++j) CHECK(out[j] != 0);

        size_t dl = 0;
        CHECK_EQ_INT(mw_cobs_decode(out, n, back, sizeof back, &dl), MW_OK);
        CHECK_EQ_INT(dl, in_len);
        if (in_len) CHECK_EQ_MEM(back, in, in_len);
    }
}

MW_TEST(test_cobs_long_runs) {
    // 254 non-zero bytes: one full block, code 0xFF, plus a trailing 0x01.
    // 255 non-zero bytes: 0xFF block + a 0x02 block.
    for (size_t len = 250; len <= 520; ++len) {
        uint8_t in[600], enc[700], dec[600];
        for (size_t i = 0; i < len; ++i) in[i] = (uint8_t)(1 + (i % 255));
        size_t n = mw_cobs_encode(in, len, enc, sizeof enc);
        CHECK(n > 0);
        CHECK(n <= mw_cobs_max_encoded(len));
        for (size_t j = 0; j < n; ++j) CHECK(enc[j] != 0);
        size_t dl = 0;
        CHECK_EQ_INT(mw_cobs_decode(enc, n, dec, sizeof dec, &dl), MW_OK);
        CHECK_EQ_INT(dl, len);
        CHECK_EQ_MEM(dec, in, len);
    }
}

MW_TEST(test_cobs_random_inplace) {
    uint8_t in[3000], enc[3200], copy[3200];
    for (int round = 0; round < 200; ++round) {
        size_t len = (size_t)(round * 37) % sizeof in;
        fill_pattern(in, len, (uint32_t)round + 7);
        // Sprinkle zeros: every 5th round is zero-heavy.
        if (round % 5 == 0) for (size_t i = 0; i < len; i += 3) in[i] = 0;
        size_t n = mw_cobs_encode(in, len, enc, sizeof enc);
        CHECK(n > 0);
        memcpy(copy, enc, n);
        size_t dl = 0;
        CHECK_EQ_INT(mw_cobs_decode(copy, n, copy, sizeof copy, &dl), MW_OK);  // in place
        CHECK_EQ_INT(dl, len);
        if (len) CHECK_EQ_MEM(copy, in, len);
    }
}

MW_TEST(test_cobs_malformed) {
    uint8_t out[16];
    size_t dl = 0;
    uint8_t zero_code[] = { 0x00 };
    CHECK_EQ_INT(mw_cobs_decode(zero_code, 1, out, sizeof out, &dl), MW_ERR_FORMAT);
    uint8_t truncated[] = { 0x05, 0x11, 0x22 };          // promises 4 bytes
    CHECK_EQ_INT(mw_cobs_decode(truncated, 3, out, sizeof out, &dl), MW_ERR_FORMAT);
    uint8_t embedded[] = { 0x03, 0x11, 0x00 };           // zero inside a block
    CHECK_EQ_INT(mw_cobs_decode(embedded, 3, out, sizeof out, &dl), MW_ERR_FORMAT);
    uint8_t ok[] = { 0x03, 0x11, 0x22, 0x02, 0x33 };     // 11 22 00 33
    CHECK_EQ_INT(mw_cobs_decode(ok, 5, out, 2, &dl), MW_ERR_TOO_MANY);
    CHECK_EQ_INT(mw_cobs_decode(ok, 5, out, 4, &dl), MW_OK);
    CHECK_EQ_INT(dl, 4);
    // Encoder refuses a short output.
    uint8_t in[10] = {1,2,3,4,5,6,7,8,9,10};
    CHECK_EQ_INT(mw_cobs_encode(in, 10, out, 5), 0);
}

// ---------------------------------------------------------------------------
// Messages
// ---------------------------------------------------------------------------
MW_TEST(test_msg_build_parse) {
    uint8_t buf[64];
    size_t n = 0;
    const uint8_t pl[] = { 1, 2, 3, 0, 4 };
    CHECK_EQ_INT(mw_link_msg_build(MW_LINK_CMD_PUT, 2, pl, sizeof pl, buf, sizeof buf, &n), MW_OK);
    CHECK_EQ_INT(n, MW_LINK_OVERHEAD + sizeof pl);
    CHECK_EQ_MEM(buf, mw_link_magic, MW_LINK_MAGIC_LEN);
    CHECK_EQ_INT(buf[0], 'M'); CHECK_EQ_INT(buf[1], 'W');
    CHECK_EQ_INT(buf[8], MW_LINK_PROTO_VERSION);
    CHECK_EQ_INT(buf[9], MW_LINK_CMD_PUT); CHECK_EQ_INT(buf[10], 2); CHECK_EQ_INT(buf[11], 0);
    CHECK_EQ_INT(rd32(buf + 12), sizeof pl);
    CHECK_EQ_INT(rd32(buf + 16), mw_crc32(buf, 16));
    CHECK(mw_link_hdr_valid(buf, n, NULL));
    CHECK_EQ_INT(rd32(buf + MW_LINK_HDR_LEN + sizeof pl),
                 mw_crc32(buf, MW_LINK_HDR_LEN + sizeof pl));

    mw_link_msg_t m;
    CHECK_EQ_INT(mw_link_msg_parse(buf, n, &m), MW_OK);
    CHECK_EQ_INT(m.cmd, MW_LINK_CMD_PUT);
    CHECK_EQ_INT(m.arg, 2);
    CHECK_EQ_INT(m.len, sizeof pl);
    CHECK_EQ_MEM(m.payload, pl, sizeof pl);

    // Empty payload, NULL pointer allowed.
    CHECK_EQ_INT(mw_link_msg_build(MW_LINK_CMD_INFO, 0, NULL, 0, buf, sizeof buf, &n), MW_OK);
    CHECK_EQ_INT(n, MW_LINK_OVERHEAD);
    CHECK_EQ_INT(mw_link_msg_parse(buf, n, &m), MW_OK);
    CHECK_EQ_INT(m.len, 0);

    // Too small an output buffer.
    CHECK(mw_link_msg_build(MW_LINK_CMD_PUT, 0, pl, sizeof pl, buf, MW_LINK_OVERHEAD + 2, &n) != MW_OK);
}

MW_TEST(test_msg_parse_rejects) {
    uint8_t buf[64];
    size_t n = 0;
    const uint8_t pl[] = { 9, 8, 7 };
    mw_link_msg_t m;
    CHECK_EQ_INT(mw_link_msg_build(MW_LINK_CMD_PING, 0, pl, 3, buf, sizeof buf, &n), MW_OK);

    CHECK_EQ_INT(mw_link_msg_parse(buf, n - 1, &m), MW_ERR_FORMAT);   // short
    CHECK_EQ_INT(mw_link_msg_parse(buf, n + 1, &m), MW_ERR_FORMAT);   // long
    CHECK_EQ_INT(mw_link_msg_parse(buf, 5, &m), MW_ERR_FORMAT);       // below header

    buf[MW_LINK_HDR_LEN + 1] ^= 0x01;                                   // payload bit flip
    CHECK_EQ_INT(mw_link_msg_parse(buf, n, &m), MW_ERR_CHECKSUM);
    buf[MW_LINK_HDR_LEN + 1] ^= 0x01;
    buf[10] ^= 0x01;                                                    // header (arg) flip
    CHECK_EQ_INT(mw_link_msg_parse(buf, n, &m), MW_ERR_CHECKSUM);
    CHECK(!mw_link_hdr_valid(buf, n, NULL));
    buf[10] ^= 0x01;
    buf[n - 1] ^= 0x80;                                                 // crc bit flip
    CHECK_EQ_INT(mw_link_msg_parse(buf, n, &m), MW_ERR_CHECKSUM);
    buf[n - 1] ^= 0x80;

    buf[0] = 'X';
    CHECK_EQ_INT(mw_link_msg_parse(buf, n, &m), MW_ERR_MAGIC);
    buf[0] = 'M';
    buf[7] ^= 0x01;                                                     // last magic byte
    CHECK_EQ_INT(mw_link_msg_parse(buf, n, &m), MW_ERR_MAGIC);
    buf[7] ^= 0x01;
    buf[8] = 2;                                                         // old protocol
    CHECK_EQ_INT(mw_link_msg_parse(buf, n, &m), MW_ERR_MAGIC);
    buf[8] = MW_LINK_PROTO_VERSION;

    // Length field claiming more than the cap (header CRC itself valid).
    uint8_t big[MW_LINK_OVERHEAD + 4];
    memset(big, 0, sizeof big);
    make_hdr(big, MW_LINK_CMD_PING, 0, MW_LINK_MAX_PAYLOAD + 1);
    CHECK_EQ_INT(mw_link_msg_parse(big, sizeof big, &m), MW_ERR_TOO_MANY);
    CHECK_EQ_INT(mw_link_msg_parse(buf, n, &m), MW_OK);                // intact again
}

// ---------------------------------------------------------------------------
// HID framing
// ---------------------------------------------------------------------------
MW_TEST(test_hid_report_count) {
    CHECK_EQ_INT(mw_link_hid_report_count(0), 1);
    CHECK_EQ_INT(mw_link_hid_report_count(1), 1);
    CHECK_EQ_INT(mw_link_hid_report_count(60), 1);
    CHECK_EQ_INT(mw_link_hid_report_count(61), 2);
    CHECK_EQ_INT(mw_link_hid_report_count(60 + 62), 2);
    CHECK_EQ_INT(mw_link_hid_report_count(60 + 62 + 1), 3);
    size_t max = MW_LINK_MAX_MSG;
    size_t r = mw_link_hid_report_count(max);
    CHECK(60 + (r - 1) * 62 >= max);
    CHECK(60 + (r - 2) * 62 < max);
}

MW_TEST(test_hid_report_layout) {
    uint8_t msg[130], rep[MW_LINK_HID_DATA];
    fill_pattern(msg, sizeof msg, 3);
    mw_link_hid_report(msg, sizeof msg, 0, rep);
    CHECK_EQ_INT(rep[0], '?'); CHECK_EQ_INT(rep[1], '#'); CHECK_EQ_INT(rep[2], '#');
    CHECK_EQ_MEM(rep + 3, msg, 60);
    mw_link_hid_report(msg, sizeof msg, 1, rep);
    CHECK_EQ_INT(rep[0], '?');
    CHECK_EQ_MEM(rep + 1, msg + 60, 62);
    mw_link_hid_report(msg, sizeof msg, 2, rep);
    CHECK_EQ_INT(rep[0], '?');
    CHECK_EQ_MEM(rep + 1, msg + 122, 8);
    for (int i = 9; i < MW_LINK_HID_DATA; ++i) CHECK_EQ_INT(rep[i], 0);   // padding
    // Beyond the end: marker only.
    mw_link_hid_report(msg, sizeof msg, 3, rep);
    CHECK_EQ_INT(rep[0], '?');
    for (int i = 1; i < MW_LINK_HID_DATA; ++i) CHECK_EQ_INT(rep[i], 0);
}

MW_TEST(test_hid_rx_reassembly) {
    static uint8_t rxbuf[MW_LINK_MAX_MSG];
    static uint8_t msg[MW_LINK_MAX_MSG];
    static uint8_t payload[MW_LINK_MAX_PAYLOAD];
    mw_link_rx_t rx;
    mw_link_rx_init(&rx, MW_LINK_TRANSPORT_HID, rxbuf, sizeof rxbuf);

    const size_t sizes[] = { 0, 1, 59, 60, 61, 122, 123, 1000, 4096, MW_LINK_MAX_PAYLOAD };
    for (size_t s = 0; s < sizeof sizes / sizeof sizes[0]; ++s) {
        size_t n = 0;
        fill_pattern(payload, sizes[s], (uint32_t)s + 11);
        CHECK_EQ_INT(mw_link_msg_build(MW_LINK_CMD_PUT, 1, payload, (uint32_t)sizes[s],
                                       msg, sizeof msg, &n), MW_OK);
        CHECK(hid_deliver(&rx, msg, n));
        CHECK(rx.ready);
        CHECK_EQ_INT(rx.len, n);
        CHECK_EQ_MEM(rx.buf, msg, n);
        mw_link_msg_t m;
        CHECK_EQ_INT(mw_link_msg_parse(rx.buf, rx.len, &m), MW_OK);
        CHECK_EQ_INT(m.len, sizes[s]);
        mw_link_rx_reset(&rx);
    }
}

MW_TEST(test_hid_rx_hostile) {
    static uint8_t rxbuf[MW_LINK_MAX_MSG];
    mw_link_rx_t rx;
    mw_link_rx_init(&rx, MW_LINK_TRANSPORT_HID, rxbuf, sizeof rxbuf);
    uint8_t rep[MW_LINK_HID_DATA];
    size_t used = 0;

    // Continuation with no frame open: dropped.
    memset(rep, 0, sizeof rep); rep[0] = '?'; rep[1] = 0x42;
    CHECK(!mw_link_rx_feed(&rx, rep, sizeof rep, &used));
    CHECK_EQ_INT(rx.dropped, 1);

    // Random junk: dropped.
    fill_pattern(rep, sizeof rep, 99); rep[0] = 'x';
    CHECK(!mw_link_rx_feed(&rx, rep, sizeof rep, &used));
    CHECK_EQ_INT(rx.dropped, 2);

    // First report with a bad magic: dropped.
    memset(rep, 0, sizeof rep); rep[0] = '?'; rep[1] = '#'; rep[2] = '#';
    make_hdr(rep + 3, MW_LINK_CMD_PING, 0, 0);
    rep[3 + 5] ^= 0x10;                                                 // one magic bit
    CHECK(!mw_link_rx_feed(&rx, rep, sizeof rep, &used));
    CHECK_EQ_INT(rx.dropped, 3);
    CHECK(!rx.in_frame);

    // First report announcing an oversize payload: dropped.
    memset(rep, 0, sizeof rep); rep[0] = '?'; rep[1] = '#'; rep[2] = '#';
    make_hdr(rep + 3, MW_LINK_CMD_PUT, 0, MW_LINK_MAX_PAYLOAD + 1);
    CHECK(!mw_link_rx_feed(&rx, rep, sizeof rep, &used));
    CHECK_EQ_INT(rx.dropped, 4);

    // A new "?##" in the middle of a frame abandons the old one and starts
    // over; the second frame still decodes.
    uint8_t msg[200]; size_t n = 0;
    uint8_t pl[150]; fill_pattern(pl, sizeof pl, 5);
    CHECK_EQ_INT(mw_link_msg_build(MW_LINK_CMD_PING, 0, pl, sizeof pl, msg, sizeof msg, &n), MW_OK);
    mw_link_hid_report(msg, n, 0, rep);
    CHECK(!mw_link_rx_feed(&rx, rep, sizeof rep, &used));
    CHECK(rx.in_frame);
    CHECK(hid_deliver(&rx, msg, n));            // restarts with "?##"
    CHECK_EQ_INT(rx.dropped, 5);
    CHECK_EQ_INT(rx.len, n);
    CHECK_EQ_MEM(rx.buf, msg, n);
    mw_link_rx_reset(&rx);

    // Too-short report is ignored.
    CHECK(!mw_link_rx_feed(&rx, rep, 2, &used));
    CHECK_EQ_INT(used, 2);
}

// ---------------------------------------------------------------------------
// Serial receiver
// ---------------------------------------------------------------------------
MW_TEST(test_serial_rx_chunking) {
    static uint8_t rxbuf[MW_LINK_MAX_MSG + MW_LINK_MAX_MSG / 254 + 4];
    static uint8_t wire[MW_LINK_MAX_MSG + MW_LINK_MAX_MSG / 254 + 4];
    static uint8_t msg[MW_LINK_MAX_MSG];
    static uint8_t payload[MW_LINK_MAX_PAYLOAD];
    mw_link_rx_t rx;
    mw_link_rx_init(&rx, MW_LINK_TRANSPORT_SERIAL, rxbuf, sizeof rxbuf);

    const size_t sizes[]  = { 0, 1, 7, 253, 254, 255, 508, 4096, MW_LINK_MAX_PAYLOAD };
    const size_t chunks[] = { 1, 3, 64, 512, 100000 };
    for (size_t s = 0; s < sizeof sizes / sizeof sizes[0]; ++s) {
        size_t n = 0;
        fill_pattern(payload, sizes[s], (uint32_t)s + 3);
        for (size_t i = 0; i < sizes[s]; i += 9) payload[i] = 0;      // plenty of zeros
        CHECK_EQ_INT(mw_link_msg_build(MW_LINK_CMD_PUT, 3, payload, (uint32_t)sizes[s],
                                       msg, sizeof msg, &n), MW_OK);
        for (size_t c = 0; c < sizeof chunks / sizeof chunks[0]; ++c) {
            if (sizes[s] > 4096 && chunks[c] < 64) continue;           // keep the run short
            CHECK(serial_deliver(&rx, msg, n, wire, sizeof wire, chunks[c]));
            CHECK_EQ_INT(rx.len, n);
            CHECK_EQ_MEM(rx.buf, msg, n);
            mw_link_rx_reset(&rx);
        }
    }
}

MW_TEST(test_serial_rx_two_frames_one_chunk) {
    uint8_t rxbuf[256], wire[512], a[64], b[64];
    size_t na = 0, nb = 0;
    const uint8_t pa[] = { 1, 0, 2 }, pb[] = { 0, 0, 0, 9 };
    CHECK_EQ_INT(mw_link_msg_build(MW_LINK_CMD_PING, 1, pa, 3, a, sizeof a, &na), MW_OK);
    CHECK_EQ_INT(mw_link_msg_build(MW_LINK_CMD_PING, 2, pb, 4, b, sizeof b, &nb), MW_OK);
    size_t wa = mw_link_serial_frame(a, na, wire, sizeof wire);
    size_t wb = mw_link_serial_frame(b, nb, wire + wa, sizeof wire - wa);
    CHECK(wa > 0 && wb > 0);

    mw_link_rx_t rx;
    mw_link_rx_init(&rx, MW_LINK_TRANSPORT_SERIAL, rxbuf, sizeof rxbuf);
    size_t used = 0;
    CHECK(mw_link_rx_feed(&rx, wire, wa + wb, &used));
    CHECK_EQ_INT(used, wa);
    CHECK_EQ_INT(rx.len, na);
    CHECK_EQ_MEM(rx.buf, a, na);
    // Not reset yet: feeding again just says "still ready".
    size_t used2 = 0;
    CHECK(mw_link_rx_feed(&rx, wire + used, wb, &used2));
    CHECK_EQ_INT(used2, 0);
    mw_link_rx_reset(&rx);
    CHECK(mw_link_rx_feed(&rx, wire + used, wb, &used2));
    CHECK_EQ_INT(used2, wb);
    CHECK_EQ_INT(rx.len, nb);
    CHECK_EQ_MEM(rx.buf, b, nb);
}

MW_TEST(test_serial_rx_resync) {
    uint8_t rxbuf[128], wire[256], msg[64];
    size_t n = 0, used = 0;
    const uint8_t pl[] = { 0xAA, 0x00, 0xBB };
    CHECK_EQ_INT(mw_link_msg_build(MW_LINK_CMD_PING, 0, pl, 3, msg, sizeof msg, &n), MW_OK);
    mw_link_rx_t rx;
    mw_link_rx_init(&rx, MW_LINK_TRANSPORT_SERIAL, rxbuf, sizeof rxbuf);

    // Idle zeros are ignored.
    uint8_t zeros[5] = { 0 };
    CHECK(!mw_link_rx_feed(&rx, zeros, sizeof zeros, &used));
    CHECK_EQ_INT(used, 5);
    CHECK_EQ_INT(rx.dropped, 0);

    // Garbage then a delimiter: dropped (bad COBS), receiver still clean.
    uint8_t junk[] = { 0x00, 0x05, 0x11, 0x00 };                        // truncated block
    CHECK(!mw_link_rx_feed(&rx, junk, sizeof junk, &used));
    CHECK_EQ_INT(rx.dropped, 1);
    CHECK_EQ_INT(rx.len, 0);

    // A frame longer than the buffer is discarded up to the next delimiter
    // and the frame after it is received intact.
    uint8_t flood[300];
    memset(flood, 0x01, sizeof flood);
    CHECK(!mw_link_rx_feed(&rx, flood, sizeof flood, &used));
    CHECK(rx.overflow);
    CHECK(!mw_link_rx_feed(&rx, zeros, 1, &used));
    CHECK_EQ_INT(rx.dropped, 2);
    CHECK(!rx.overflow);
    CHECK(serial_deliver(&rx, msg, n, wire, sizeof wire, 1000));
    CHECK_EQ_INT(rx.len, n);
    CHECK_EQ_MEM(rx.buf, msg, n);
}

// ---------------------------------------------------------------------------
// Dispatcher
// ---------------------------------------------------------------------------
static int  s_info_calls = 0;
static void info_provider(mw_link_info_t* out, void* ctx) {
    (void)ctx;
    s_info_calls++;
    snprintf(out->fw_version, sizeof out->fw_version, "0.1.0-test");
    snprintf(out->board, sizeof out->board, "HOST");
    snprintf(out->wallet_name, sizeof out->wallet_name, "borya");
    out->wallet_count = 3;
    out->unlocked = 1;
    out->network = 2;
    out->pp_variant = 1;
}

MW_TEST(test_dispatch_ping_info_status) {
    static uint8_t req[MW_LINK_MAX_MSG], rsp[MW_LINK_MAX_MSG];
    mw_link_msg_t m;
    CHECK_EQ_INT(mw_link_init(), MW_OK);
    mw_link_set_info_provider(info_provider, NULL);
    mw_link_set_up(true, MW_LINK_CAP_SERIAL | MW_LINK_CAP_HID);

    // PING echoes the payload and the arg.
    const uint8_t pl[] = { 'h', 'i', 0, 1 };
    roundtrip(MW_LINK_CMD_PING, 0x5A, pl, sizeof pl, req, sizeof req, rsp, sizeof rsp, &m);
    CHECK_EQ_INT(m.cmd, MW_LINK_RSP_PONG);
    CHECK_EQ_INT(m.arg, 0x5A);
    CHECK_EQ_INT(m.len, sizeof pl);
    CHECK_EQ_MEM(m.payload, pl, sizeof pl);

    // PING with a huge payload is echoed truncated, not refused.
    static uint8_t big[4000];
    fill_pattern(big, sizeof big, 1);
    roundtrip(MW_LINK_CMD_PING, 0, big, sizeof big, req, sizeof req, rsp, sizeof rsp, &m);
    CHECK_EQ_INT(m.cmd, MW_LINK_RSP_PONG);
    CHECK_EQ_INT(m.len, MW_LINK_PING_MAX);
    CHECK_EQ_MEM(m.payload, big, MW_LINK_PING_MAX);

    // INFO (v2 layout).
    mw_link_set_state(MW_LINK_STATE_WALLET, 0x05);
    s_info_calls = 0;
    roundtrip(MW_LINK_CMD_INFO, 0, NULL, 0, req, sizeof req, rsp, sizeof rsp, &m);
    CHECK_EQ_INT(m.cmd, MW_LINK_RSP_INFO);
    CHECK_EQ_INT(m.len, MW_LINK_INFO_WIRE_LEN);
    CHECK_EQ_INT(s_info_calls, 1);
    CHECK_EQ_INT(m.payload[0], MW_LINK_PROTO_VERSION);
    CHECK_EQ_INT(m.payload[1], MW_LINK_CAP_SERIAL | MW_LINK_CAP_HID |
                               MW_LINK_CAP_AUTO_KIND | MW_LINK_CAP_REQ);
    CHECK_EQ_INT(m.payload[2], MW_LINK_STATE_WALLET);
    CHECK_EQ_INT(m.payload[3], 2);                       // stagenet
    CHECK_EQ_INT(rd32(m.payload + 4), MW_LINK_MAX_PAYLOAD);
    CHECK_EQ_INT(m.payload[8], 3);
    CHECK_EQ_INT(m.payload[9], 1);
    CHECK_EQ_INT(m.payload[10], 1);
    CHECK_EQ_INT(m.payload[11], MW_LINK_FILE_KINDS);
    CHECK_EQ_STR((const char*)m.payload + 12, "0.1.0-test");
    CHECK_EQ_STR((const char*)m.payload + 28, "HOST");
    CHECK_EQ_STR((const char*)m.payload + 60, "borya");
    CHECK_EQ_INT(m.payload[27], 0);                     // NUL padded
    CHECK_EQ_INT(m.payload[91], 0);
    CHECK_EQ_INT(m.payload[127], 0);

    // STATUS: all empty, state and mask reported.
    roundtrip(MW_LINK_CMD_STATUS, 0, NULL, 0, req, sizeof req, rsp, sizeof rsp, &m);
    CHECK_EQ_INT(m.cmd, MW_LINK_RSP_STATUS);
    CHECK_EQ_INT(m.len, MW_LINK_STATUS_WIRE_LEN);
    for (int i = 0; i < 2 * MW_LINK_FILE_KINDS; ++i) CHECK_EQ_INT(rd32(m.payload + 4 * i), 0);
    CHECK_EQ_INT(m.payload[40], MW_LINK_STATE_WALLET);
    CHECK_EQ_INT(m.payload[41], 0);
    CHECK_EQ_INT(m.payload[42], 0x05);

    mw_link_deinit();
}

MW_TEST(test_dispatch_put_get_clear) {
    static uint8_t req[MW_LINK_MAX_MSG], rsp[MW_LINK_MAX_MSG];
    static uint8_t file[MW_LINK_MAX_PAYLOAD], back[MW_LINK_MAX_PAYLOAD];
    mw_link_msg_t m;
    CHECK_EQ_INT(mw_link_init(), MW_OK);
    mw_link_set_state(MW_LINK_STATE_WALLET, 0x1F);

    // PUT outputs (kind 0) of 1234 bytes -> ACK, inbox shows it, STATUS too.
    fill_pattern(file, 1234, 42);
    roundtrip(MW_LINK_CMD_PUT, MW_FILE_KIND_OUTPUTS, file, 1234, req, sizeof req, rsp, sizeof rsp, &m);
    CHECK_EQ_INT(m.cmd, MW_LINK_RSP_ACK);
    CHECK_EQ_INT(m.arg, MW_FILE_KIND_OUTPUTS);
    size_t len = 0;
    CHECK(mw_link_inbox_pending(MW_FILE_KIND_OUTPUTS, &len));
    CHECK_EQ_INT(len, 1234);
    CHECK(!mw_link_inbox_pending(MW_FILE_KIND_UNSIGNED_TX, NULL));
    roundtrip(MW_LINK_CMD_STATUS, 0, NULL, 0, req, sizeof req, rsp, sizeof rsp, &m);
    CHECK_EQ_INT(rd32(m.payload + 0), 1234);
    CHECK_EQ_INT(rd32(m.payload + 4 * MW_LINK_FILE_KINDS), 0);

    // A second PUT while the first is still being processed: BUSY, the first
    // file is kept.
    fill_pattern(file, 999, 43);
    roundtrip(MW_LINK_CMD_PUT, MW_FILE_KIND_OUTPUTS, file, 999, req, sizeof req, rsp, sizeof rsp, &m);
    CHECK_EQ_INT(m.cmd, MW_LINK_RSP_ERROR);
    CHECK_EQ_INT(m.arg, MW_LINK_ERR_BUSY);
    CHECK(mw_link_inbox_pending(MW_FILE_KIND_OUTPUTS, &len));
    CHECK_EQ_INT(len, 1234);
    mw_link_inbox_clear(MW_FILE_KIND_OUTPUTS);
    roundtrip(MW_LINK_CMD_PUT, MW_FILE_KIND_OUTPUTS, file, 999, req, sizeof req, rsp, sizeof rsp, &m);
    CHECK_EQ_INT(m.cmd, MW_LINK_RSP_ACK);
    CHECK(mw_link_inbox_pending(MW_FILE_KIND_OUTPUTS, &len));
    CHECK_EQ_INT(len, 999);

    // Firmware takes it: contents match, slot empties, a small buffer is refused
    // without losing the file.
    CHECK_EQ_INT(mw_link_inbox_take(MW_FILE_KIND_OUTPUTS, back, 100, &len), MW_ERR_TOO_MANY);
    CHECK(mw_link_inbox_pending(MW_FILE_KIND_OUTPUTS, NULL));
    CHECK_EQ_INT(mw_link_inbox_take(MW_FILE_KIND_OUTPUTS, back, sizeof back, &len), MW_OK);
    CHECK_EQ_INT(len, 999);
    CHECK_EQ_MEM(back, file, 999);
    CHECK(!mw_link_inbox_pending(MW_FILE_KIND_OUTPUTS, NULL));
    CHECK_EQ_INT(mw_link_inbox_take(MW_FILE_KIND_OUTPUTS, back, sizeof back, &len), MW_ERR_NOT_SUPPORTED);

    // GET on an empty outbox -> ERROR not ready.
    roundtrip(MW_LINK_CMD_GET, MW_FILE_KIND_KEYIMAGES, NULL, 0, req, sizeof req, rsp, sizeof rsp, &m);
    CHECK_EQ_INT(m.cmd, MW_LINK_RSP_ERROR);
    CHECK_EQ_INT(m.arg, MW_LINK_ERR_NOT_READY);
    CHECK(m.len > 0);

    // Firmware puts a result; GET returns it, twice (retransmit safe), CLEAR
    // empties it.
    fill_pattern(file, 5000, 44);
    CHECK_EQ_INT(mw_link_outbox_put(MW_FILE_KIND_KEYIMAGES, file, 5000), MW_OK);
    CHECK(mw_link_outbox_pending(MW_FILE_KIND_KEYIMAGES, &len));
    CHECK_EQ_INT(len, 5000);
    for (int rep = 0; rep < 2; ++rep) {
        roundtrip(MW_LINK_CMD_GET, MW_FILE_KIND_KEYIMAGES, NULL, 0, req, sizeof req, rsp, sizeof rsp, &m);
        CHECK_EQ_INT(m.cmd, MW_LINK_RSP_FILE);
        CHECK_EQ_INT(m.arg, MW_FILE_KIND_KEYIMAGES);
        CHECK_EQ_INT(m.len, 5000);
        CHECK_EQ_MEM(m.payload, file, 5000);
    }
    roundtrip(MW_LINK_CMD_STATUS, 0, NULL, 0, req, sizeof req, rsp, sizeof rsp, &m);
    CHECK_EQ_INT(rd32(m.payload + 4 * MW_LINK_FILE_KINDS + 4 * MW_FILE_KIND_KEYIMAGES), 5000);
    roundtrip(MW_LINK_CMD_CLEAR, MW_FILE_KIND_KEYIMAGES, NULL, 0, req, sizeof req, rsp, sizeof rsp, &m);
    CHECK_EQ_INT(m.cmd, MW_LINK_RSP_ACK);
    CHECK(!mw_link_outbox_pending(MW_FILE_KIND_KEYIMAGES, NULL));
    roundtrip(MW_LINK_CMD_GET, MW_FILE_KIND_KEYIMAGES, NULL, 0, req, sizeof req, rsp, sizeof rsp, &m);
    CHECK_EQ_INT(m.cmd, MW_LINK_RSP_ERROR);

    // CLEAR all.
    CHECK_EQ_INT(mw_link_outbox_put(MW_FILE_KIND_SIGNED_TX, file, 10), MW_OK);
    CHECK_EQ_INT(mw_link_outbox_put(MW_FILE_KIND_KEYIMAGES, file, 20), MW_OK);
    roundtrip(MW_LINK_CMD_CLEAR, MW_LINK_KIND_ALL, NULL, 0, req, sizeof req, rsp, sizeof rsp, &m);
    CHECK_EQ_INT(m.cmd, MW_LINK_RSP_ACK);
    CHECK(!mw_link_outbox_pending(MW_FILE_KIND_SIGNED_TX, NULL));
    CHECK(!mw_link_outbox_pending(MW_FILE_KIND_KEYIMAGES, NULL));

    // Full-size file both ways.
    fill_pattern(file, MW_LINK_MAX_PAYLOAD, 45);
    roundtrip(MW_LINK_CMD_PUT, MW_FILE_KIND_UNSIGNED_TX, file, MW_LINK_MAX_PAYLOAD,
              req, sizeof req, rsp, sizeof rsp, &m);
    CHECK_EQ_INT(m.cmd, MW_LINK_RSP_ACK);
    CHECK_EQ_INT(mw_link_inbox_take(MW_FILE_KIND_UNSIGNED_TX, back, sizeof back, &len), MW_OK);
    CHECK_EQ_INT(len, MW_LINK_MAX_PAYLOAD);
    CHECK_EQ_MEM(back, file, MW_LINK_MAX_PAYLOAD);
    CHECK_EQ_INT(mw_link_outbox_put(MW_FILE_KIND_SIGNED_TX, file, MW_LINK_MAX_PAYLOAD), MW_OK);
    size_t r = roundtrip(MW_LINK_CMD_GET, MW_FILE_KIND_SIGNED_TX, NULL, 0,
                         req, sizeof req, rsp, sizeof rsp, &m);
    CHECK_EQ_INT(r, MW_LINK_MAX_MSG);
    CHECK_EQ_INT(m.len, MW_LINK_MAX_PAYLOAD);
    CHECK_EQ_MEM(m.payload, file, MW_LINK_MAX_PAYLOAD);

    // Over the limit is refused by the store as well.
    CHECK_EQ_INT(mw_link_outbox_put(MW_FILE_KIND_SIGNED_TX, file, 0), MW_ERR_INVALID_ARG);

    mw_link_deinit();
}

MW_TEST(test_dispatch_errors) {
    static uint8_t req[MW_LINK_MAX_MSG], rsp[MW_LINK_MAX_MSG];
    mw_link_msg_t m;
    size_t n = 0;
    CHECK_EQ_INT(mw_link_init(), MW_OK);

    // Unknown command.
    roundtrip(0x77, 0, NULL, 0, req, sizeof req, rsp, sizeof rsp, &m);
    CHECK_EQ_INT(m.cmd, MW_LINK_RSP_ERROR);
    CHECK_EQ_INT(m.arg, MW_LINK_ERR_BAD_CMD);

    // Bad kinds.
    mw_link_set_state(MW_LINK_STATE_WALLET, 0x1F);
    roundtrip(MW_LINK_CMD_PUT, MW_LINK_FILE_KINDS, (const uint8_t*)"x", 1, req, sizeof req, rsp, sizeof rsp, &m);
    CHECK_EQ_INT(m.arg, MW_LINK_ERR_BAD_KIND);
    roundtrip(MW_LINK_CMD_GET, 0xFE, NULL, 0, req, sizeof req, rsp, sizeof rsp, &m);
    CHECK_EQ_INT(m.arg, MW_LINK_ERR_BAD_KIND);
    roundtrip(MW_LINK_CMD_CLEAR, 9, NULL, 0, req, sizeof req, rsp, sizeof rsp, &m);
    CHECK_EQ_INT(m.arg, MW_LINK_ERR_BAD_KIND);

    // Empty PUT.
    roundtrip(MW_LINK_CMD_PUT, 0, NULL, 0, req, sizeof req, rsp, sizeof rsp, &m);
    CHECK_EQ_INT(m.cmd, MW_LINK_RSP_ERROR);
    CHECK_EQ_INT(m.arg, MW_LINK_ERR_BAD_LEN);
    CHECK(!mw_link_inbox_pending(0, NULL));

    // Corrupted frames get an ERROR reply rather than silence.
    CHECK_EQ_INT(mw_link_msg_build(MW_LINK_CMD_STATUS, 0, NULL, 0, req, sizeof req, &n), MW_OK);
    req[10] ^= 0xFF;                                    // arg: header CRC breaks
    size_t r = mw_link_handle(req, n, rsp, sizeof rsp);
    CHECK(r > 0);
    CHECK_EQ_INT(mw_link_msg_parse(rsp, r, &m), MW_OK);
    CHECK_EQ_INT(m.cmd, MW_LINK_RSP_ERROR);
    CHECK_EQ_INT(m.arg, MW_LINK_ERR_CRC);
    req[10] ^= 0xFF;
    r = mw_link_handle(req, n - 2, rsp, sizeof rsp);
    CHECK_EQ_INT(mw_link_msg_parse(rsp, r, &m), MW_OK);
    CHECK_EQ_INT(m.arg, MW_LINK_ERR_BAD_LEN);
    req[1] = 'w';
    r = mw_link_handle(req, n, rsp, sizeof rsp);
    CHECK_EQ_INT(mw_link_msg_parse(rsp, r, &m), MW_OK);
    CHECK_EQ_INT(m.arg, MW_LINK_ERR_BAD_MAGIC);
    req[1] = 'W';

    // A reply buffer too small for the file: ERROR, not a truncated FILE.
    static uint8_t file[3000];
    CHECK_EQ_INT(mw_link_outbox_put(MW_FILE_KIND_SIGNED_TX, file, sizeof file), MW_OK);
    CHECK_EQ_INT(mw_link_msg_build(MW_LINK_CMD_GET, MW_FILE_KIND_SIGNED_TX, NULL, 0, req, sizeof req, &n), MW_OK);
    r = mw_link_handle(req, n, rsp, 100);
    CHECK(r > 0 && r <= 100);
    CHECK_EQ_INT(mw_link_msg_parse(rsp, r, &m), MW_OK);
    CHECK_EQ_INT(m.cmd, MW_LINK_RSP_ERROR);
    CHECK_EQ_INT(m.arg, MW_LINK_ERR_NO_MEMORY);

    // Names never return NULL.
    for (int c = 0; c < 256; ++c) CHECK(mw_link_cmd_name((uint8_t)c) != NULL);
    for (int c = 0; c < 256; ++c) CHECK(mw_link_err_name((uint8_t)c) != NULL);
    CHECK_EQ_STR(mw_link_cmd_name(MW_LINK_CMD_PUT), "PUT");
    CHECK_EQ_STR(mw_link_err_name(MW_LINK_ERR_NOT_READY), "not ready");

    mw_link_deinit();
    // After deinit the dispatcher still answers, with "not ready".
    CHECK_EQ_INT(mw_link_msg_build(MW_LINK_CMD_STATUS, 0, NULL, 0, req, sizeof req, &n), MW_OK);
    r = mw_link_handle(req, n, rsp, sizeof rsp);
    CHECK_EQ_INT(mw_link_msg_parse(rsp, r, &m), MW_OK);
    CHECK_EQ_INT(m.cmd, MW_LINK_RSP_ERROR);
    CHECK_EQ_INT(m.arg, MW_LINK_ERR_NOT_READY);
}

// ---------------------------------------------------------------------------
// Protocol v2: auto-classified PUT, state gating, host requests
// ---------------------------------------------------------------------------
static int s_events = 0;
static void event_hook(void* ctx) { (void)ctx; s_events++; }

static int classify(const uint8_t* d, size_t n, char* why, size_t cap) {
    if (n >= 3 && memcmp(d, "OUT", 3) == 0) return MW_FILE_KIND_OUTPUTS;
    if (n >= 3 && memcmp(d, "UNS", 3) == 0) return MW_FILE_KIND_UNSIGNED_TX;
    if (n >= 3 && memcmp(d, "KEY", 3) == 0) return MW_FILE_KIND_KEYIMAGES;
    snprintf(why, cap, "unknown test file");
    return -1;
}

MW_TEST(test_dispatch_v2) {
    static uint8_t req[MW_LINK_MAX_MSG], rsp[MW_LINK_MAX_MSG];
    mw_link_msg_t m;
    size_t len = 0;
    CHECK_EQ_INT(mw_link_init(), MW_OK);
    mw_link_set_event_hook(event_hook, NULL);
    s_events = 0;

    // Locked: nothing is accepted, and the reason says why.
    mw_link_set_state(MW_LINK_STATE_LOCKED, 0);
    roundtrip(MW_LINK_CMD_PUT, MW_FILE_KIND_OUTPUTS, (const uint8_t*)"OUTx", 4, req,
              sizeof req, rsp, sizeof rsp, &m);
    CHECK_EQ_INT(m.cmd, MW_LINK_RSP_ERROR);
    CHECK_EQ_INT(m.arg, MW_LINK_ERR_LOCKED);
    CHECK(m.len > 10);
    roundtrip(MW_LINK_CMD_REQ, MW_LINK_REQ_ADDRESS, NULL, 0, req, sizeof req, rsp, sizeof rsp, &m);
    CHECK_EQ_INT(m.arg, MW_LINK_ERR_LOCKED);
    CHECK_EQ_INT(s_events, 0);

    // Wallet open: outputs + unsigned accepted, classified by content.
    mw_link_set_state(MW_LINK_STATE_WALLET,
                      (1u << MW_FILE_KIND_OUTPUTS) | (1u << MW_FILE_KIND_UNSIGNED_TX));
    roundtrip(MW_LINK_CMD_STATUS, 0, NULL, 0, req, sizeof req, rsp, sizeof rsp, &m);
    const uint32_t seq0 = rd32(m.payload + 44);

    // No classifier installed yet.
    roundtrip(MW_LINK_CMD_PUT, MW_LINK_KIND_AUTO, (const uint8_t*)"UNSx", 4, req,
              sizeof req, rsp, sizeof rsp, &m);
    CHECK_EQ_INT(m.arg, MW_LINK_ERR_BAD_FORMAT);

    mw_link_set_classifier(classify);
    roundtrip(MW_LINK_CMD_PUT, MW_LINK_KIND_AUTO, (const uint8_t*)"UNSx", 4, req,
              sizeof req, rsp, sizeof rsp, &m);
    CHECK_EQ_INT(m.cmd, MW_LINK_RSP_ACK);
    CHECK_EQ_INT(m.arg, MW_FILE_KIND_UNSIGNED_TX);
    CHECK_EQ_INT(s_events, 1);
    CHECK_EQ_INT(mw_link_inbox_any(&len), MW_FILE_KIND_UNSIGNED_TX);
    CHECK_EQ_INT(len, 4);

    // Unknown content: refused with the classifier's reason.
    roundtrip(MW_LINK_CMD_PUT, MW_LINK_KIND_AUTO, (const uint8_t*)"ZIPx", 4, req,
              sizeof req, rsp, sizeof rsp, &m);
    CHECK_EQ_INT(m.arg, MW_LINK_ERR_BAD_FORMAT);
    CHECK(m.len == strlen("unknown test file") &&
          memcmp(m.payload, "unknown test file", m.len) == 0);

    // A known kind the device does not accept right now.
    roundtrip(MW_LINK_CMD_PUT, MW_LINK_KIND_AUTO, (const uint8_t*)"KEYx", 4, req,
              sizeof req, rsp, sizeof rsp, &m);
    CHECK_EQ_INT(m.arg, MW_LINK_ERR_LOCKED);

    // STATUS reports the file and a bumped sequence number.
    roundtrip(MW_LINK_CMD_STATUS, 0, NULL, 0, req, sizeof req, rsp, sizeof rsp, &m);
    CHECK_EQ_INT(rd32(m.payload + 4 * MW_FILE_KIND_UNSIGNED_TX), 4);
    CHECK(rd32(m.payload + 44) != seq0);
    mw_link_inbox_clear(MW_FILE_KIND_UNSIGNED_TX);
    CHECK_EQ_INT(mw_link_inbox_any(NULL), -1);

    // Requests: queued once, visible in STATUS, taken by the firmware.
    roundtrip(MW_LINK_CMD_REQ, 9, NULL, 0, req, sizeof req, rsp, sizeof rsp, &m);
    CHECK_EQ_INT(m.arg, MW_LINK_ERR_BAD_CMD);
    roundtrip(MW_LINK_CMD_REQ, MW_LINK_REQ_VIEWONLY, NULL, 0, req, sizeof req, rsp, sizeof rsp, &m);
    CHECK_EQ_INT(m.cmd, MW_LINK_RSP_ACK);
    CHECK_EQ_INT(s_events, 2);
    roundtrip(MW_LINK_CMD_REQ, MW_LINK_REQ_ADDRESS, NULL, 0, req, sizeof req, rsp, sizeof rsp, &m);
    CHECK_EQ_INT(m.arg, MW_LINK_ERR_BUSY);
    roundtrip(MW_LINK_CMD_STATUS, 0, NULL, 0, req, sizeof req, rsp, sizeof rsp, &m);
    CHECK_EQ_INT(m.payload[41], MW_LINK_REQ_VIEWONLY);
    CHECK_EQ_INT(mw_link_request_peek(), MW_LINK_REQ_VIEWONLY);
    CHECK_EQ_INT(mw_link_request_take(), MW_LINK_REQ_VIEWONLY);
    CHECK_EQ_INT(mw_link_request_take(), 0);

    // The answer goes to the WALLET_EXPORT slot.
    CHECK_EQ_INT(mw_link_outbox_put(MW_FILE_KIND_WALLET_EXPORT, (const uint8_t*)"{}", 2), MW_OK);
    roundtrip(MW_LINK_CMD_GET, MW_FILE_KIND_WALLET_EXPORT, NULL, 0, req, sizeof req, rsp,
              sizeof rsp, &m);
    CHECK_EQ_INT(m.cmd, MW_LINK_RSP_FILE);
    CHECK_EQ_INT(m.len, 2);

    // Leaving the wallet drops a pending request.
    roundtrip(MW_LINK_CMD_REQ, MW_LINK_REQ_ADDRESS, NULL, 0, req, sizeof req, rsp, sizeof rsp, &m);
    mw_link_set_state(MW_LINK_STATE_MENU, 0);
    CHECK_EQ_INT(mw_link_request_peek(), 0);

    CHECK_EQ_STR(mw_link_cmd_name(MW_LINK_CMD_REQ), "REQ");
    mw_link_set_classifier(NULL);
    mw_link_set_event_hook(NULL, NULL);
    mw_link_deinit();
}

// End to end: frame on one side, receive on the other, dispatch, frame the
// reply, receive it - for both transports and every file kind.
MW_TEST(test_end_to_end_both_transports) {
    static uint8_t rx_s_buf[MW_LINK_MAX_MSG + MW_LINK_MAX_MSG / 254 + 4];
    static uint8_t rx_h_buf[MW_LINK_MAX_MSG];
    static uint8_t wire[MW_LINK_MAX_MSG + MW_LINK_MAX_MSG / 254 + 4];
    static uint8_t req[MW_LINK_MAX_MSG], rsp[MW_LINK_MAX_MSG];
    static uint8_t file[MW_LINK_MAX_PAYLOAD], back[MW_LINK_MAX_PAYLOAD];
    mw_link_rx_t rx_dev_s, rx_dev_h, rx_host_s, rx_host_h;
    mw_link_msg_t m;
    size_t n = 0, len = 0;

    CHECK_EQ_INT(mw_link_init(), MW_OK);
    mw_link_set_state(MW_LINK_STATE_WALLET, 0x1F);
    mw_link_rx_init(&rx_dev_s,  MW_LINK_TRANSPORT_SERIAL, rx_s_buf, sizeof rx_s_buf);
    mw_link_rx_init(&rx_host_s, MW_LINK_TRANSPORT_SERIAL, rx_s_buf, sizeof rx_s_buf);
    mw_link_rx_init(&rx_dev_h,  MW_LINK_TRANSPORT_HID, rx_h_buf, sizeof rx_h_buf);
    mw_link_rx_init(&rx_host_h, MW_LINK_TRANSPORT_HID, rx_h_buf, sizeof rx_h_buf);

    const size_t sizes[] = { 1, 61, 4097, MW_LINK_MAX_PAYLOAD };
    for (int transport = 0; transport < 2; ++transport) {
        for (int kind = 0; kind < MW_LINK_FILE_KINDS; ++kind) {
            for (size_t s = 0; s < sizeof sizes / sizeof sizes[0]; ++s) {
                fill_pattern(file, sizes[s], (uint32_t)(kind * 10 + (int)s + transport));
                mw_link_rx_t* rx_dev  = transport ? &rx_dev_h  : &rx_dev_s;
                mw_link_rx_t* rx_host = transport ? &rx_host_h : &rx_host_s;

                // host -> device PUT
                CHECK_EQ_INT(mw_link_msg_build(MW_LINK_CMD_PUT, (uint8_t)kind, file,
                                               (uint32_t)sizes[s], req, sizeof req, &n), MW_OK);
                bool ready = transport ? hid_deliver(rx_dev, req, n)
                                       : serial_deliver(rx_dev, req, n, wire, sizeof wire, 4096);
                CHECK(ready);
                size_t r = mw_link_handle(rx_dev->buf, rx_dev->len, rsp, sizeof rsp);
                mw_link_rx_reset(rx_dev);
                // device -> host ACK
                ready = transport ? hid_deliver(rx_host, rsp, r)
                                  : serial_deliver(rx_host, rsp, r, wire, sizeof wire, 4096);
                CHECK(ready);
                CHECK_EQ_INT(mw_link_msg_parse(rx_host->buf, rx_host->len, &m), MW_OK);
                mw_link_rx_reset(rx_host);
                CHECK_EQ_INT(m.cmd, MW_LINK_RSP_ACK);

                // firmware consumes and answers with the same bytes reversed
                CHECK_EQ_INT(mw_link_inbox_take((mw_file_kind_id_t)kind, back, sizeof back, &len), MW_OK);
                CHECK_EQ_INT(len, sizes[s]);
                CHECK_EQ_MEM(back, file, sizes[s]);
                for (size_t i = 0; i < len / 2; ++i) {
                    uint8_t t = back[i]; back[i] = back[len - 1 - i]; back[len - 1 - i] = t;
                }
                CHECK_EQ_INT(mw_link_outbox_put((mw_file_kind_id_t)kind, back, len), MW_OK);

                // host -> device GET, device -> host FILE
                CHECK_EQ_INT(mw_link_msg_build(MW_LINK_CMD_GET, (uint8_t)kind, NULL, 0, req, sizeof req, &n), MW_OK);
                ready = transport ? hid_deliver(rx_dev, req, n)
                                  : serial_deliver(rx_dev, req, n, wire, sizeof wire, 4096);
                CHECK(ready);
                r = mw_link_handle(rx_dev->buf, rx_dev->len, rsp, sizeof rsp);
                mw_link_rx_reset(rx_dev);
                ready = transport ? hid_deliver(rx_host, rsp, r)
                                  : serial_deliver(rx_host, rsp, r, wire, sizeof wire, 4096);
                CHECK(ready);
                CHECK_EQ_INT(mw_link_msg_parse(rx_host->buf, rx_host->len, &m), MW_OK);
                CHECK_EQ_INT(m.cmd, MW_LINK_RSP_FILE);
                CHECK_EQ_INT(m.arg, kind);
                CHECK_EQ_INT(m.len, sizes[s]);
                CHECK_EQ_MEM(m.payload, back, sizes[s]);
                mw_link_rx_reset(rx_host);
                mw_link_outbox_clear((mw_file_kind_id_t)kind);
            }
        }
    }
    mw_link_deinit();
}

// ---------------------------------------------------------------------------
// transfer.c channel
// ---------------------------------------------------------------------------
static int  s_hook_calls = 0;
static int  s_hook_abort_after = -1;
static bool wait_hook(uint32_t elapsed_ms, void* ctx) {
    (void)elapsed_ms; (void)ctx;
    s_hook_calls++;
    return s_hook_abort_after < 0 || s_hook_calls <= s_hook_abort_after;
}

MW_TEST(test_transfer_channel) {
    static uint8_t req[MW_LINK_MAX_MSG], rsp[MW_LINK_MAX_MSG];
    static uint8_t file[MW_LINK_MAX_PAYLOAD], back[MW_LINK_MAX_PAYLOAD];
    mw_link_msg_t m;
    size_t len = 0;

    CHECK_EQ_INT(mw_hal_init(), MW_OK);
    (void)mw_transfer_init();           // SD availability is not this test's business
    CHECK_EQ_INT(mw_link_init(), MW_OK);
    mw_link_set_state(MW_LINK_STATE_WALLET, 0x1F);

    // Not up until the driver says so.
    mw_link_set_up(false, 0);
    CHECK(!mw_transfer_available(MW_CHANNEL_USB_LINK));
    mw_link_set_up(true, MW_LINK_CAP_SERIAL);
    CHECK(mw_transfer_available(MW_CHANNEL_USB_LINK));
    CHECK_EQ_INT(mw_link_caps(), MW_LINK_CAP_SERIAL);

    // Host PUTs first, the flow receives without waiting.
    fill_pattern(file, 2222, 77);
    roundtrip(MW_LINK_CMD_PUT, MW_FILE_KIND_OUTPUTS, file, 2222, req, sizeof req, rsp, sizeof rsp, &m);
    CHECK_EQ_INT(m.cmd, MW_LINK_RSP_ACK);
    s_hook_calls = 0; s_hook_abort_after = -1;
    mw_link_set_wait_hook(wait_hook, NULL);
    CHECK_EQ_INT(mw_transfer_receive(MW_CHANNEL_USB_LINK, MW_FILE_KIND_OUTPUTS, back, sizeof back, &len), MW_OK);
    CHECK_EQ_INT(len, 2222);
    CHECK_EQ_MEM(back, file, 2222);
    CHECK_EQ_INT(s_hook_calls, 0);

    // Nothing there: the hook aborts after two polls.
    s_hook_calls = 0; s_hook_abort_after = 2;
    CHECK_EQ_INT(mw_transfer_receive(MW_CHANNEL_USB_LINK, MW_FILE_KIND_OUTPUTS, back, sizeof back, &len), MW_ERR_ABORTED);
    CHECK_EQ_INT(s_hook_calls, 3);

    // Timeout without a hook.
    mw_link_set_wait_hook(NULL, NULL);
    uint32_t t0 = mw_millis();
    CHECK_EQ_INT(mw_link_wait_inbox(MW_FILE_KIND_UNSIGNED_TX, back, sizeof back, &len, 60), MW_ERR_IO);
    CHECK(mw_millis() - t0 >= 40);

    // A file that does not fit the flow's buffer is reported, not dropped.
    fill_pattern(file, 5000, 78);
    roundtrip(MW_LINK_CMD_PUT, MW_FILE_KIND_UNSIGNED_TX, file, 5000, req, sizeof req, rsp, sizeof rsp, &m);
    CHECK_EQ_INT(mw_transfer_receive(MW_CHANNEL_USB_LINK, MW_FILE_KIND_UNSIGNED_TX, back, 4000, &len), MW_ERR_TOO_MANY);
    CHECK(mw_link_inbox_pending(MW_FILE_KIND_UNSIGNED_TX, NULL));
    CHECK_EQ_INT(mw_transfer_receive(MW_CHANNEL_USB_LINK, MW_FILE_KIND_UNSIGNED_TX, back, sizeof back, &len), MW_OK);
    CHECK_EQ_INT(len, 5000);

    // Send parks the file for GET.
    fill_pattern(file, 777, 79);
    CHECK_EQ_INT(mw_transfer_send(MW_CHANNEL_USB_LINK, MW_FILE_KIND_SIGNED_TX, file, 777), MW_OK);
    roundtrip(MW_LINK_CMD_GET, MW_FILE_KIND_SIGNED_TX, NULL, 0, req, sizeof req, rsp, sizeof rsp, &m);
    CHECK_EQ_INT(m.cmd, MW_LINK_RSP_FILE);
    CHECK_EQ_INT(m.len, 777);
    CHECK_EQ_MEM(m.payload, file, 777);

    // Argument checks at the transfer layer still apply.
    CHECK_EQ_INT(mw_transfer_send(MW_CHANNEL_USB_LINK, MW_FILE_KIND_SIGNED_TX, file, 0), MW_ERR_INVALID_ARG);
    CHECK_EQ_INT(mw_transfer_receive(MW_CHANNEL_USB_LINK, (mw_file_kind_id_t)7, back, sizeof back, &len), MW_ERR_INVALID_ARG);

    mw_link_deinit();
    CHECK(!mw_transfer_available(MW_CHANNEL_USB_LINK));
    mw_hal_deinit();
}

// ---------------------------------------------------------------------------
// v5: HID frame start, busy refusal, crash diagnostics in INFO
// ---------------------------------------------------------------------------
// A continuation whose data begins with "##" is part of the frame, not the
// start of a new one (the receiver needs "?##" + magic + header CRC).
MW_TEST(test_hid_rx_continuation_starting_with_hashes) {
    static uint8_t rxbuf[MW_LINK_MAX_MSG];
    uint8_t msg[300], pl[250];
    size_t n = 0;
    fill_pattern(pl, sizeof pl, 17);
    // The first continuation carries msg[60..121] = pl[40..101]
    // (header is MW_LINK_HDR_LEN = 20 bytes).
    pl[40] = '#'; pl[41] = '#';
    // The second one starts with "##M" but not the magic.
    pl[102] = '#'; pl[103] = '#'; pl[104] = 'M'; pl[105] = 'X';
    CHECK_EQ_INT(mw_link_msg_build(MW_LINK_CMD_PUT, 0, pl, sizeof pl, msg, sizeof msg, &n), MW_OK);
    uint8_t rep[MW_LINK_HID_DATA];
    mw_link_hid_report(msg, n, 1, rep);
    CHECK(rep[0] == '?' && rep[1] == '#' && rep[2] == '#');
    mw_link_rx_t rx;
    mw_link_rx_init(&rx, MW_LINK_TRANSPORT_HID, rxbuf, sizeof rxbuf);
    CHECK(hid_deliver(&rx, msg, n));
    CHECK_EQ_INT(rx.dropped, 0);
    CHECK_EQ_INT(rx.len, n);
    CHECK_EQ_MEM(rx.buf, msg, n);
}

// Protocol 3: even the whole 8-byte magic right after "##" in a
// continuation (the old collision, made worse) does not restart the
// receiver, because the header CRC that follows it does not match.
MW_TEST(test_hid_rx_continuation_with_full_magic) {
    static uint8_t rxbuf[MW_LINK_MAX_MSG];
    uint8_t msg[400], pl[300];
    size_t n = 0;
    fill_pattern(pl, sizeof pl, 31);
    // First continuation carries msg[60..121] = pl[40..101]: put "##" + magic
    // + a plausible-looking but wrong header there.
    pl[40] = '#'; pl[41] = '#';
    memcpy(pl + 42, mw_link_magic, MW_LINK_MAGIC_LEN);
    pl[50] = MW_LINK_PROTO_VERSION; pl[51] = MW_LINK_CMD_PING;
    pl[52] = 0; pl[53] = 0; wr32(pl + 54, 4); wr32(pl + 58, 0xDEADBEEF);
    CHECK_EQ_INT(mw_link_msg_build(MW_LINK_CMD_PUT, 0, pl, sizeof pl, msg, sizeof msg, &n), MW_OK);
    uint8_t rep[MW_LINK_HID_DATA];
    mw_link_hid_report(msg, n, 1, rep);
    CHECK(rep[0] == '?' && rep[1] == '#' && rep[2] == '#');
    CHECK_EQ_MEM(rep + 3, mw_link_magic, MW_LINK_MAGIC_LEN);
    mw_link_rx_t rx;
    mw_link_rx_init(&rx, MW_LINK_TRANSPORT_HID, rxbuf, sizeof rxbuf);
    CHECK(hid_deliver(&rx, msg, n));
    CHECK_EQ_INT(rx.dropped, 0);
    CHECK_EQ_INT(rx.len, n);
    CHECK_EQ_MEM(rx.buf, msg, n);
}

// After a lost report the receiver resynchronises on the next valid start.
MW_TEST(test_hid_rx_resync_on_magic) {
    static uint8_t rxbuf[MW_LINK_MAX_MSG];
    uint8_t a[400], b[100], pl[380];
    size_t na = 0, nb = 0, used = 0;
    fill_pattern(pl, sizeof pl, 23);
    CHECK_EQ_INT(mw_link_msg_build(MW_LINK_CMD_PUT, 0, pl, sizeof pl, a, sizeof a, &na), MW_OK);
    CHECK_EQ_INT(mw_link_msg_build(MW_LINK_CMD_PING, 7, pl, 40, b, sizeof b, &nb), MW_OK);
    mw_link_rx_t rx;
    mw_link_rx_init(&rx, MW_LINK_TRANSPORT_HID, rxbuf, sizeof rxbuf);
    uint8_t rep[MW_LINK_HID_DATA];
    // Frame A loses its last reports.
    for (size_t i = 0; i < 3; ++i) {
        mw_link_hid_report(a, na, i, rep);
        CHECK(!mw_link_rx_feed(&rx, rep, sizeof rep, &used));
    }
    CHECK(rx.in_frame);
    // Frame B arrives whole: A is abandoned, B is received.
    CHECK(hid_deliver(&rx, b, nb));
    CHECK_EQ_INT(rx.dropped, 1);
    CHECK_EQ_INT(rx.len, nb);
    CHECK_EQ_MEM(rx.buf, b, nb);
    mw_link_rx_reset(&rx);
    // "?##" without the magic and no frame open: a stray report.
    memset(rep, 0, sizeof rep); rep[0] = '?'; rep[1] = '#'; rep[2] = '#'; rep[3] = 'M';
    CHECK(!mw_link_rx_feed(&rx, rep, sizeof rep, &used));
    CHECK(!rx.in_frame);
    CHECK_EQ_INT(rx.dropped, 2);
}

// A PUT while the device is busy with the previous file says so, instead of
// "not accepted".
MW_TEST(test_dispatch_busy_refusal) {
    static uint8_t req[MW_LINK_MAX_MSG], rsp[MW_LINK_MAX_MSG];
    mw_link_msg_t m;
    CHECK_EQ_INT(mw_link_init(), MW_OK);
    mw_link_set_classifier(classify);
    mw_link_set_state(MW_LINK_STATE_BUSY, 0);
    roundtrip(MW_LINK_CMD_PUT, MW_LINK_KIND_AUTO, (const uint8_t*)"OUTx", 4, req,
              sizeof req, rsp, sizeof rsp, &m);
    CHECK_EQ_INT(m.cmd, MW_LINK_RSP_ERROR);
    CHECK_EQ_INT(m.arg, MW_LINK_ERR_BUSY);
    CHECK(m.len > 10 && memmem_simple(m.payload, m.len, "busy"));
    CHECK_EQ_INT(mw_link_inbox_any(NULL), -1);
    // Unknown content is still reported as such.
    roundtrip(MW_LINK_CMD_PUT, MW_LINK_KIND_AUTO, (const uint8_t*)"ZIPx", 4, req,
              sizeof req, rsp, sizeof rsp, &m);
    CHECK_EQ_INT(m.arg, MW_LINK_ERR_BAD_FORMAT);
    // Back in the wallet: a kind outside the mask is "not accepted".
    mw_link_set_state(MW_LINK_STATE_WALLET, 1u << MW_FILE_KIND_UNSIGNED_TX);
    roundtrip(MW_LINK_CMD_PUT, MW_LINK_KIND_AUTO, (const uint8_t*)"OUTx", 4, req,
              sizeof req, rsp, sizeof rsp, &m);
    CHECK_EQ_INT(m.arg, MW_LINK_ERR_LOCKED);
    CHECK_EQ_STR(mw_link_err_name(MW_LINK_ERR_LOCKED), "not accepted");
    CHECK_EQ_STR(mw_link_err_name(MW_LINK_ERR_BUSY), "busy");
    mw_link_set_classifier(NULL);
    mw_link_deinit();
}

static uint8_t s_diag_unlocked;
static void diag_info_provider(mw_link_info_t* out, void* ctx) {
    (void)ctx;
    out->unlocked = s_diag_unlocked;
    out->reset_reason = mw_hal_reset_reason();
    uint8_t op = 0, stage = 0;
    if (mw_hal_last_crash(&op, &stage)) {
        out->crash_op = op;
        out->crash_stage = stage;
        out->crash_flags = MW_LINK_CRASH_VALID | MW_LINK_CRASH_STACK;
        out->crash_stack_free = 0x1234;
    }
}

MW_TEST(test_info_crash_fields) {
    static uint8_t req[MW_LINK_MAX_MSG], rsp[MW_LINK_MAX_MSG];
    mw_link_msg_t m;
    CHECK_EQ_INT(mw_link_init(), MW_OK);
    mw_link_set_info_provider(diag_info_provider, NULL);

    // A crash during CLSAG, then a panic reset.
    mw_hal_crumb_set(MW_CRUMB_OP_SIGN, MW_CRUMB_STAGE_CLSAG);
    mw_host_simulate_reset(MW_RESET_PANIC);
    uint8_t op = 0, stage = 0;
    CHECK(mw_hal_last_crash(&op, &stage));
    CHECK_EQ_INT(op, MW_CRUMB_OP_SIGN);
    CHECK_EQ_INT(stage, MW_CRUMB_STAGE_CLSAG);

    // Locked: the reset reason only.
    s_diag_unlocked = 0;
    mw_link_set_state(MW_LINK_STATE_LOCKED, 0);
    roundtrip(MW_LINK_CMD_INFO, 0, NULL, 0, req, sizeof req, rsp, sizeof rsp, &m);
    CHECK_EQ_INT(m.payload[92], MW_RESET_PANIC);
    for (int i = 93; i < MW_LINK_INFO_WIRE_LEN; ++i) CHECK_EQ_INT(m.payload[i], 0);

    // Unlocked: what the device was doing.
    s_diag_unlocked = 1;
    mw_link_set_state(MW_LINK_STATE_MENU, 0);
    roundtrip(MW_LINK_CMD_INFO, 0, NULL, 0, req, sizeof req, rsp, sizeof rsp, &m);
    CHECK_EQ_INT(m.payload[92], MW_RESET_PANIC);
    CHECK_EQ_INT(m.payload[93], MW_CRUMB_OP_SIGN);
    CHECK_EQ_INT(m.payload[94], MW_CRUMB_STAGE_CLSAG);
    CHECK_EQ_INT(m.payload[95], MW_LINK_CRASH_VALID | MW_LINK_CRASH_STACK);
    CHECK_EQ_INT(m.payload[96], 0x34);
    CHECK_EQ_INT(m.payload[97], 0x12);
    for (int i = 98; i < MW_LINK_INFO_WIRE_LEN; ++i) CHECK_EQ_INT(m.payload[i], 0);

    // Forgotten after it was shown; a clean restart records nothing.
    mw_hal_last_crash_forget();
    CHECK(!mw_hal_last_crash(NULL, NULL));
    mw_hal_crumb_set(MW_CRUMB_OP_KEYIMAGES, MW_CRUMB_STAGE_KEYS);
    mw_host_simulate_reset(MW_RESET_SOFTWARE);
    CHECK(!mw_hal_last_crash(NULL, NULL));
    CHECK_EQ_INT(mw_hal_reset_reason(), MW_RESET_SOFTWARE);
    // A cleared crumb is not reported after a watchdog reset either.
    mw_hal_crumb_set(MW_CRUMB_OP_SIGN, MW_CRUMB_STAGE_BPP);
    mw_hal_crumb_clear();
    mw_host_simulate_reset(MW_RESET_TASK_WDT);
    CHECK(!mw_hal_last_crash(NULL, NULL));
    roundtrip(MW_LINK_CMD_INFO, 0, NULL, 0, req, sizeof req, rsp, sizeof rsp, &m);
    CHECK_EQ_INT(m.payload[92], MW_RESET_TASK_WDT);
    CHECK_EQ_INT(m.payload[95], 0);
    CHECK(mw_stack_free_min() == UINT32_MAX);

    mw_host_simulate_reset(MW_RESET_POWERON);
    mw_link_set_info_provider(NULL, NULL);
    mw_link_deinit();
}

int main(void) {
    RUN_TEST(test_cobs_vectors);
    RUN_TEST(test_cobs_long_runs);
    RUN_TEST(test_cobs_random_inplace);
    RUN_TEST(test_cobs_malformed);
    RUN_TEST(test_msg_build_parse);
    RUN_TEST(test_msg_parse_rejects);
    RUN_TEST(test_hid_report_count);
    RUN_TEST(test_hid_report_layout);
    RUN_TEST(test_hid_rx_reassembly);
    RUN_TEST(test_hid_rx_hostile);
    RUN_TEST(test_serial_rx_chunking);
    RUN_TEST(test_serial_rx_two_frames_one_chunk);
    RUN_TEST(test_serial_rx_resync);
    RUN_TEST(test_dispatch_ping_info_status);
    RUN_TEST(test_dispatch_put_get_clear);
    RUN_TEST(test_dispatch_errors);
    RUN_TEST(test_dispatch_v2);
    RUN_TEST(test_end_to_end_both_transports);
    RUN_TEST(test_transfer_channel);
    RUN_TEST(test_hid_rx_continuation_starting_with_hashes);
    RUN_TEST(test_hid_rx_continuation_with_full_magic);
    RUN_TEST(test_hid_rx_resync_on_magic);
    RUN_TEST(test_dispatch_busy_refusal);
    RUN_TEST(test_info_crash_fields);
    return mw_test_summary();
}
