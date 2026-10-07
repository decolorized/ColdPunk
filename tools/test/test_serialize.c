// Varint / cursor / boost portable-archive primitives.
//
// These are the first thing an attacker's file touches, so the negative cases
// matter more than the positive ones: overlong varints, 64-bit overflow, reads
// past the end and a sticky overflow flag that cannot be cleared by a later
// successful-looking read.
#include "test_framework.h"

#include "monero/serialize.h"

MW_TEST(test_varint_round_trip)
{
    static const uint64_t values[] = {
        0, 1, 2, 63, 127, 128, 129, 255, 256, 16383, 16384, 0xffff,
        0x1fffff, 0x200000, 0xffffffffULL, 0x100000000ULL,
        0x7fffffffffffffffULL, 0xffffffffffffffffULL,
        1000000000000ULL,                      // 1 XMR in atomic units
    };
    for (size_t i = 0; i < sizeof(values) / sizeof(values[0]); ++i) {
        uint8_t buf[10];
        size_t n = mw_varint_encode(values[i], buf);
        CHECK(n >= 1 && n <= 10);
        CHECK_EQ_INT(n, mw_varint_size(values[i]));

        mw_reader_t r;
        mw_reader_init(&r, buf, n);
        uint64_t got = 0;
        CHECK(mw_read_varint(&r, &got));
        CHECK(got == values[i]);
        CHECK_EQ_INT(r.pos, n);
        CHECK_EQ_INT(mw_remaining(&r), 0);
        CHECK(!r.overflow);
    }
}

MW_TEST(test_varint_known_encodings)
{
    uint8_t buf[10];
    CHECK_EQ_INT(mw_varint_encode(0, buf), 1);
    CHECK_EQ_INT(buf[0], 0x00);
    CHECK_EQ_INT(mw_varint_encode(127, buf), 1);
    CHECK_EQ_INT(buf[0], 0x7f);
    CHECK_EQ_INT(mw_varint_encode(128, buf), 2);
    CHECK_EQ_INT(buf[0], 0x80);
    CHECK_EQ_INT(buf[1], 0x01);
    CHECK_EQ_INT(mw_varint_encode(300, buf), 2);
    CHECK_EQ_INT(buf[0], 0xac);
    CHECK_EQ_INT(buf[1], 0x02);
    CHECK_EQ_INT(mw_varint_encode(UINT64_MAX, buf), 10);
}

MW_TEST(test_varint_rejects_non_canonical)
{
    // 0x80 0x00 == "0" written in two bytes: Monero rejects it.
    const uint8_t overlong[] = { 0x80, 0x00 };
    mw_reader_t r;
    uint64_t v = 0;
    mw_reader_init(&r, overlong, sizeof(overlong));
    CHECK(!mw_read_varint(&r, &v));
    CHECK(r.overflow);

    const uint8_t overlong2[] = { 0xff, 0x80, 0x00 };
    mw_reader_init(&r, overlong2, sizeof(overlong2));
    CHECK(!mw_read_varint(&r, &v));

    // Eleven continuation bytes: more than 64 bits.
    const uint8_t too_long[] = { 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
                                 0xff, 0xff, 0xff, 0x01 };
    mw_reader_init(&r, too_long, sizeof(too_long));
    CHECK(!mw_read_varint(&r, &v));
    CHECK(r.overflow);

    // 2^64 exactly: the tenth byte carries a bit that does not fit.
    const uint8_t just_over[] = { 0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0x80,
                                  0x80, 0x80, 0x02 };
    mw_reader_init(&r, just_over, sizeof(just_over));
    CHECK(!mw_read_varint(&r, &v));

    // Truncated: continuation bit set but nothing follows.
    const uint8_t truncated[] = { 0x80 };
    mw_reader_init(&r, truncated, sizeof(truncated));
    CHECK(!mw_read_varint(&r, &v));
    CHECK(r.overflow);

    // UINT64_MAX is still accepted.
    uint8_t max_buf[10];
    size_t n = mw_varint_encode(UINT64_MAX, max_buf);
    mw_reader_init(&r, max_buf, n);
    CHECK(mw_read_varint(&r, &v));
    CHECK(v == UINT64_MAX);
}

MW_TEST(test_reader_bounds)
{
    const uint8_t data[8] = { 1, 2, 3, 4, 5, 6, 7, 8 };
    mw_reader_t r;
    mw_reader_init(&r, data, sizeof(data));

    uint32_t u32 = 0;
    CHECK(mw_read_u32(&r, &u32));
    CHECK_EQ_INT(u32, 0x04030201u);
    CHECK_EQ_INT(mw_remaining(&r), 4);

    uint64_t u64 = 0;
    CHECK(!mw_read_u64(&r, &u64));               // only 4 bytes left
    CHECK(r.overflow);
    // The overflow flag is sticky: a read that would fit must still fail.
    uint8_t byte = 0;
    CHECK(!mw_read_u8(&r, &byte));

    mw_reader_init(&r, data, sizeof(data));
    CHECK(mw_read_u64(&r, &u64));
    CHECK(u64 == 0x0807060504030201ULL);
    CHECK_EQ_INT(mw_remaining(&r), 0);
    CHECK(!mw_read_u8(&r, &byte));

    // Zero-length and NULL buffers behave, they do not crash.
    mw_reader_init(&r, NULL, 100);
    CHECK_EQ_INT(mw_remaining(&r), 0);
    CHECK(!mw_read_u8(&r, &byte));

    // A huge length request must not wrap around.
    mw_reader_init(&r, data, sizeof(data));
    CHECK(!mw_skip(&r, (size_t)-1));
    CHECK(r.overflow);
}

MW_TEST(test_points_and_scalars)
{
    uint8_t data[64];
    for (int i = 0; i < 64; ++i) {
        data[i] = (uint8_t)i;
    }
    mw_reader_t r;
    mw_reader_init(&r, data, sizeof(data));
    mw_point_t p;
    mw_scalar_t s;
    CHECK(mw_read_point(&r, &p));
    CHECK(mw_read_scalar(&r, &s));
    CHECK_EQ_MEM(p.b, data, 32);
    CHECK_EQ_MEM(s.b, data + 32, 32);
    CHECK_EQ_INT(mw_remaining(&r), 0);

    uint8_t out[64];
    mw_writer_t w;
    mw_writer_init(&w, out, sizeof(out));
    CHECK(mw_write_point(&w, &p));
    CHECK(mw_write_scalar(&w, &s));
    CHECK_EQ_INT(w.pos, 64);
    CHECK_EQ_MEM(out, data, 64);
}

MW_TEST(test_writer_bounds)
{
    uint8_t out[4];
    mw_writer_t w;
    mw_writer_init(&w, out, sizeof(out));
    CHECK(mw_write_u32(&w, 0xdeadbeef));
    CHECK(!w.overflow);
    CHECK(!mw_write_u8(&w, 1));
    CHECK(w.overflow);
    // Sticky, like the reader.
    mw_writer_init(&w, out, sizeof(out));
    CHECK(!mw_write_u64(&w, 0));
    CHECK(w.overflow);
    CHECK(!mw_write_u8(&w, 1));

    CHECK_EQ_INT(out[0], 0xef);
    CHECK_EQ_INT(out[3], 0xde);
}

MW_TEST(test_pba_integers)
{
    static const uint64_t values[] = { 0, 1, 127, 255, 256, 0x1234, 0xffffff,
                                       0xffffffffULL, 0x123456789abcdefULL,
                                       UINT64_MAX };
    for (size_t i = 0; i < sizeof(values) / sizeof(values[0]); ++i) {
        uint8_t buf[16];
        mw_writer_t w;
        mw_writer_init(&w, buf, sizeof(buf));
        CHECK(mw_pba_write_u64(&w, values[i]));

        mw_reader_t r;
        mw_reader_init(&r, buf, w.pos);
        uint64_t got = 0;
        CHECK(mw_pba_read_u64(&r, &got));
        CHECK(got == values[i]);
        CHECK_EQ_INT(mw_remaining(&r), 0);
    }

    // Zero is a single 0x00 size byte.
    uint8_t zero_buf[4];
    mw_writer_t w;
    mw_writer_init(&w, zero_buf, sizeof(zero_buf));
    CHECK(mw_pba_write_u64(&w, 0));
    CHECK_EQ_INT(w.pos, 1);
    CHECK_EQ_INT(zero_buf[0], 0);

    // Little-endian magnitude bytes.
    mw_writer_init(&w, zero_buf, sizeof(zero_buf));
    CHECK(mw_pba_write_u64(&w, 0x0102));
    CHECK_EQ_INT(w.pos, 3);
    CHECK_EQ_INT(zero_buf[0], 2);
    CHECK_EQ_INT(zero_buf[1], 0x02);
    CHECK_EQ_INT(zero_buf[2], 0x01);
}

MW_TEST(test_pba_signed_and_limits)
{
    // Bit 7 of the size byte is the sign flag.
    const uint8_t neg_one[] = { 0x81, 0x01 };
    mw_reader_t r;
    mw_reader_init(&r, neg_one, sizeof(neg_one));
    int64_t sv = 0;
    CHECK(mw_pba_read_i64(&r, &sv));
    CHECK(sv == -1);

    // The same bytes read as unsigned must be rejected, not silently wrapped.
    mw_reader_init(&r, neg_one, sizeof(neg_one));
    uint64_t uv = 0;
    CHECK(!mw_pba_read_u64(&r, &uv));
    CHECK(r.overflow);

    // A size byte larger than 8 cannot fit a 64-bit value.
    const uint8_t too_wide[] = { 0x09, 1, 2, 3, 4, 5, 6, 7, 8, 9 };
    mw_reader_init(&r, too_wide, sizeof(too_wide));
    CHECK(!mw_pba_read_u64(&r, &uv));
    CHECK(r.overflow);

    // Truncated magnitude.
    const uint8_t truncated[] = { 0x04, 1, 2 };
    mw_reader_init(&r, truncated, sizeof(truncated));
    CHECK(!mw_pba_read_u64(&r, &uv));

    // u32 accessor range check.
    uint8_t buf[16];
    mw_writer_t w;
    mw_writer_init(&w, buf, sizeof(buf));
    CHECK(mw_pba_write_u64(&w, 0x1ffffffffULL));
    mw_reader_init(&r, buf, w.pos);
    uint32_t u32 = 0;
    CHECK(!mw_pba_read_u32(&r, &u32));
}

MW_TEST(test_pba_header)
{
    uint8_t buf[64];
    mw_writer_t w;
    mw_writer_init(&w, buf, sizeof(buf));
    CHECK(mw_pba_write_header(&w, 17));

    mw_reader_t r;
    mw_reader_init(&r, buf, w.pos);
    uint32_t version = 0;
    CHECK(mw_pba_read_header(&r, &version));
    CHECK_EQ_INT(version, 17);
    CHECK_EQ_INT(mw_remaining(&r), 0);

    // The signature really is on the wire: one size byte, one magnitude byte
    // holding 22, then the characters.
    CHECK_EQ_INT(buf[0], 1);
    CHECK_EQ_INT(buf[1], 22);
    CHECK(memcmp(buf + 2, "serialization::archive", 22) == 0);

    // A corrupted signature is rejected.
    uint8_t bad[64];
    memcpy(bad, buf, w.pos);
    bad[4] ^= 1;
    mw_reader_init(&r, bad, w.pos);
    CHECK(!mw_pba_read_header(&r, &version));

    // A wrong length prefix is rejected.
    memcpy(bad, buf, w.pos);
    bad[1] = 99;                                  // claims 99 characters
    mw_reader_init(&r, bad, w.pos);
    CHECK(!mw_pba_read_header(&r, &version));

    // Truncated header.
    mw_reader_init(&r, buf, 5);
    CHECK(!mw_pba_read_header(&r, &version));
}

int main(void)
{
    RUN_TEST(test_varint_round_trip);
    RUN_TEST(test_varint_known_encodings);
    RUN_TEST(test_varint_rejects_non_canonical);
    RUN_TEST(test_reader_bounds);
    RUN_TEST(test_points_and_scalars);
    RUN_TEST(test_writer_bounds);
    RUN_TEST(test_pba_integers);
    RUN_TEST(test_pba_signed_and_limits);
    RUN_TEST(test_pba_header);
    return mw_test_summary();
}
