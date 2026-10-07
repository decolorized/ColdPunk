// Binary archive primitives (TZ 9 / 12).
//
// Two distinct integer encodings live in this file:
//
//   1. Monero's own "varint" (LEB128, 7 bits per byte, little endian). This is
//      what cryptonote transactions, outputs.bin (export format 4) and the
//      version-5 unsigned/signed tx sets use.
//   2. boost::archive::portable_binary_[io]archive, used by the *deprecated*
//      version-3/4 unsigned tx sets: one length byte whose bit 7 is the sign
//      flag, followed by that many little-endian magnitude bytes.
//
// Everything here is hostile-input safe: the reader carries a sticky overflow
// flag, never indexes past `len`, and every read returns false once the flag is
// set so a caller may check it once at the end of a long parse.
#include "serialize.h"

#include <string.h>

// ------------------------------------------------------------------ cursor
void mw_reader_init(mw_reader_t* r, const uint8_t* data, size_t len)
{
    if (r == NULL) {
        return;
    }
    r->data = data;
    r->len = (data == NULL) ? 0 : len;
    r->pos = 0;
    r->overflow = false;
}

void mw_writer_init(mw_writer_t* w, uint8_t* buf, size_t cap)
{
    if (w == NULL) {
        return;
    }
    w->data = buf;
    w->cap = (buf == NULL) ? 0 : cap;
    w->pos = 0;
    w->overflow = false;
}

size_t mw_remaining(const mw_reader_t* r)
{
    if (r == NULL || r->overflow || r->pos > r->len) {
        return 0;
    }
    return r->len - r->pos;
}

// Every read funnels through here, so there is exactly one bounds check in the
// whole reader.
bool mw_read_bytes(mw_reader_t* r, void* out, size_t n)
{
    if (r == NULL || r->overflow) {
        return false;
    }
    if (n > r->len - r->pos) {       // r->pos <= r->len is an invariant
        r->overflow = true;
        return false;
    }
    if (out != NULL && n != 0) {
        memcpy(out, r->data + r->pos, n);
    }
    r->pos += n;
    return true;
}

bool mw_skip(mw_reader_t* r, size_t n)
{
    return mw_read_bytes(r, NULL, n);
}

bool mw_read_u8(mw_reader_t* r, uint8_t* out)
{
    return mw_read_bytes(r, out, 1);
}

bool mw_read_u16(mw_reader_t* r, uint16_t* out)
{
    uint8_t b[2];
    if (!mw_read_bytes(r, b, sizeof(b))) {
        return false;
    }
    *out = (uint16_t)((uint16_t)b[0] | ((uint16_t)b[1] << 8));
    return true;
}

bool mw_read_u32(mw_reader_t* r, uint32_t* out)
{
    uint8_t b[4];
    if (!mw_read_bytes(r, b, sizeof(b))) {
        return false;
    }
    *out = (uint32_t)b[0] | ((uint32_t)b[1] << 8) | ((uint32_t)b[2] << 16) |
           ((uint32_t)b[3] << 24);
    return true;
}

bool mw_read_u64(mw_reader_t* r, uint64_t* out)
{
    uint8_t b[8];
    if (!mw_read_bytes(r, b, sizeof(b))) {
        return false;
    }
    uint64_t v = 0;
    for (int i = 7; i >= 0; --i) {
        v = (v << 8) | b[i];
    }
    *out = v;
    return true;
}

// Monero's tools::read_varint, including both of its rejection rules:
//   * overflow past 64 bits,
//   * non-canonical (a 0x00 continuation byte after the first byte).
bool mw_read_varint(mw_reader_t* r, uint64_t* out)
{
    if (r == NULL || out == NULL || r->overflow) {
        return false;
    }
    uint64_t v = 0;
    for (int shift = 0; ; shift += 7) {
        uint8_t byte;
        if (!mw_read_u8(r, &byte)) {
            return false;
        }
        if (shift >= 64) {                       // 10th byte and beyond
            r->overflow = true;
            return false;
        }
        if (shift + 7 >= 64 && byte >= (1u << (64 - shift))) {
            r->overflow = true;                  // would not fit in 64 bits
            return false;
        }
        if (byte == 0 && shift != 0) {
            r->overflow = true;                  // overlong / non-canonical
            return false;
        }
        v |= (uint64_t)(byte & 0x7f) << shift;
        if ((byte & 0x80) == 0) {
            break;
        }
    }
    *out = v;
    return true;
}

bool mw_read_point(mw_reader_t* r, mw_point_t* out)
{
    return mw_read_bytes(r, out->b, 32);
}

bool mw_read_scalar(mw_reader_t* r, mw_scalar_t* out)
{
    // No reduction and no canonicity check here: callers that need `s < l`
    // must call mw_sc_check() explicitly (CLSAG and signature parsers do).
    return mw_read_bytes(r, out->b, 32);
}

// ------------------------------------------------------------------ writer
bool mw_write_bytes(mw_writer_t* w, const void* data, size_t n)
{
    if (w == NULL || w->overflow) {
        return false;
    }
    if (n > w->cap - w->pos) {
        w->overflow = true;
        return false;
    }
    if (data != NULL && n != 0) {
        memcpy(w->data + w->pos, data, n);
    }
    w->pos += n;
    return true;
}

bool mw_write_u8(mw_writer_t* w, uint8_t v)
{
    return mw_write_bytes(w, &v, 1);
}

bool mw_write_u32(mw_writer_t* w, uint32_t v)
{
    uint8_t b[4] = { (uint8_t)v, (uint8_t)(v >> 8), (uint8_t)(v >> 16),
                     (uint8_t)(v >> 24) };
    return mw_write_bytes(w, b, sizeof(b));
}

bool mw_write_u64(mw_writer_t* w, uint64_t v)
{
    uint8_t b[8];
    for (int i = 0; i < 8; ++i) {
        b[i] = (uint8_t)((v >> (8 * i)) & 0xff);
    }
    return mw_write_bytes(w, b, sizeof(b));
}

size_t mw_varint_encode(uint64_t v, uint8_t out[10])
{
    size_t n = 0;
    while (v >= 0x80) {
        out[n++] = (uint8_t)((v & 0x7f) | 0x80);
        v >>= 7;
    }
    out[n++] = (uint8_t)v;
    return n;
}

size_t mw_varint_size(uint64_t v)
{
    size_t n = 1;
    while (v >= 0x80) {
        ++n;
        v >>= 7;
    }
    return n;
}

bool mw_write_varint(mw_writer_t* w, uint64_t v)
{
    uint8_t buf[10];
    size_t n = mw_varint_encode(v, buf);
    return mw_write_bytes(w, buf, n);
}

bool mw_write_point(mw_writer_t* w, const mw_point_t* p)
{
    return mw_write_bytes(w, p->b, 32);
}

bool mw_write_scalar(mw_writer_t* w, const mw_scalar_t* s)
{
    return mw_write_bytes(w, s->b, 32);
}

// ------------------------------------------- boost portable_binary_archive
// Layout of one integer (boost's portable_binary_oarchive::save_impl):
//     byte  size        bit 7 set => the value is negative
//     byte  v[size]     little-endian magnitude, no leading zero byte
// A zero value is a single 0x00 byte.
//
// The archive as a whole starts with the signature string
// "serialization::archive" (itself written as a portable int length followed
// by the raw characters) and the library version as a portable int.

#define MW_PBA_MAX_BYTES 8

static bool pba_read_raw(mw_reader_t* r, uint64_t* mag_out, bool* negative_out)
{
    uint8_t size_byte;
    if (!mw_read_u8(r, &size_byte)) {
        return false;
    }
    bool negative = (size_byte & 0x80) != 0;
    uint8_t size = (uint8_t)(size_byte & 0x7f);
    if (size > MW_PBA_MAX_BYTES) {
        r->overflow = true;                      // wider than 64 bits
        return false;
    }
    uint8_t buf[MW_PBA_MAX_BYTES];
    if (size != 0 && !mw_read_bytes(r, buf, size)) {
        return false;
    }
    uint64_t v = 0;
    for (int i = (int)size - 1; i >= 0; --i) {
        v = (v << 8) | buf[i];                   // little endian on the wire
    }
    if (mag_out != NULL) {
        *mag_out = v;
    }
    if (negative_out != NULL) {
        *negative_out = negative;
    }
    return true;
}

bool mw_pba_read_u64(mw_reader_t* r, uint64_t* out)
{
    uint64_t v;
    bool negative;
    if (!pba_read_raw(r, &v, &negative)) {
        return false;
    }
    if (negative) {
        r->overflow = true;                      // unsigned field, signed value
        return false;
    }
    *out = v;
    return true;
}

bool mw_pba_read_u32(mw_reader_t* r, uint32_t* out)
{
    uint64_t v;
    if (!mw_pba_read_u64(r, &v)) {
        return false;
    }
    if (v > 0xffffffffULL) {
        r->overflow = true;
        return false;
    }
    *out = (uint32_t)v;
    return true;
}

bool mw_pba_read_i64(mw_reader_t* r, int64_t* out)
{
    uint64_t v;
    bool negative;
    if (!pba_read_raw(r, &v, &negative)) {
        return false;
    }
    if (negative) {
        if (v > (uint64_t)INT64_MAX + 1u) {
            r->overflow = true;
            return false;
        }
        *out = (v == (uint64_t)INT64_MAX + 1u) ? INT64_MIN : -(int64_t)v;
    } else {
        if (v > (uint64_t)INT64_MAX) {
            r->overflow = true;
            return false;
        }
        *out = (int64_t)v;
    }
    return true;
}

bool mw_pba_read_size(mw_reader_t* r, size_t* out)
{
    uint64_t v;
    if (!mw_pba_read_u64(r, &v)) {
        return false;
    }
    if (v > (uint64_t)SIZE_MAX) {
        r->overflow = true;
        return false;
    }
    *out = (size_t)v;
    return true;
}

bool mw_pba_write_u64(mw_writer_t* w, uint64_t v)
{
    uint8_t buf[MW_PBA_MAX_BYTES];
    uint8_t size = 0;
    uint64_t t = v;
    while (t != 0) {
        buf[size++] = (uint8_t)(t & 0xff);
        t >>= 8;
    }
    if (!mw_write_u8(w, size)) {
        return false;
    }
    return size == 0 ? true : mw_write_bytes(w, buf, size);
}

bool mw_pba_write_u32(mw_writer_t* w, uint32_t v)
{
    return mw_pba_write_u64(w, v);
}

static const char MW_PBA_SIGNATURE[] = "serialization::archive";
#define MW_PBA_SIGNATURE_LEN (sizeof(MW_PBA_SIGNATURE) - 1)

bool mw_pba_read_header(mw_reader_t* r, uint32_t* version_out)
{
    uint64_t sig_len;
    if (!mw_pba_read_u64(r, &sig_len)) {
        return false;
    }
    if (sig_len != MW_PBA_SIGNATURE_LEN) {
        r->overflow = true;
        return false;
    }
    char sig[MW_PBA_SIGNATURE_LEN];
    if (!mw_read_bytes(r, sig, sizeof(sig))) {
        return false;
    }
    if (memcmp(sig, MW_PBA_SIGNATURE, sizeof(sig)) != 0) {
        r->overflow = true;
        return false;
    }
    uint32_t version;
    if (!mw_pba_read_u32(r, &version)) {
        return false;
    }
    // Boost's library version is a 16-bit field; anything larger means we are
    // not looking at a boost archive at all.
    if (version > 0xffff) {
        r->overflow = true;
        return false;
    }
    if (version_out != NULL) {
        *version_out = version;
    }
    return true;
}

bool mw_pba_write_header(mw_writer_t* w, uint32_t version)
{
    if (!mw_pba_write_u64(w, MW_PBA_SIGNATURE_LEN)) {
        return false;
    }
    if (!mw_write_bytes(w, MW_PBA_SIGNATURE, MW_PBA_SIGNATURE_LEN)) {
        return false;
    }
    return mw_pba_write_u32(w, version);
}
