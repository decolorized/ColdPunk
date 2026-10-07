// Monero's binary archive primitives: varint, portable_binary_archive layout
// and the byte cursor used by every parser in the project.
#ifndef MW_SERIALIZE_H
#define MW_SERIALIZE_H

#include "monero_types.h"

#ifdef __cplusplus
extern "C" {
#endif

// ---------------- cursor --------------------------------------------------
typedef struct {
    const uint8_t* data;
    size_t len;
    size_t pos;
    bool   overflow;   // set once a read ran past the end; sticky
} mw_reader_t;

typedef struct {
    uint8_t* data;
    size_t   cap;
    size_t   pos;
    bool     overflow;
} mw_writer_t;

void mw_reader_init(mw_reader_t* r, const uint8_t* data, size_t len);
void mw_writer_init(mw_writer_t* w, uint8_t* buf, size_t cap);

bool mw_read_bytes(mw_reader_t* r, void* out, size_t n);
bool mw_read_u8(mw_reader_t* r, uint8_t* out);
bool mw_read_u16(mw_reader_t* r, uint16_t* out);    // little endian
bool mw_read_u32(mw_reader_t* r, uint32_t* out);
bool mw_read_u64(mw_reader_t* r, uint64_t* out);
bool mw_read_varint(mw_reader_t* r, uint64_t* out); // Monero LEB128, max 10 bytes
bool mw_read_point(mw_reader_t* r, mw_point_t* out);
bool mw_read_scalar(mw_reader_t* r, mw_scalar_t* out);
bool mw_skip(mw_reader_t* r, size_t n);
size_t mw_remaining(const mw_reader_t* r);

bool mw_write_bytes(mw_writer_t* w, const void* data, size_t n);
bool mw_write_u8(mw_writer_t* w, uint8_t v);
bool mw_write_u32(mw_writer_t* w, uint32_t v);
bool mw_write_u64(mw_writer_t* w, uint64_t v);
bool mw_write_varint(mw_writer_t* w, uint64_t v);
bool mw_write_point(mw_writer_t* w, const mw_point_t* p);
bool mw_write_scalar(mw_writer_t* w, const mw_scalar_t* s);

// Standalone varint helpers (needed by hash-to-point domain separation).
size_t mw_varint_encode(uint64_t v, uint8_t out[10]);
size_t mw_varint_size(uint64_t v);

// ---------------- boost portable_binary_archive ---------------------------
// NOT used by the current parser. Version 5 of unsigned_tx_set - the only one
// this firmware accepts - is written with Monero's OWN binary_archive (plain
// varints), which the mw_read_varint path above handles. Versions 3 and 4 used
// boost::archive::portable_binary_oarchive, where integers are stored as
// 1 size byte (bit 7 = negative) followed by little-endian bytes.
//
// These helpers are kept, and tested, so that support for an older tx set can
// be added without re-deriving the encoding. Nothing in src/ calls them today.
bool mw_pba_read_u64(mw_reader_t* r, uint64_t* out);
bool mw_pba_read_u32(mw_reader_t* r, uint32_t* out);
bool mw_pba_read_i64(mw_reader_t* r, int64_t* out);
bool mw_pba_read_size(mw_reader_t* r, size_t* out);
bool mw_pba_write_u64(mw_writer_t* w, uint64_t v);
bool mw_pba_write_u32(mw_writer_t* w, uint32_t v);
// Reads and validates the boost archive signature + version header.
bool mw_pba_read_header(mw_reader_t* r, uint32_t* version_out);
bool mw_pba_write_header(mw_writer_t* w, uint32_t version);

#ifdef __cplusplus
}
#endif
#endif
