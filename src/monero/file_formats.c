// Monero / Feather exchange files - see file_formats.h for the layouts.
//
// Reference: src/wallet/wallet2.{h,cpp}, src/cryptonote_core/
// cryptonote_tx_utils.h and src/serialization/*.h of the Feather fork of
// monero (the code Feather ships) and of monero-project/monero
// release-v0.18. The functions that produce / consume the files there are
// export_outputs_to_str(), export_key_images_for_outputs_from_str(),
// parse_unsigned_tx_from_str(), sign_tx() and parse_tx_from_str().
//
// Every byte parsed here arrives from an online machine. All reads go through
// the bounds-checked mw_reader_t, every count is checked against the bytes
// that are actually left before anything is looped over, and every point is
// validated by the signer before it is used in arithmetic.
#include "file_formats.h"

#include <stdarg.h>
#include <stdio.h>
#include <string.h>

#include "serialize.h"
#include "keys.h"
#include "../crypto/chacha.h"
#include "../crypto/hash.h"
#include "../crypto/memzero.h"
#include "../crypto/random.h"

// ---------------------------------------------------------------- magics
static const uint8_t MAGIC_OUTPUTS[]   = MW_MAGIC_OUTPUTS;
static const uint8_t MAGIC_KEYIMAGES[] = MW_MAGIC_KEYIMAGES;
static const uint8_t MAGIC_UNSIGNED[]  = MW_MAGIC_UNSIGNED_TX;
static const uint8_t MAGIC_SIGNED[]    = MW_MAGIC_SIGNED_TX;
static const uint8_t MAGIC_MULTISIG[]  = MW_MAGIC_MULTISIG_TX;

_Static_assert(sizeof(MAGIC_OUTPUTS) - 1 == MW_MAGIC_OUTPUTS_LEN, "outputs magic length");
_Static_assert(sizeof(MAGIC_KEYIMAGES) - 1 == MW_MAGIC_KEYIMAGES_LEN, "key image magic length");
_Static_assert(sizeof(MAGIC_UNSIGNED) - 1 == MW_MAGIC_UNSIGNED_TX_LEN, "unsigned tx magic length");
_Static_assert(sizeof(MAGIC_SIGNED) - 1 == MW_MAGIC_SIGNED_TX_LEN, "signed tx magic length");
_Static_assert(sizeof(MAGIC_MULTISIG) - 1 == MW_MAGIC_MULTISIG_TX_LEN, "multisig magic length");

const mw_file_kind_t MW_FILE_OUTPUTS = {
    MAGIC_OUTPUTS, MW_MAGIC_OUTPUTS_LEN, 0, false
};
const mw_file_kind_t MW_FILE_KEYIMAGES = {
    MAGIC_KEYIMAGES, MW_MAGIC_KEYIMAGES_LEN, 0, false
};
const mw_file_kind_t MW_FILE_UNSIGNED_TX = {
    MAGIC_UNSIGNED, MW_MAGIC_UNSIGNED_TX_LEN, MW_UNSIGNED_TX_VERSION, true
};
const mw_file_kind_t MW_FILE_SIGNED_TX = {
    MAGIC_SIGNED, MW_MAGIC_SIGNED_TX_LEN, MW_UNSIGNED_TX_VERSION, true
};

// ------------------------------------------------------------ diagnostics
static void diag_set(mw_ff_diag_t* d, size_t offset, const char* fmt, ...)
#if defined(__GNUC__)
    __attribute__((format(printf, 3, 4)))
#endif
    ;

static void diag_set(mw_ff_diag_t* d, size_t offset, const char* fmt, ...)
{
    if (d == NULL) {
        return;
    }
    d->offset = offset;
    va_list ap;
    va_start(ap, fmt);
    vsnprintf(d->what, sizeof(d->what), fmt, ap);
    va_end(ap);
}

// ------------------------------------------------------------ detection
static bool has_prefix(const uint8_t* data, size_t len, const uint8_t* magic,
                       size_t magic_len)
{
    return len >= magic_len && memcmp(data, magic, magic_len) == 0;
}

mw_file_format_t mw_file_detect(const uint8_t* data, size_t len)
{
    if (data == NULL) {
        return MW_FMT_UNKNOWN;
    }
    // Multisig first: "Monero multisig unsigned tx set" shares no prefix with
    // the others, but it is checked explicitly so it gets its own verdict.
    if (has_prefix(data, len, MAGIC_MULTISIG, MW_MAGIC_MULTISIG_TX_LEN)) {
        return MW_FMT_MULTISIG;
    }
    // The outputs / key image magics end in their version byte; an older
    // version of the same file family is reported as such.
    if (has_prefix(data, len, MAGIC_OUTPUTS, MW_MAGIC_OUTPUTS_LEN)) {
        return MW_FMT_OUTPUTS;
    }
    if (has_prefix(data, len, MAGIC_OUTPUTS, MW_MAGIC_OUTPUTS_LEN - 1)) {
        return MW_FMT_UNSUPPORTED_VERSION;
    }
    if (has_prefix(data, len, MAGIC_KEYIMAGES, MW_MAGIC_KEYIMAGES_LEN)) {
        return MW_FMT_KEYIMAGES;
    }
    if (has_prefix(data, len, MAGIC_KEYIMAGES, MW_MAGIC_KEYIMAGES_LEN - 1)) {
        return MW_FMT_UNSUPPORTED_VERSION;
    }
    if (has_prefix(data, len, MAGIC_UNSIGNED, MW_MAGIC_UNSIGNED_TX_LEN)) {
        if (len > MW_MAGIC_UNSIGNED_TX_LEN &&
            data[MW_MAGIC_UNSIGNED_TX_LEN] == MW_UNSIGNED_TX_VERSION) {
            return MW_FMT_UNSIGNED_TX;
        }
        return MW_FMT_UNSUPPORTED_VERSION;
    }
    if (has_prefix(data, len, MAGIC_SIGNED, MW_MAGIC_SIGNED_TX_LEN)) {
        if (len > MW_MAGIC_SIGNED_TX_LEN &&
            data[MW_MAGIC_SIGNED_TX_LEN] == MW_UNSIGNED_TX_VERSION) {
            return MW_FMT_SIGNED_TX;
        }
        return MW_FMT_UNSUPPORTED_VERSION;
    }
    return MW_FMT_UNKNOWN;
}

const char* mw_file_format_name(mw_file_format_t f)
{
    switch (f) {
    case MW_FMT_OUTPUTS:             return "Monero output export";
    case MW_FMT_KEYIMAGES:           return "Monero key image export";
    case MW_FMT_UNSIGNED_TX:         return "Monero unsigned tx set";
    case MW_FMT_SIGNED_TX:           return "Monero signed tx set";
    case MW_FMT_MULTISIG:            return "Monero multisig tx set";
    case MW_FMT_UNSUPPORTED_VERSION: return "Monero file, unsupported version";
    case MW_FMT_UNKNOWN:
    default:                         return "unknown";
    }
}

// ------------------------------------------------------- Schnorr signature
// crypto::generate_signature(): c = Hs(prefix || pub || k*G), r = k - c*sec.
mw_err_t mw_schnorr_sign(const uint8_t hash[32], const mw_pubkey_t* pub,
                         const mw_seckey_t* sec, uint8_t sig_out[MW_SIG_LEN])
{
    if (hash == NULL || pub == NULL || sec == NULL || sig_out == NULL) {
        return MW_ERR_INVALID_ARG;
    }
    if (!mw_sc_check(sec)) {
        return MW_ERR_INVALID_ARG;
    }
    mw_err_t err = mw_check_key_pair(sec, pub);
    if (err != MW_OK) {
        return err;
    }

    uint8_t buf[96];
    memcpy(buf, hash, 32);
    memcpy(buf + 32, pub->b, 32);

    for (int attempt = 0; attempt < 8; ++attempt) {
        uint8_t ctx[96];
        memcpy(ctx, hash, 32);
        memcpy(ctx + 32, sec->b, 32);
        memset(ctx + 64, attempt, 32);
        mw_scalar_t k;
        mw_random_hedged_scalar(&k, ctx, sizeof(ctx));
        mw_memzero(ctx, sizeof(ctx));

        mw_point_t comm;
        mw_point_scalarmult_base(&comm, &k);
        memcpy(buf + 64, comm.b, 32);

        mw_scalar_t c, r;
        mw_hash_to_scalar(buf, sizeof(buf), &c);
        if (mw_sc_is_zero(&c)) {
            mw_memzero(&k, sizeof(k));
            continue;
        }
        mw_sc_mulsub(&r, &c, sec, &k);          // r = k - c*sec
        mw_memzero(&k, sizeof(k));
        if (mw_sc_is_zero(&r)) {
            continue;
        }
        memcpy(sig_out, c.b, 32);
        memcpy(sig_out + 32, r.b, 32);
        mw_memzero(&c, sizeof(c));
        mw_memzero(&r, sizeof(r));
        mw_memzero(buf, sizeof(buf));
        return MW_OK;
    }
    mw_memzero(buf, sizeof(buf));
    return MW_ERR_SIGNATURE;
}

mw_err_t mw_schnorr_verify(const uint8_t hash[32], const mw_pubkey_t* pub,
                           const uint8_t sig[MW_SIG_LEN])
{
    if (hash == NULL || pub == NULL || sig == NULL) {
        return MW_ERR_INVALID_ARG;
    }
    mw_scalar_t c, r;
    memcpy(c.b, sig, 32);
    memcpy(r.b, sig + 32, 32);
    if (!mw_sc_check(&c) || !mw_sc_check(&r)) {
        return MW_ERR_SIGNATURE;
    }
    if (!mw_point_check_public(pub)) {
        return MW_ERR_SUBGROUP;
    }

    mw_ge_p3 pub_p3;
    if (mw_ge_frombytes_vartime(&pub_p3, pub) != 0) {
        return MW_ERR_FORMAT;
    }

    mw_ge_p2 comm;
    mw_ge_double_scalarmult_base_vartime(&comm, &c, &pub_p3, &r);  // c*P + r*G
    mw_point_t comm_bytes;
    mw_ge_p2_tobytes(&comm_bytes, &comm);

    uint8_t buf[96];
    memcpy(buf, hash, 32);
    memcpy(buf + 32, pub->b, 32);
    memcpy(buf + 64, comm_bytes.b, 32);

    mw_scalar_t c2, diff;
    mw_hash_to_scalar(buf, sizeof(buf), &c2);
    mw_sc_sub(&diff, &c2, &c);
    return mw_sc_is_zero(&diff) ? MW_OK : MW_ERR_SIGNATURE;
}

// ---------------------------------------------------------------- envelope
void mw_file_key(const mw_account_keys_t* keys, mw_chacha_key* key_out)
{
    // wallet2 uses kdf_rounds == 1 for the exchange files.
    mw_generate_chacha_key(keys->sec.view.b, 32, key_out, 1);
}

mw_err_t mw_file_open(const mw_file_kind_t* kind,
                      const uint8_t* file, size_t file_len,
                      const mw_account_keys_t* keys,
                      uint8_t* plaintext, size_t plaintext_cap,
                      size_t* plaintext_len)
{
    return mw_file_open_k(kind, file, file_len, keys, NULL, plaintext,
                          plaintext_cap, plaintext_len);
}

mw_err_t mw_file_open_k(const mw_file_kind_t* kind,
                        const uint8_t* file, size_t file_len,
                        const mw_account_keys_t* keys, const mw_chacha_key* file_key,
                        uint8_t* plaintext, size_t plaintext_cap,
                        size_t* plaintext_len)
{
    if (kind == NULL || file == NULL || keys == NULL || plaintext == NULL ||
        plaintext_len == NULL) {
        return MW_ERR_INVALID_ARG;
    }
    *plaintext_len = 0;

    const size_t head = kind->magic_len + (kind->has_version ? 1u : 0u);
    if (file_len < head + MW_IV_LEN + MW_SIG_LEN) {
        return MW_ERR_FORMAT;
    }
    if (memcmp(file, kind->magic, kind->magic_len) != 0) {
        return MW_ERR_MAGIC;
    }
    if (kind->has_version && file[kind->magic_len] != kind->version) {
        return MW_ERR_VERSION;
    }

    const uint8_t* body = file + head;                 // iv || ct || sig
    const size_t body_len = file_len - head;
    const size_t ct_len = body_len - MW_IV_LEN - MW_SIG_LEN;
    if (ct_len > plaintext_cap) {
        return MW_ERR_TOO_MANY;
    }

    // Authenticate before decrypting: the hash covers iv || ciphertext.
    uint8_t hash[32];
    mw_keccak256(body, MW_IV_LEN + ct_len, hash);
    mw_err_t err = mw_schnorr_verify(hash, &keys->pub.view, body + MW_IV_LEN + ct_len);
    if (err != MW_OK) {
        return err;
    }

    mw_chacha_key key;
    if (file_key != NULL) {
        key = *file_key;
    } else {
        mw_file_key(keys, &key);
    }
    mw_chacha_iv iv;
    memcpy(iv.data, body, MW_IV_LEN);
    // Forward, byte-wise: safe when `plaintext` aliases `file`, because the
    // output always trails the input it is computed from.
    mw_chacha20(body + MW_IV_LEN, ct_len, &key, &iv, plaintext);
    mw_memzero(&key, sizeof(key));

    *plaintext_len = ct_len;
    return MW_OK;
}

mw_err_t mw_file_seal(const mw_file_kind_t* kind,
                      const uint8_t* plaintext, size_t plaintext_len,
                      const mw_account_keys_t* keys,
                      uint8_t* out, size_t out_cap, size_t* out_len)
{
    return mw_file_seal_k(kind, plaintext, plaintext_len, keys, NULL, out,
                          out_cap, out_len);
}

mw_err_t mw_file_seal_k(const mw_file_kind_t* kind,
                        const uint8_t* plaintext, size_t plaintext_len,
                        const mw_account_keys_t* keys, const mw_chacha_key* file_key,
                        uint8_t* out, size_t out_cap, size_t* out_len)
{
    if (kind == NULL || keys == NULL || out_len == NULL ||
        (plaintext == NULL && plaintext_len != 0)) {
        return MW_ERR_INVALID_ARG;
    }

    const size_t head = kind->magic_len + (kind->has_version ? 1u : 0u);
    const size_t total = head + MW_IV_LEN + plaintext_len + MW_SIG_LEN;
    *out_len = total;
    if (out == NULL) {
        return MW_OK;                                  // size query
    }
    if (out_cap < total) {
        return MW_ERR_MEMORY;
    }

    memcpy(out, kind->magic, kind->magic_len);
    if (kind->has_version) {
        out[kind->magic_len] = kind->version;
    }

    uint8_t* body = out + head;
    mw_chacha_iv iv;
    mw_random_bytes(iv.data, MW_IV_LEN);
    memcpy(body, iv.data, MW_IV_LEN);

    mw_chacha_key key;
    if (file_key != NULL) {
        key = *file_key;
    } else {
        mw_file_key(keys, &key);
    }
    mw_chacha20(plaintext, plaintext_len, &key, &iv, body + MW_IV_LEN);
    mw_memzero(&key, sizeof(key));

    uint8_t hash[32];
    mw_keccak256(body, MW_IV_LEN + plaintext_len, hash);
    mw_err_t err = mw_schnorr_sign(hash, &keys->pub.view, &keys->sec.view,
                                   body + MW_IV_LEN + plaintext_len);
    if (err != MW_OK) {
        mw_memzero(out, total);
        *out_len = 0;
        return err;
    }
    // Fault-injection defence: the device verifies what it is about to export.
    return mw_schnorr_verify(hash, &keys->pub.view, body + MW_IV_LEN + plaintext_len);
}

// ------------------------------------------------------ archive helpers
// A count that cannot possibly be satisfied by the bytes left is refused
// before anything loops over it (container.h does the same).
static bool count_fits(const mw_reader_t* r, uint64_t count, size_t min_elem)
{
    const size_t left = mw_remaining(r);
    if (min_elem == 0) {
        min_elem = 1;
    }
    return count <= (uint64_t)(left / min_elem);
}

// VERSION_FIELD / std::pair / std::tuple markers are varints.
static bool read_marker(mw_reader_t* r, uint64_t want)
{
    uint64_t v = 0;
    return mw_read_varint(r, &v) && v == want;
}

// ------------------------------------------------ exported_transfer_details
//   VERSION_FIELD(1) (refused when < 1)
//   FIELD(m_pubkey)                        32
//   VARINT_FIELD(m_internal_output_index)
//   VARINT_FIELD(m_global_output_index)
//   FIELD(m_tx_pubkey)                     32
//   FIELD(m_flags.flags)                   1
//   VARINT_FIELD(m_amount)
//   FIELD(m_additional_tx_keys)            varint n, n*32
//   VARINT_FIELD(m_subaddr_index_major)
//   VARINT_FIELD(m_subaddr_index_minor)
#define ETD_MIN_SIZE (1 + 32 + 1 + 1 + 32 + 1 + 1 + 1 + 1 + 1)

static mw_err_t read_etd(mw_reader_t* r, mw_exported_output_t* o,
                         uint64_t index, mw_ff_diag_t* diag)
{
    uint64_t version = 0, internal = 0, global = 0, amount = 0, n_add = 0;
    uint64_t major = 0, minor = 0;
    const size_t at = r->pos;

    memset(o, 0, sizeof(*o));
    if (!mw_read_varint(r, &version)) {
        diag_set(diag, at, "output #%llu: truncated", (unsigned long long)index);
        return MW_ERR_FORMAT;
    }
    if (version < 1) {
        diag_set(diag, at, "output #%llu: record version 0 is not supported",
                 (unsigned long long)index);
        return MW_ERR_VERSION;
    }
    if (!mw_read_point(r, &o->one_time_pubkey) ||
        !mw_read_varint(r, &internal) ||
        !mw_read_varint(r, &global) ||
        !mw_read_point(r, &o->tx_pub_key) ||
        !mw_read_u8(r, &o->flags) ||
        !mw_read_varint(r, &amount) ||
        !mw_read_varint(r, &n_add)) {
        diag_set(diag, r->pos, "output #%llu: truncated or malformed record",
                 (unsigned long long)index);
        return MW_ERR_FORMAT;
    }
    // wallet2::import_outputs(): "internal output index seems outrageously
    // high, rejecting".
    if (internal >= 65536u) {
        diag_set(diag, r->pos, "output #%llu: output index %llu out of range",
                 (unsigned long long)index, (unsigned long long)internal);
        return MW_ERR_RANGE;
    }
    if (!count_fits(r, n_add, 32)) {
        diag_set(diag, r->pos, "output #%llu: %llu additional keys do not fit the file",
                 (unsigned long long)index, (unsigned long long)n_add);
        return MW_ERR_FORMAT;
    }
    for (uint64_t k = 0; k < n_add; ++k) {
        mw_pubkey_t key;
        if (!mw_read_point(r, &key)) {
            return MW_ERR_FORMAT;
        }
        if (k == internal) {
            o->additional_tx_pub = key;
            o->has_additional = true;
        }
    }
    if (!mw_read_varint(r, &major) || !mw_read_varint(r, &minor)) {
        diag_set(diag, r->pos, "output #%llu: truncated subaddress index",
                 (unsigned long long)index);
        return MW_ERR_FORMAT;
    }
    if (major > 0xffffffffULL || minor > 0xffffffffULL) {
        diag_set(diag, r->pos, "output #%llu: subaddress index out of range",
                 (unsigned long long)index);
        return MW_ERR_RANGE;
    }

    o->internal_output_index = (uint32_t)internal;
    o->global_output_index = global;
    o->amount = amount;
    o->additional_count = (uint32_t)n_add;
    o->subaddr_major = (uint32_t)major;
    o->subaddr_minor = (uint32_t)minor;
    o->rct = (o->flags & 0x04u) != 0;            // m_rct is bit 2 of m_flags
    return MW_OK;
}

// ------------------------------------------------------------ outputs file
// plaintext := spend_pub(32) view_pub(32)
//              tuple<u64 offset, u64 total, vector<exported_transfer_details>>
mw_err_t mw_outputs_begin(mw_outputs_iter_t* it, const uint8_t* plaintext,
                          size_t len, const mw_account_keys_t* keys,
                          mw_ff_diag_t* diag)
{
    if (it == NULL || plaintext == NULL || keys == NULL) {
        return MW_ERR_INVALID_ARG;
    }
    memset(it, 0, sizeof(*it));

    mw_reader_t r;
    mw_reader_init(&r, plaintext, len);

    mw_pubkey_t spend, view;
    if (!mw_read_point(&r, &spend) || !mw_read_point(&r, &view)) {
        diag_set(diag, 0, "outputs: file too short for the account header");
        return MW_ERR_FORMAT;
    }
    // wallet2: "Outputs from are for a different account".
    if (!mw_point_eq(&spend, &keys->pub.spend) || !mw_point_eq(&view, &keys->pub.view)) {
        diag_set(diag, 0, "outputs: exported by a different wallet (public keys "
                          "do not match the open wallet)");
        return MW_ERR_KEY_MISMATCH;
    }

    uint64_t offset = 0, total = 0, count = 0;
    if (!read_marker(&r, 3)) {
        diag_set(diag, r.pos, "outputs: not an export format 4 payload (tuple marker)");
        return MW_ERR_FORMAT;
    }
    if (!mw_read_varint(&r, &offset) || !mw_read_varint(&r, &total) ||
        !mw_read_varint(&r, &count)) {
        diag_set(diag, r.pos, "outputs: truncated header");
        return MW_ERR_FORMAT;
    }
    if (!count_fits(&r, count, ETD_MIN_SIZE)) {
        diag_set(diag, r.pos, "outputs: %llu records do not fit a %u-byte file",
                 (unsigned long long)count, (unsigned)len);
        return MW_ERR_FORMAT;
    }
    if (count > MW_MAX_EXPORTED_OUTPUTS) {
        diag_set(diag, r.pos, "outputs: %llu records, the device handles at most %u "
                              "per file", (unsigned long long)count,
                 (unsigned)MW_MAX_EXPORTED_OUTPUTS);
        return MW_ERR_TOO_MANY;
    }
    if (offset > 0xffffffffULL) {
        // The key image file carries the offset as a u32.
        diag_set(diag, r.pos, "outputs: offset %llu out of range",
                 (unsigned long long)offset);
        return MW_ERR_RANGE;
    }

    it->data = plaintext;
    it->len = len;
    it->pos = r.pos;
    it->offset = offset;
    it->total = total;
    it->count = count;
    it->next = 0;
    return MW_OK;
}

mw_err_t mw_outputs_next(mw_outputs_iter_t* it, mw_exported_output_t* out,
                         bool* done, mw_ff_diag_t* diag)
{
    if (it == NULL || out == NULL || done == NULL || it->data == NULL) {
        return MW_ERR_INVALID_ARG;
    }
    *done = false;
    if (it->next >= it->count) {
        // check_stream_state(): everything must have been consumed.
        if (it->pos != it->len) {
            diag_set(diag, it->pos, "outputs: %u unexpected bytes after the last record",
                     (unsigned)(it->len - it->pos));
            return MW_ERR_FORMAT;
        }
        *done = true;
        return MW_OK;
    }

    mw_reader_t r;
    mw_reader_init(&r, it->data, it->len);
    r.pos = it->pos;
    mw_err_t e = read_etd(&r, out, it->next, diag);
    if (e != MW_OK) {
        return e;
    }
    it->pos = r.pos;
    it->next++;
    return MW_OK;
}

// --------------------------------------------------------- key image file
// layout (wallet2::export_key_images_to_str):
//     u32 offset (little endian, NOT a varint)
//     spend_public_key(32) view_public_key(32)
//     count * ( key_image(32) || signature(64) )
// The public keys are mandatory: import_key_images_from_str() compares them
// against the importing account and rejects the file otherwise.
mw_err_t mw_build_keyimages(const mw_account_keys_t* keys,
                            const mw_exported_key_image_t* items, uint32_t count,
                            uint64_t offset, uint8_t* out, size_t out_cap,
                            size_t* out_len)
{
    if (out_len == NULL || keys == NULL || (items == NULL && count != 0)) {
        return MW_ERR_INVALID_ARG;
    }
    if (count > MW_MAX_EXPORTED_OUTPUTS) {
        return MW_ERR_TOO_MANY;
    }
    if (offset > 0xffffffffULL) {
        return MW_ERR_RANGE;
    }

    const size_t total = 4u + 64u + (size_t)count * (32u + MW_SIG_LEN);
    *out_len = total;
    if (out == NULL) {
        return MW_OK;                                  // size query
    }
    if (out_cap < total) {
        return MW_ERR_MEMORY;
    }

    mw_writer_t w;
    mw_writer_init(&w, out, out_cap);
    mw_write_u32(&w, (uint32_t)offset);
    mw_write_point(&w, &keys->pub.spend);
    mw_write_point(&w, &keys->pub.view);
    for (uint32_t i = 0; i < count; ++i) {
        mw_write_point(&w, &items[i].image);
        mw_write_scalar(&w, &items[i].sig.c);
        mw_write_scalar(&w, &items[i].sig.r);
    }
    if (w.overflow) {
        return MW_ERR_MEMORY;
    }
    *out_len = w.pos;
    return MW_OK;
}

// ------------------------------------------------------ unsigned tx set
// cryptonote::tx_destination_entry
//   FIELD(original)       std::string
//   VARINT_FIELD(amount)
//   FIELD(addr)           spend(32) view(32)
//   FIELD(is_subaddress)  bool
//   FIELD(is_integrated)  bool
#define DEST_MIN_SIZE (1 + 1 + 64 + 1 + 1)
#define DEST_ORIGINAL_MAX 1024

typedef struct {
    uint64_t    amount;
    mw_pubkey_t spend;
    mw_pubkey_t view;
    bool        is_subaddress;
    bool        is_integrated;
} dest_rec_t;

static bool read_bool(mw_reader_t* r, bool* out)
{
    uint8_t b = 0;
    if (!mw_read_u8(r, &b)) {
        return false;
    }
    if (b > 1) {                                 // binary_archive refuses it too
        r->overflow = true;
        return false;
    }
    *out = (b != 0);
    return true;
}

static mw_err_t read_dest(mw_reader_t* r, dest_rec_t* d, const char* what,
                          uint32_t index, mw_ff_diag_t* diag)
{
    uint64_t n = 0;
    const size_t at = r->pos;
    memset(d, 0, sizeof(*d));
    if (!mw_read_varint(r, &n) || n > DEST_ORIGINAL_MAX || !mw_skip(r, (size_t)n) ||
        !mw_read_varint(r, &d->amount) ||
        !mw_read_point(r, &d->spend) || !mw_read_point(r, &d->view) ||
        !read_bool(r, &d->is_subaddress) || !read_bool(r, &d->is_integrated)) {
        diag_set(diag, at, "%s #%u: malformed destination", what, (unsigned)index);
        return MW_ERR_FORMAT;
    }
    return MW_OK;
}

// cryptonote::tx_source_entry
//   FIELD(outputs)                     vector<pair<u64, ctkey>>
//                                      pair: varint 2, varint index, 64 bytes
//   FIELD(real_output)                 u64, 8 bytes
//   FIELD(real_out_tx_key)             32
//   FIELD(real_out_additional_tx_keys) varint n, n*32
//   FIELD(real_output_in_tx_index)     u64, 8 bytes
//   FIELD(amount)                      u64, 8 bytes
//   FIELD(rct)                         bool
//   FIELD(mask)                        32
//   FIELD(multisig_kLRki)              128
//   (real_output >= outputs.size() is refused)
#define SOURCE_MIN_SIZE (1 + (1 + 1 + 64) + 8 + 32 + 1 + 8 + 8 + 1 + 32 + 128)

typedef struct {
    uint8_t     ring_size;
    uint64_t    abs_index[MW_MAX_RING_SIZE];
    mw_ctkey_t  ring[MW_MAX_RING_SIZE];
    uint64_t    real_output;
    mw_pubkey_t real_out_tx_key;
    bool        has_additional;
    mw_pubkey_t additional;
    uint64_t    real_output_in_tx_index;
    uint64_t    amount;
    bool        rct;
    mw_scalar_t mask;
} source_rec_t;

static mw_err_t read_source(mw_reader_t* r, source_rec_t* s, uint32_t index,
                            mw_ff_diag_t* diag)
{
    uint64_t n_outs = 0, n_add = 0;
    const size_t at = r->pos;
    memset(s, 0, sizeof(*s));

    if (!mw_read_varint(r, &n_outs)) {
        diag_set(diag, at, "input #%u: truncated", (unsigned)index);
        return MW_ERR_FORMAT;
    }
    if (n_outs == 0 || n_outs > MW_MAX_RING_SIZE) {
        diag_set(diag, at, "input #%u: ring size %llu (supported 1..%u)",
                 (unsigned)index, (unsigned long long)n_outs, (unsigned)MW_MAX_RING_SIZE);
        return MW_ERR_TOO_MANY;
    }
    for (uint64_t k = 0; k < n_outs; ++k) {
        if (!read_marker(r, 2) || !mw_read_varint(r, &s->abs_index[k]) ||
            !mw_read_point(r, &s->ring[k].dest) || !mw_read_point(r, &s->ring[k].mask)) {
            diag_set(diag, r->pos, "input #%u: malformed ring member %u",
                     (unsigned)index, (unsigned)k);
            return MW_ERR_FORMAT;
        }
        // wallet2 sorts the ring by global index; the relative offsets on the
        // wire are meaningless otherwise, and a repeated index is a
        // transaction the network refuses.
        if (k != 0 && s->abs_index[k] <= s->abs_index[k - 1]) {
            diag_set(diag, r->pos, "input #%u: ring indices are not strictly increasing",
                     (unsigned)index);
            return MW_ERR_FORMAT;
        }
    }
    s->ring_size = (uint8_t)n_outs;

    if (!mw_read_u64(r, &s->real_output) || !mw_read_point(r, &s->real_out_tx_key) ||
        !mw_read_varint(r, &n_add)) {
        diag_set(diag, r->pos, "input #%u: truncated", (unsigned)index);
        return MW_ERR_FORMAT;
    }
    if (s->real_output >= n_outs) {
        diag_set(diag, r->pos, "input #%u: real output %llu outside the ring",
                 (unsigned)index, (unsigned long long)s->real_output);
        return MW_ERR_RANGE;
    }
    if (!count_fits(r, n_add, 32)) {
        diag_set(diag, r->pos, "input #%u: additional keys do not fit the file",
                 (unsigned)index);
        return MW_ERR_FORMAT;
    }
    const size_t add_pos = r->pos;
    if (!mw_skip(r, (size_t)n_add * 32u) ||
        !mw_read_u64(r, &s->real_output_in_tx_index) ||
        !mw_read_u64(r, &s->amount) ||
        !read_bool(r, &s->rct) ||
        !mw_read_scalar(r, &s->mask) ||
        !mw_skip(r, 4 * 32)) {                   // multisig_kLRki
        diag_set(diag, r->pos, "input #%u: truncated", (unsigned)index);
        return MW_ERR_FORMAT;
    }
    if (s->real_output_in_tx_index >= 65536u) {
        diag_set(diag, r->pos, "input #%u: output index %llu out of range",
                 (unsigned)index, (unsigned long long)s->real_output_in_tx_index);
        return MW_ERR_RANGE;
    }
    if (s->real_output_in_tx_index < n_add) {
        memcpy(s->additional.b, r->data + add_pos + 32u * (size_t)s->real_output_in_tx_index, 32);
        s->has_additional = true;
    }
    return MW_OK;
}

// Walks one tools::wallet2::tx_construction_data, recording where its parts
// are:
//   FIELD(sources)             vector<tx_source_entry>
//   FIELD(change_dts)          tx_destination_entry
//   FIELD(splitted_dsts)       vector<tx_destination_entry>
//   FIELD(selected_transfers)  vector<size_t>        (varint elements)
//   FIELD(extra)               vector<uint8_t>
//   FIELD(unlock_time)         u64, 8 bytes
//   FIELD_N("use_rct", construction_flags)  u8
//   FIELD(rct_config)          VERSION_FIELD(0), VARINT range_proof_type,
//                              VARINT bp_version
//   FIELD(dests)               vector<tx_destination_entry>
//   FIELD(subaddr_account)     u32, 4 bytes
//   FIELD(subaddr_indices)     set<u32>              (varint elements)
static mw_err_t walk_cd(mw_reader_t* r, mw_utx_entry_t* e, uint32_t txi,
                        mw_ff_diag_t* diag)
{
    static source_rec_t s;                       // ~3 KiB, keep off the stack
    uint64_t n = 0;
    mw_err_t err;

    memset(e, 0, sizeof(*e));
    e->cd.off = (uint32_t)r->pos;

    // ---- sources
    e->sources.off = (uint32_t)r->pos;
    if (!mw_read_varint(r, &n)) {
        diag_set(diag, r->pos, "tx %u: truncated", (unsigned)txi);
        return MW_ERR_FORMAT;
    }
    if (n == 0) {
        diag_set(diag, r->pos, "tx %u: no inputs", (unsigned)txi);
        return MW_ERR_FORMAT;
    }
    if (!count_fits(r, n, SOURCE_MIN_SIZE)) {
        diag_set(diag, r->pos, "tx %u: %llu inputs do not fit the file",
                 (unsigned)txi, (unsigned long long)n);
        return MW_ERR_FORMAT;
    }
    if (n > MW_MAX_INPUTS) {
        diag_set(diag, r->pos, "tx %u: %llu inputs, the device signs at most %u",
                 (unsigned)txi, (unsigned long long)n, (unsigned)MW_MAX_INPUTS);
        return MW_ERR_TOO_MANY;
    }
    e->n_sources = (uint32_t)n;
    uint8_t ring0 = 0;
    for (uint32_t i = 0; i < e->n_sources; ++i) {
        err = read_source(r, &s, i, diag);
        if (err != MW_OK) {
            mw_memzero(&s, sizeof(s));
            return err;
        }
        // CLSAG prunable data is serialised with ONE ring size, taken from
        // the first input: mixed ring sizes cannot even be parsed back.
        if (i == 0) {
            ring0 = s.ring_size;
        } else if (s.ring_size != ring0) {
            diag_set(diag, r->pos, "tx %u: inputs have different ring sizes",
                     (unsigned)txi);
            mw_memzero(&s, sizeof(s));
            return MW_ERR_FORMAT;
        }
        if (s.amount > UINT64_MAX - e->amount_in) {
            mw_memzero(&s, sizeof(s));
            return MW_ERR_RANGE;
        }
        e->amount_in += s.amount;
    }
    mw_memzero(&s, sizeof(s));
    e->sources.len = (uint32_t)(r->pos - e->sources.off);

    // ---- change_dts
    dest_rec_t d;
    e->change_dts.off = (uint32_t)r->pos;
    err = read_dest(r, &d, "change", 0, diag);
    if (err != MW_OK) {
        return err;
    }
    e->change_dts.len = (uint32_t)(r->pos - e->change_dts.off);

    // ---- splitted_dsts
    e->splitted_dsts.off = (uint32_t)r->pos;
    if (!mw_read_varint(r, &n) || !count_fits(r, n, DEST_MIN_SIZE)) {
        diag_set(diag, r->pos, "tx %u: malformed destination list", (unsigned)txi);
        return MW_ERR_FORMAT;
    }
    if (n == 0) {
        diag_set(diag, r->pos, "tx %u: no destinations", (unsigned)txi);
        return MW_ERR_FORMAT;
    }
    if (n > MW_MAX_DESTINATIONS || n > MW_MAX_OUTPUTS) {
        diag_set(diag, r->pos, "tx %u: %llu outputs, at most %u are allowed",
                 (unsigned)txi, (unsigned long long)n, (unsigned)MW_MAX_OUTPUTS);
        return MW_ERR_TOO_MANY;
    }
    e->n_splitted = (uint32_t)n;
    for (uint32_t i = 0; i < e->n_splitted; ++i) {
        err = read_dest(r, &d, "destination", i, diag);
        if (err != MW_OK) {
            return err;
        }
        if (d.amount > UINT64_MAX - e->amount_out) {
            return MW_ERR_RANGE;
        }
        e->amount_out += d.amount;
    }
    e->splitted_dsts.len = (uint32_t)(r->pos - e->splitted_dsts.off);
    if (e->amount_out > e->amount_in) {
        diag_set(diag, r->pos, "tx %u: outputs exceed inputs", (unsigned)txi);
        return MW_ERR_BALANCE;
    }

    // ---- selected_transfers
    e->selected_transfers.off = (uint32_t)r->pos;
    if (!mw_read_varint(r, &n) || !count_fits(r, n, 1)) {
        diag_set(diag, r->pos, "tx %u: malformed selected_transfers", (unsigned)txi);
        return MW_ERR_FORMAT;
    }
    for (uint64_t i = 0; i < n; ++i) {
        uint64_t v;
        if (!mw_read_varint(r, &v)) {
            diag_set(diag, r->pos, "tx %u: malformed selected_transfers", (unsigned)txi);
            return MW_ERR_FORMAT;
        }
    }
    e->selected_transfers.len = (uint32_t)(r->pos - e->selected_transfers.off);

    // ---- extra
    if (!mw_read_varint(r, &n) || !count_fits(r, n, 1)) {
        diag_set(diag, r->pos, "tx %u: malformed extra", (unsigned)txi);
        return MW_ERR_FORMAT;
    }
    if (n > MW_MAX_TX_EXTRA) {
        diag_set(diag, r->pos, "tx %u: extra of %llu bytes is too large",
                 (unsigned)txi, (unsigned long long)n);
        return MW_ERR_TOO_MANY;
    }
    e->extra.off = (uint32_t)r->pos;
    e->extra.len = (uint32_t)n;
    mw_skip(r, (size_t)n);

    // ---- unlock_time, flags, rct_config
    uint64_t rp = 0, bp = 0;
    if (!mw_read_u64(r, &e->unlock_time) || !mw_read_u8(r, &e->construction_flags) ||
        !mw_read_varint(r, &n) /* RCTConfig VERSION_FIELD */ ||
        !mw_read_varint(r, &rp) || !mw_read_varint(r, &bp)) {
        diag_set(diag, r->pos, "tx %u: truncated construction flags", (unsigned)txi);
        return MW_ERR_FORMAT;
    }
    if (rp > 0xffffffffULL || bp > 0xffffffffULL) {
        return MW_ERR_RANGE;
    }
    e->range_proof_type = (uint32_t)rp;
    e->bp_version = (uint32_t)bp;

    // ---- dests
    e->dests.off = (uint32_t)r->pos;
    if (!mw_read_varint(r, &n) || !count_fits(r, n, DEST_MIN_SIZE)) {
        diag_set(diag, r->pos, "tx %u: malformed dests", (unsigned)txi);
        return MW_ERR_FORMAT;
    }
    e->n_dests = (uint32_t)n;
    for (uint32_t i = 0; i < e->n_dests; ++i) {
        err = read_dest(r, &d, "dest", i, diag);
        if (err != MW_OK) {
            return err;
        }
    }
    e->dests.len = (uint32_t)(r->pos - e->dests.off);

    // ---- subaddr_account, subaddr_indices
    if (!mw_read_u32(r, &e->subaddr_account)) {
        diag_set(diag, r->pos, "tx %u: truncated subaddress account", (unsigned)txi);
        return MW_ERR_FORMAT;
    }
    e->subaddr_indices.off = (uint32_t)r->pos;
    if (!mw_read_varint(r, &n) || !count_fits(r, n, 1)) {
        diag_set(diag, r->pos, "tx %u: malformed subaddress indices", (unsigned)txi);
        return MW_ERR_FORMAT;
    }
    e->n_subaddr_indices = (uint32_t)n;
    for (uint64_t i = 0; i < n; ++i) {
        uint64_t v;
        if (!mw_read_varint(r, &v) || v > 0xffffffffULL) {
            diag_set(diag, r->pos, "tx %u: malformed subaddress indices", (unsigned)txi);
            return MW_ERR_FORMAT;
        }
    }
    e->subaddr_indices.len = (uint32_t)(r->pos - e->subaddr_indices.off);

    e->cd.len = (uint32_t)(r->pos - e->cd.off);
    return MW_OK;
}

mw_err_t mw_unsigned_set_parse(const uint8_t* plaintext, size_t len,
                               mw_unsigned_set_t* out, mw_ff_diag_t* diag)
{
    if (plaintext == NULL || out == NULL) {
        return MW_ERR_INVALID_ARG;
    }
    memset(out, 0, sizeof(*out));
    if (len > 0xffffffffu) {
        return MW_ERR_TOO_MANY;
    }

    mw_reader_t r;
    mw_reader_init(&r, plaintext, len);

    uint64_t version = 0, n_txes = 0;
    if (!mw_read_varint(&r, &version)) {
        diag_set(diag, 0, "unsigned set: empty payload");
        return MW_ERR_FORMAT;
    }
    if (version == 0 || version > 2) {
        diag_set(diag, 0, "unsigned set: version %llu is not supported (1 and 2 are)",
                 (unsigned long long)version);
        return MW_ERR_VERSION;
    }
    if (!mw_read_varint(&r, &n_txes)) {
        diag_set(diag, r.pos, "unsigned set: truncated");
        return MW_ERR_FORMAT;
    }
    if (n_txes == 0) {
        diag_set(diag, r.pos, "unsigned set: contains no transaction");
        return MW_ERR_FORMAT;
    }
    if (n_txes > MW_MAX_TXES_PER_SET) {
        diag_set(diag, r.pos, "unsigned set: %llu transactions, the device signs at "
                              "most %u at a time", (unsigned long long)n_txes,
                 (unsigned)MW_MAX_TXES_PER_SET);
        return MW_ERR_NOT_SUPPORTED;
    }
    out->version = (uint32_t)version;
    out->n_txes = (uint32_t)n_txes;

    for (uint32_t i = 0; i < out->n_txes; ++i) {
        mw_err_t e = walk_cd(&r, &out->tx[i], i, diag);
        if (e != MW_OK) {
            return e;
        }
    }

    // new_transfers
    uint64_t offset = 0, total = 0, count = 0;
    if (version == 1) {
        // std::pair<size_t, std::vector<exported_transfer_details>>
        if (!read_marker(&r, 2) || !mw_read_varint(&r, &offset) ||
            !mw_read_varint(&r, &count)) {
            diag_set(diag, r.pos, "unsigned set: malformed transfer list");
            return MW_ERR_FORMAT;
        }
        total = offset + count;
    } else {
        // std::tuple<u64, u64, std::vector<exported_transfer_details>>
        if (!read_marker(&r, 3) || !mw_read_varint(&r, &offset) ||
            !mw_read_varint(&r, &total) || !mw_read_varint(&r, &count)) {
            diag_set(diag, r.pos, "unsigned set: malformed transfer list");
            return MW_ERR_FORMAT;
        }
    }
    if (!count_fits(&r, count, ETD_MIN_SIZE)) {
        diag_set(diag, r.pos, "unsigned set: %llu transfers do not fit the file",
                 (unsigned long long)count);
        return MW_ERR_FORMAT;
    }
    out->nt_offset = offset;
    out->nt_total = total;
    out->nt_count = count;
    out->nt_pos = r.pos;
    for (uint64_t i = 0; i < count; ++i) {
        mw_exported_output_t o;
        mw_err_t e = read_etd(&r, &o, i, diag);
        if (e != MW_OK) {
            return e;
        }
    }
    out->nt_end = r.pos;

    if (mw_remaining(&r) != 0 || r.overflow) {
        diag_set(diag, r.pos, "unsigned set: %u unexpected trailing bytes",
                 (unsigned)mw_remaining(&r));
        return MW_ERR_FORMAT;
    }
    out->data = plaintext;
    out->len = len;
    return MW_OK;
}

void mw_unsigned_set_new_transfers(const mw_unsigned_set_t* set,
                                   mw_outputs_iter_t* it)
{
    if (it == NULL) {
        return;
    }
    memset(it, 0, sizeof(*it));
    if (set == NULL || set->data == NULL) {
        return;
    }
    it->data = set->data;
    it->len = set->nt_end;
    it->pos = set->nt_pos;
    it->offset = set->nt_offset;
    it->total = set->nt_total;
    it->count = set->nt_count;
}

static void dest_to_model(const dest_rec_t* d, mw_tx_destination_t* out)
{
    memset(out, 0, sizeof(*out));
    out->amount = d->amount;
    out->addr.spend = d->spend;
    out->addr.view = d->view;
    out->is_subaddress = d->is_subaddress;
    out->is_integrated = d->is_integrated && !d->is_subaddress;
    out->addr.type = d->is_subaddress ? MW_ADDR_SUBADDRESS
                                      : (out->is_integrated ? MW_ADDR_INTEGRATED
                                                            : MW_ADDR_STANDARD);
    out->addr.has_payment_id = false;            // the id travels in extra
}

mw_err_t mw_unsigned_set_load_tx(const mw_unsigned_set_t* set, uint32_t index,
                                 mw_transaction_t* tx, mw_ff_diag_t* diag)
{
    static source_rec_t s;
    if (set == NULL || tx == NULL || set->data == NULL) {
        return MW_ERR_INVALID_ARG;
    }
    if (index >= set->n_txes) {
        return MW_ERR_RANGE;
    }
    const mw_utx_entry_t* e = &set->tx[index];
    memset(tx, 0, sizeof(*tx));

    // ---- what kind of transaction this is
    if ((e->construction_flags & 0x01u) == 0) {
        diag_set(diag, e->cd.off, "tx %u: not a RingCT transaction", (unsigned)index);
        return MW_ERR_NOT_SUPPORTED;
    }
    // genRctSimple(): range_proof_type > Borromean selects bulletproofs, and
    // bp_version 0 or >= 4 selects Bulletproofs+ (RCTTypeBulletproofPlus).
    if (e->range_proof_type == 0 || (e->bp_version != 0 && e->bp_version < 4)) {
        diag_set(diag, e->cd.off, "tx %u: range proof %u / bulletproof v%u is not "
                                  "supported (only Bulletproofs+)", (unsigned)index,
                 (unsigned)e->range_proof_type, (unsigned)e->bp_version);
        return MW_ERR_NOT_SUPPORTED;
    }
    // wallet2::sign_tx(): THROW_WALLET_EXCEPTION_IF(sd.unlock_time, nonzero_unlock_time)
    if (e->unlock_time != 0) {
        diag_set(diag, e->cd.off, "tx %u: non-zero unlock time is not supported",
                 (unsigned)index);
        return MW_ERR_NOT_SUPPORTED;
    }
    tx->version = 2;
    tx->unlock_time = 0;
    tx->rct_type = 6;
    tx->use_view_tags = (e->construction_flags & 0x02u) != 0;

    mw_reader_t r;
    mw_reader_init(&r, set->data, set->len);

    // ---- sources
    r.pos = e->sources.off;
    uint64_t n = 0;
    mw_read_varint(&r, &n);
    for (uint32_t i = 0; i < e->n_sources; ++i) {
        mw_err_t err = read_source(&r, &s, i, diag);
        if (err != MW_OK) {
            mw_memzero(&s, sizeof(s));
            return err;
        }
        mw_tx_source_t* src = &tx->sources[i];
        src->ring_size = s.ring_size;
        for (uint8_t k = 0; k < s.ring_size; ++k) {
            src->ring[k] = s.ring[k];
            src->key_offsets[k] = (k == 0) ? s.abs_index[0]
                                           : s.abs_index[k] - s.abs_index[k - 1];
        }
        src->real_output_index = (uint8_t)s.real_output;
        src->real_out_tx_key = s.real_out_tx_key;
        src->has_additional_key = s.has_additional;
        src->real_out_additional_key = s.additional;
        src->real_output_in_tx_index = (uint32_t)s.real_output_in_tx_index;
        src->amount = s.amount;
        src->rct = s.rct;
        src->mask = s.mask;
        if (!mw_sc_check(&src->mask)) {
            diag_set(diag, r.pos, "input #%u: non-canonical mask", (unsigned)i);
            mw_memzero(&s, sizeof(s));
            return MW_ERR_FORMAT;
        }
    }
    mw_memzero(&s, sizeof(s));
    tx->n_inputs = (uint8_t)e->n_sources;

    // ---- change_dts
    dest_rec_t d;
    r.pos = e->change_dts.off;
    if (read_dest(&r, &d, "change", 0, diag) != MW_OK) {
        return MW_ERR_FORMAT;
    }
    {
        static const uint8_t zero[32] = {0};
        const bool null_addr = memcmp(d.spend.b, zero, 32) == 0 &&
                               memcmp(d.view.b, zero, 32) == 0;
        tx->has_change_addr = !null_addr;
        tx->change_addr.spend = d.spend;
        tx->change_addr.view = d.view;
        tx->change_addr.type = d.is_subaddress ? MW_ADDR_SUBADDRESS : MW_ADDR_STANDARD;
        tx->change_is_subaddress = d.is_subaddress;
        tx->change_amount = d.amount;
    }

    // ---- splitted_dsts: what the transaction pays
    r.pos = e->splitted_dsts.off;
    mw_read_varint(&r, &n);
    for (uint32_t i = 0; i < e->n_splitted; ++i) {
        if (read_dest(&r, &d, "destination", i, diag) != MW_OK) {
            return MW_ERR_FORMAT;
        }
        dest_to_model(&d, &tx->destinations[i]);
    }
    tx->n_destinations = (uint8_t)e->n_splitted;
    tx->n_outputs = tx->n_destinations;
    for (uint8_t i = 0; i < tx->n_outputs; ++i) {
        tx->out_dest[i] = i;
        tx->outputs[i].amount = tx->destinations[i].amount;
    }

    // ---- extra
    memcpy(tx->extra_in, set->data + e->extra.off, e->extra.len);
    tx->extra_in_len = (uint16_t)e->extra.len;

    // ---- subaddress hints
    tx->subaddr_account = e->subaddr_account;
    r.pos = e->subaddr_indices.off;
    mw_read_varint(&r, &n);
    for (uint64_t i = 0; i < n; ++i) {
        uint64_t v = 0;
        mw_read_varint(&r, &v);
        if (tx->n_subaddr_hints < MW_MAX_SUBADDR_HINTS) {
            tx->subaddr_hints[tx->n_subaddr_hints++] = (uint32_t)v;
        }
    }
    if (r.overflow) {
        return MW_ERR_FORMAT;                    // cannot happen after parse()
    }

    tx->fee = e->amount_in - e->amount_out;
    return MW_OK;
}

// -------------------------------------------------------- signed tx set
static void write_span(mw_writer_t* w, const mw_unsigned_set_t* set, mw_span_t sp)
{
    mw_write_bytes(w, set->data + sp.off, sp.len);
}

// pending_tx::key_images: boost::to_string(key_image) + " " per input, i.e.
// "<hex> " (epee::to_hex::formatted wraps the hex in angle brackets).
static void write_key_image_string(mw_writer_t* w, const mw_keyimage_t* kis,
                                   uint8_t n)
{
    static const char hexd[] = "0123456789abcdef";
    mw_write_varint(w, (uint64_t)n * 67u);       // '<' + 64 hex + '>' + ' '
    for (uint8_t i = 0; i < n; ++i) {
        char buf[67];
        buf[0] = '<';
        for (int k = 0; k < 32; ++k) {
            buf[1 + 2 * k] = hexd[kis[i].b[k] >> 4];
            buf[2 + 2 * k] = hexd[kis[i].b[k] & 0x0f];
        }
        buf[65] = '>';
        buf[66] = ' ';
        mw_write_bytes(w, buf, sizeof(buf));
    }
}

mw_err_t mw_build_signed_set(const mw_unsigned_set_t* set,
                             const mw_signed_ptx_t* ptx, uint32_t n_ptx,
                             const mw_ki_pair_t* kis, uint32_t n_kis,
                             uint8_t* out, size_t out_cap, size_t* out_len)
{
    if (set == NULL || set->data == NULL || out_len == NULL ||
        (ptx == NULL && n_ptx != 0) || (kis == NULL && n_kis != 0)) {
        return MW_ERR_INVALID_ARG;
    }
    if (n_ptx != set->n_txes) {
        return MW_ERR_INVALID_ARG;               // one pending_tx per unsigned tx
    }

    // Size first (a writer without a buffer counts nothing, so compute).
    size_t need = 10 + 10 + 10 + 10;
    for (uint32_t i = 0; i < n_ptx; ++i) {
        const mw_utx_entry_t* e = &set->tx[i];
        need += 1 + ptx[i].tx_blob_len + 8 + 8 + 1 + e->change_dts.len +
                e->selected_transfers.len + 10 + (size_t)ptx[i].n_vin * 67u + 32 + 1 +
                e->dests.len + e->cd.len + 1 + 32;
    }
    need += (size_t)n_kis * (1 + 32 + 32);
    if (out == NULL) {
        *out_len = need;                         // upper bound
        return MW_OK;
    }

    mw_writer_t w;
    mw_writer_init(&w, out, out_cap);

    mw_write_varint(&w, 0);                      // signed_tx_set VERSION_FIELD(0)
    mw_write_varint(&w, n_ptx);                  // ptx
    for (uint32_t i = 0; i < n_ptx; ++i) {
        const mw_utx_entry_t* e = &set->tx[i];
        static const uint8_t identity[32] = { 1 };
        static const uint8_t zero32[32] = { 0 };

        mw_write_varint(&w, 1);                  // pending_tx VERSION_FIELD(1)
        mw_write_bytes(&w, ptx[i].tx_blob, ptx[i].tx_blob_len);   // FIELD(tx)
        mw_write_u64(&w, 0);                     // dust
        mw_write_u64(&w, ptx[i].fee);            // fee
        mw_write_u8(&w, 0);                      // dust_added_to_fee
        write_span(&w, set, e->change_dts);      // change_dts
        write_span(&w, set, e->selected_transfers);
        write_key_image_string(&w, ptx[i].vin_key_images, ptx[i].n_vin);
        // "don't send it back to the untrusted view wallet"
        mw_write_bytes(&w, identity, 32);        // tx_key = rct::identity()
        mw_write_varint(&w, 0);                  // additional_tx_keys
        write_span(&w, set, e->dests);           // dests
        write_span(&w, set, e->cd);              // construction_data
        mw_write_varint(&w, 0);                  // multisig_sigs
        mw_write_bytes(&w, zero32, 32);          // multisig_tx_key_entropy
    }
    mw_write_varint(&w, 0);                      // key_images (Feather: empty)
    mw_write_varint(&w, n_kis);                  // tx_key_images
    for (uint32_t i = 0; i < n_kis; ++i) {
        mw_write_varint(&w, 2);                  // std::pair
        mw_write_point(&w, &kis[i].out_pub);
        mw_write_point(&w, &kis[i].image);
    }

    if (w.overflow) {
        *out_len = 0;
        return MW_ERR_MEMORY;
    }
    *out_len = w.pos;
    return MW_OK;
}

// ------------------------------------------------ serialized transaction
// cryptonote::transaction (v2) = prefix || rct base || rct prunable, exactly
// what t_serializable_object_to_blob() produces and what FIELD(tx) embeds.
mw_err_t mw_build_signed_tx(const mw_transaction_t* tx,
                            const uint8_t* rct_blob, size_t rct_len,
                            uint8_t* out, size_t out_cap, size_t* out_len)
{
    if (tx == NULL || out_len == NULL || (rct_blob == NULL && rct_len != 0)) {
        return MW_ERR_INVALID_ARG;
    }
    if (tx->n_inputs == 0 || tx->n_inputs > MW_MAX_INPUTS ||
        tx->n_outputs == 0 || tx->n_outputs > MW_MAX_OUTPUTS) {
        return MW_ERR_TOO_MANY;
    }
    if (tx->tx_extra_len > MW_MAX_TX_EXTRA) {
        return MW_ERR_TOO_MANY;
    }

    if (out == NULL) {
        size_t n = mw_varint_size(tx->version) + mw_varint_size(tx->unlock_time) +
                   mw_varint_size(tx->n_inputs);
        for (uint8_t i = 0; i < tx->n_inputs; ++i) {
            const mw_tx_source_t* s = &tx->sources[i];
            n += 1 + mw_varint_size(0) + mw_varint_size(s->ring_size) + 32;
            for (uint8_t k = 0; k < s->ring_size; ++k) {
                n += mw_varint_size(s->key_offsets[k]);
            }
        }
        n += mw_varint_size(tx->n_outputs);
        for (uint8_t i = 0; i < tx->n_outputs; ++i) {
            n += mw_varint_size(0) + 1 + 32 + (tx->outputs[i].has_view_tag ? 1u : 0u);
        }
        n += mw_varint_size(tx->tx_extra_len) + tx->tx_extra_len + rct_len;
        *out_len = n;
        return MW_OK;
    }

    mw_writer_t w;
    mw_writer_init(&w, out, out_cap);

    mw_write_varint(&w, tx->version);
    mw_write_varint(&w, tx->unlock_time);

    mw_write_varint(&w, tx->n_inputs);
    for (uint8_t i = 0; i < tx->n_inputs; ++i) {
        const mw_tx_source_t* s = &tx->sources[i];
        if (s->ring_size == 0 || s->ring_size > MW_MAX_RING_SIZE) {
            return MW_ERR_TOO_MANY;
        }
        mw_write_u8(&w, 0x02);                         // txin_to_key
        mw_write_varint(&w, 0);                        // amount (RingCT)
        mw_write_varint(&w, s->ring_size);
        for (uint8_t k = 0; k < s->ring_size; ++k) {
            mw_write_varint(&w, s->key_offsets[k]);
        }
        mw_write_point(&w, &s->key_image);
    }

    mw_write_varint(&w, tx->n_outputs);
    for (uint8_t i = 0; i < tx->n_outputs; ++i) {
        const mw_tx_output_t* o = &tx->outputs[i];
        mw_write_varint(&w, 0);
        mw_write_u8(&w, o->has_view_tag ? 0x03 : 0x02);
        mw_write_point(&w, &o->out_pubkey);
        if (o->has_view_tag) {
            mw_write_u8(&w, o->view_tag);
        }
    }

    mw_write_varint(&w, tx->tx_extra_len);
    mw_write_bytes(&w, tx->tx_extra, tx->tx_extra_len);
    mw_write_bytes(&w, rct_blob, rct_len);

    if (w.overflow) {
        *out_len = 0;
        return MW_ERR_MEMORY;
    }
    *out_len = w.pos;
    return MW_OK;
}
