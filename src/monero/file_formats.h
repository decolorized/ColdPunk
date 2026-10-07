// Monero / Feather wallet exchange files (TZ section 9, task 3 item 4).
//
// Every file has the layout
//
//     magic [version byte] || iv(8) || chacha20(plaintext) || signature(64)
//
// with the ChaCha key derived as cn_slow_hash(view_secret_key) (kdf_rounds 1)
// and the signature a Schnorr signature over keccak256(iv || ct) under the
// VIEW secret key - wallet2::encrypt_with_view_secret_key(). Signing with the
// spend key would make every file unreadable by Feather and Monero GUI.
//
// The four payloads are Monero's own binary_archive serialisation of
// wallet2 structures. The layouts below were taken from the sources of the
// Feather fork of wallet2 (feather-wallet/monero, the one Feather ships), and
// cross-checked against monero-project/monero release-v0.18:
//
//   outputs     "Monero output export\004"
//               spend_pub(32) view_pub(32)
//               tuple<u64 offset, u64 total, vector<exported_transfer_details>>
//   key images  "Monero key image export\003"
//               u32 offset(LE) spend_pub(32) view_pub(32) N*(ki(32) sig(64))
//   unsigned    "Monero unsigned tx set" '\005'
//               unsigned_tx_set VERSION 2: txes, new_transfers (version 1:
//               pair<size_t, vector<etd>> instead of the tuple)
//   signed      "Monero signed tx set" '\005'
//               signed_tx_set VERSION 0: ptx, key_images, tx_key_images
//
// Binary archive rules this module follows (serialization/*.h):
//   FIELD(uintN)           fixed width, little endian (u64 8, u32 4, u8 1)
//   VARINT_FIELD / VERSION varint
//   bool                   one byte
//   std::string / vector   varint count, then the elements; unsigned integer
//                          elements wider than one byte are varints
//   std::pair              varint 2, then both elements (u64 as varint)
//   std::tuple<3>          varint 3, then the elements (u64 as varint)
//   variant                one tag byte, then the alternative
//   blobs (keys, ctkey...) raw bytes
#ifndef MW_FILE_FORMATS_H
#define MW_FILE_FORMATS_H

#include "monero_types.h"
#include "key_image.h"
#include "tx.h"
#include "../crypto/chacha.h"

#ifdef __cplusplus
extern "C" {
#endif

#define MW_MAGIC_OUTPUTS      "Monero output export\004"
#define MW_MAGIC_OUTPUTS_LEN  21
#define MW_MAGIC_KEYIMAGES    "Monero key image export\003"
// 24, not the 26 printed in TZ 9.2: 23 characters plus the version byte.
#define MW_MAGIC_KEYIMAGES_LEN 24
// "Monero unsigned tx set" is 22 characters; wallet2's UNSIGNED_TX_PREFIX
// appends the version character ('\005'), which the envelope carries as a
// separate version byte (MW_FILE_UNSIGNED_TX.has_version).
#define MW_MAGIC_UNSIGNED_TX  "Monero unsigned tx set"
#define MW_MAGIC_UNSIGNED_TX_LEN 22
#define MW_MAGIC_SIGNED_TX    "Monero signed tx set"
#define MW_MAGIC_SIGNED_TX_LEN 20
// Recognised only so it can be refused with a clear message.
#define MW_MAGIC_MULTISIG_TX  "Monero multisig unsigned tx set"
#define MW_MAGIC_MULTISIG_TX_LEN 31

#define MW_UNSIGNED_TX_VERSION 0x05
#define MW_SIG_LEN 64
#define MW_IV_LEN  8

// Largest key image batch the device produces in one file. Bounded by the
// USB link payload (68 + 96 * N bytes must fit MW_LINK_MAX_PAYLOAD).
#define MW_MAX_EXPORTED_OUTPUTS 2700

// At most this many transactions in one unsigned set (wallet2 splits big
// transfers into several; each one is confirmed and signed on the device).
#define MW_MAX_TXES_PER_SET   4
// subaddr_indices hints kept per transaction (inputs' minor indices).
#define MW_MAX_SUBADDR_HINTS  16

// ---------------- diagnostics ----------------------------------------------
// Parsers explain WHY a file was refused: the text goes to the screen and,
// in full, to the host log. It never contains key material - offsets,
// counts, indices and the name of the offending field only.
typedef struct {
    size_t offset;          // plaintext offset where parsing stopped
    char   what[112];
} mw_ff_diag_t;

// ---------------- file detection -------------------------------------------
typedef enum {
    MW_FMT_UNKNOWN = 0,
    MW_FMT_OUTPUTS,
    MW_FMT_KEYIMAGES,
    MW_FMT_UNSIGNED_TX,
    MW_FMT_SIGNED_TX,
    MW_FMT_MULTISIG,           // multisig tx set - not supported
    MW_FMT_UNSUPPORTED_VERSION // right family, version this device cannot read
} mw_file_format_t;

// Classifies a file by its magic, regardless of its name or extension.
mw_file_format_t mw_file_detect(const uint8_t* data, size_t len);
const char*      mw_file_format_name(mw_file_format_t f);

// ---------------- envelope -------------------------------------------------
typedef struct {
    const uint8_t* magic;
    size_t         magic_len;
    uint8_t        version;      // valid when has_version
    bool           has_version;
} mw_file_kind_t;

extern const mw_file_kind_t MW_FILE_OUTPUTS;
extern const mw_file_kind_t MW_FILE_KEYIMAGES;
extern const mw_file_kind_t MW_FILE_UNSIGNED_TX;
extern const mw_file_kind_t MW_FILE_SIGNED_TX;

// Checks magic/version, verifies the Schnorr signature with the account's
// view key and decrypts into `plaintext`. `plaintext` may alias `file`
// (decryption runs forward and the plaintext starts before the ciphertext).
// MW_ERR_SIGNATURE means "not made by this wallet's view key": the file
// belongs to a different wallet (or a different passphrase variant).
mw_err_t mw_file_open(const mw_file_kind_t* kind,
                      const uint8_t* file, size_t file_len,
                      const mw_account_keys_t* keys,
                      uint8_t* plaintext, size_t plaintext_cap,
                      size_t* plaintext_len);

// Encrypts + signs a plaintext blob into the on-disk envelope. out == NULL
// queries the size.
mw_err_t mw_file_seal(const mw_file_kind_t* kind,
                      const uint8_t* plaintext, size_t plaintext_len,
                      const mw_account_keys_t* keys,
                      uint8_t* out, size_t out_cap, size_t* out_len);

// The envelope's ChaCha key: cn_slow_hash(view secret key), slow on the
// device (~16 s). The _k variants take a key derived earlier with
// mw_file_key() (NULL derives it); the caller wipes it.
void     mw_file_key(const mw_account_keys_t* keys, mw_chacha_key* key_out);
mw_err_t mw_file_open_k(const mw_file_kind_t* kind,
                        const uint8_t* file, size_t file_len,
                        const mw_account_keys_t* keys, const mw_chacha_key* file_key,
                        uint8_t* plaintext, size_t plaintext_cap,
                        size_t* plaintext_len);
mw_err_t mw_file_seal_k(const mw_file_kind_t* kind,
                        const uint8_t* plaintext, size_t plaintext_len,
                        const mw_account_keys_t* keys, const mw_chacha_key* file_key,
                        uint8_t* out, size_t out_cap, size_t* out_len);

// Schnorr signature over a 32-byte hash, as Monero's generate_signature.
mw_err_t mw_schnorr_sign(const uint8_t hash[32], const mw_pubkey_t* pub,
                         const mw_seckey_t* sec, uint8_t sig_out[MW_SIG_LEN]);
mw_err_t mw_schnorr_verify(const uint8_t hash[32], const mw_pubkey_t* pub,
                           const uint8_t sig[MW_SIG_LEN]);

// ---------------- outputs (exported_transfer_details) ----------------------
// Streaming reader: the records are decoded one at a time, so a file with
// thousands of outputs needs no per-record array.
typedef struct {
    const uint8_t* data;
    size_t         len;
    size_t         pos;          // next record
    uint64_t       offset;       // tuple<0>: hot wallet index of record 0
    uint64_t       total;        // tuple<1>: hot wallet transfer count
    uint64_t       count;        // records in the vector
    uint64_t       next;         // records already returned
} mw_outputs_iter_t;

// Parses the header of a decrypted outputs payload. MW_ERR_KEY_MISMATCH when
// the embedded public keys are not this account's (a different wallet or a
// different passphrase variant).
mw_err_t mw_outputs_begin(mw_outputs_iter_t* it, const uint8_t* plaintext,
                          size_t len, const mw_account_keys_t* keys,
                          mw_ff_diag_t* diag);
// Returns the next record. *done is set (and MW_OK returned) once every
// record has been read; trailing bytes after the last one are an error.
mw_err_t mw_outputs_next(mw_outputs_iter_t* it, mw_exported_output_t* out,
                         bool* done, mw_ff_diag_t* diag);

// ---------------- key images -----------------------------------------------
// Builds the key image PLAINTEXT (seal it with mw_file_seal afterwards):
//     u32 offset || spend_pub(32) || view_pub(32) || N * (ki(32) || sig(64))
// Pass out == NULL to query the size.
mw_err_t mw_build_keyimages(const mw_account_keys_t* keys,
                            const mw_exported_key_image_t* items, uint32_t count,
                            uint64_t offset, uint8_t* out, size_t out_cap,
                            size_t* out_len);

// ---------------- unsigned tx set ------------------------------------------
typedef struct {
    uint32_t off;
    uint32_t len;
} mw_span_t;

// One tools::wallet2::tx_construction_data, located and validated.
typedef struct {
    mw_span_t cd;                  // the whole record (copied into pending_tx)
    mw_span_t sources;             // vector<tx_source_entry>, count included
    mw_span_t change_dts;          // tx_destination_entry
    mw_span_t splitted_dsts;       // vector<tx_destination_entry>
    mw_span_t selected_transfers;  // vector<size_t>
    mw_span_t extra;               // extra bytes (payload only)
    mw_span_t dests;               // vector<tx_destination_entry>
    mw_span_t subaddr_indices;     // set<u32>, count included
    uint32_t  n_sources;
    uint32_t  n_splitted;
    uint32_t  n_dests;
    uint32_t  n_subaddr_indices;
    uint64_t  unlock_time;
    uint8_t   construction_flags;  // bit0 use_rct, bit1 use_view_tags
    uint32_t  range_proof_type;
    uint32_t  bp_version;
    uint32_t  subaddr_account;
    uint64_t  amount_in;           // sum of sources
    uint64_t  amount_out;          // sum of splitted_dsts
} mw_utx_entry_t;

typedef struct {
    const uint8_t* data;           // the decrypted plaintext (not owned)
    size_t         len;
    uint32_t       version;        // unsigned_tx_set VERSION_FIELD (1 or 2)
    uint32_t       n_txes;
    mw_utx_entry_t tx[MW_MAX_TXES_PER_SET];
    // new_transfers: outputs whose key images the hot wallet requests
    uint64_t       nt_offset;
    uint64_t       nt_total;
    uint64_t       nt_count;
    size_t         nt_pos;         // first record
    size_t         nt_end;
} mw_unsigned_set_t;

// Walks and validates the whole set. Nothing secret is involved: the set is
// public data from the online wallet, authenticated by the envelope.
mw_err_t mw_unsigned_set_parse(const uint8_t* plaintext, size_t len,
                               mw_unsigned_set_t* out, mw_ff_diag_t* diag);

// Loads transaction `index` into the signer model: sources (ring, real
// output, mask, additional key), splitted destinations, change address,
// extra, subaddress hints, fee. Change flags are NOT decided here - the
// signer derives them from the change address it has verified.
mw_err_t mw_unsigned_set_load_tx(const mw_unsigned_set_t* set, uint32_t index,
                                 mw_transaction_t* tx, mw_ff_diag_t* diag);

// Reader over new_transfers (same record format as the outputs file).
void     mw_unsigned_set_new_transfers(const mw_unsigned_set_t* set,
                                       mw_outputs_iter_t* it);

// ---------------- signed tx set --------------------------------------------
// Everything the device contributes to one pending_tx.
typedef struct {
    const uint8_t*       tx_blob;      // serialized transaction (prefix + rct)
    size_t               tx_blob_len;
    uint64_t             fee;
    const mw_keyimage_t* vin_key_images; // in vin order (sorted)
    uint8_t              n_vin;
} mw_signed_ptx_t;

typedef struct {
    mw_pubkey_t   out_pub;
    mw_keyimage_t image;
} mw_ki_pair_t;

// Writes the signed_tx_set PLAINTEXT exactly as the Feather fork of
// wallet2::sign_tx() does for a cold wallet:
//   * one pending_tx per transaction, carrying the change_dts, the
//     selected_transfers, the dests and the construction data of the
//     unsigned set verbatim, the tx key replaced by the identity (it is not
//     sent back to the online wallet) and no additional tx keys;
//   * an empty key_images vector;
//   * tx_key_images: key images of our own outputs of the new transactions
//     and of every new_transfers record.
// Pass out == NULL to query the size.
mw_err_t mw_build_signed_set(const mw_unsigned_set_t* set,
                             const mw_signed_ptx_t* ptx, uint32_t n_ptx,
                             const mw_ki_pair_t* kis, uint32_t n_kis,
                             uint8_t* out, size_t out_cap, size_t* out_len);

// Serialized transaction (prefix || rct blob). out == NULL queries the size.
mw_err_t mw_build_signed_tx(const mw_transaction_t* tx,
                            const uint8_t* rct_blob, size_t rct_len,
                            uint8_t* out, size_t out_cap, size_t* out_len);

#ifdef __cplusplus
}
#endif
#endif
