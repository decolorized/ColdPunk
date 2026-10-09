// Wallet operations on exchange files (task 3, algorithm steps 4-10).
//
// Platform independent and host-tested: the screens in ui/flows.cpp only add
// the confirmations and the progress bar around these calls.
//
//   outputs file  --inspect--> confirmation --export--> key image file
//   unsigned set  --inspect--> review screen --sign-->  signed tx set
//   host request  ----------->  confirmation --------->  wallet export (JSON)
//
// Every function explains a refusal in `er->text` (one line, English,
// technical, no key material) - the firmware shows it and logs it to the
// host. The inspect steps decrypt the file IN PLACE.
#ifndef MW_WALLET_OPS_H
#define MW_WALLET_OPS_H

#include "../monero/monero_types.h"
#include "../monero/file_formats.h"
#include "../monero/sign.h"
#include "../monero/tx.h"

#ifdef __cplusplus
extern "C" {
#endif

typedef struct {
    mw_err_t err;
    char     text[176];
} mw_ops_error_t;

// Progress: `stage` is a short English label ("key images", "signing tx 1/2",
// ...), done/total a counter for the bar.
typedef void (*mw_ops_progress_fn)(void* user, const char* stage,
                                   uint32_t done, uint32_t total);

typedef struct {
    mw_ops_progress_fn progress;
    void*              user;
} mw_ops_cb_t;

// Allocator for the large scratch buffers (PSRAM on the device).
typedef struct {
    void* (*alloc)(size_t n);
    void  (*free)(void* p, size_t n);     // must wipe
} mw_ops_alloc_t;
void mw_ops_set_allocator(const mw_ops_alloc_t* a);

// Where a sealed file's plaintext must be placed so that mw_file_seal() can
// encrypt it in place (magic + version + IV in front of it).
size_t mw_ops_seal_offset(const mw_file_kind_t* kind);

// ---------------- outputs -> key images ------------------------------------
typedef struct {
    uint64_t offset;         // hot wallet index of the first output
    uint64_t total;          // hot wallet transfer count
    uint64_t count;          // outputs in the file
    uint32_t known;          // already in the key image cache
} mw_ki_export_info_t;

// Decrypts `file` in place (MW_ERR_SIGNATURE: "made by a different wallet or
// passphrase variant"), checks the account header and the record structure.
mw_err_t mw_ops_outputs_inspect(const mw_account_keys_t* keys,
                                uint8_t* file, size_t file_len, size_t* plain_len,
                                mw_ki_export_info_t* info, mw_ops_error_t* er);

// Key image cache entries that did not fit (cache full) during the last
// mw_ops_outputs_to_keyimages() / mw_ops_unsigned_sign(); 0 normally. The
// result itself is still valid, but the device cannot track those outputs.
uint32_t mw_ops_cache_overflow(void);

// Computes the key image + signature of every output (the whole file fails
// on the first output that is not ours), records them in the open key
// image cache, and writes the SEALED "Monero key image export" file.
mw_err_t mw_ops_outputs_to_keyimages(const mw_account_keys_t* keys,
                                     const uint8_t* plain, size_t plain_len,
                                     uint8_t* out, size_t out_cap, size_t* out_len,
                                     const mw_ops_cb_t* cb, mw_ops_error_t* er);

// ---------------- unsigned -> signed ---------------------------------------
typedef struct {
    uint32_t        n_txes;
    mw_tx_summary_t sum[MW_MAX_TXES_PER_SET];
    uint64_t        total_in, total_out, total_change, total_fee;
    uint32_t        n_inputs;
    uint32_t        spent_before;   // inputs already spent by an earlier
                                    // transaction signed on this device
    uint64_t        new_transfers;  // key images the online wallet requested
} mw_tx_review_t;

// Working memory for one signing session (large: keep in PSRAM).
// file_key: the envelope key derived by the inspect (cn_slow_hash, ~16 s on
// the device), reused to seal the signed set; wiped by mw_ops_unsigned_sign
// and by the caller's wiping free of the session.
typedef struct {
    mw_unsigned_set_t set;
    mw_transaction_t  tx;
    mw_signed_data_t  sd;
    mw_chacha_key     file_key;
    bool              has_file_key;
} mw_sign_session_t;

// Decrypts in place, parses the set and checks every transaction against
// the wallet before anything is shown:
//   * every input must belong to this wallet (key re-derived) and its key
//     image must be known from a key image export - otherwise the online
//     wallet has not synchronised key images and may be spending outputs
//     that are already spent (MW_ERR_NOT_SUPPORTED + explanation);
//   * every destination and the change pass mw_tx_check_destinations()
//     (MW_ERR_KEY_MISMATCH: hybrid address, change address substitution,
//     wrong subaddress flag, inputs from another account, claimed change
//     not paid); all transactions of a set must spend from one account;
//   * amounts must balance.
// `require_known_ki` = false skips the key image cache check (tests, or a
// cache that could not be loaded - the caller decides).
mw_err_t mw_ops_unsigned_inspect(const mw_account_keys_t* keys, mw_network_t net,
                                 uint8_t* file, size_t file_len,
                                 mw_sign_session_t* s, bool require_known_ki,
                                 mw_tx_review_t* review, mw_ops_error_t* er);

// Signs every transaction of the inspected set and writes the SEALED
// "Monero signed tx set" into `out`. Updates the key image cache (inputs
// marked spent, change and requested key images added).
mw_err_t mw_ops_unsigned_sign(const mw_account_keys_t* keys, mw_sign_session_t* s,
                              uint8_t* out, size_t out_cap, size_t* out_len,
                              const mw_ops_cb_t* cb, mw_ops_error_t* er);

// ---------------- wallet export --------------------------------------------
// JSON for the host program: address, optionally the private view key (only
// ever after an on-device confirmation - the caller's job), restore height.
// The spend key, the seed and the passphrase are never part of it.
mw_err_t mw_ops_wallet_export(const mw_account_keys_t* keys, mw_network_t net,
                              const char* wallet_name, uint32_t restore_height,
                              bool with_view_key, char* out, size_t cap,
                              size_t* len);

// The same data as plain text (CRLF lines) for a file on the SD card: wallet
// name, network, primary address, private view key, restore height and how
// to restore a view-only wallet from it. MW_ERR_INVALID_ARG when the wallet
// has no private view key.
mw_err_t mw_ops_viewonly_text(const mw_account_keys_t* keys, mw_network_t net,
                              const char* wallet_name, uint32_t restore_height,
                              char* out, size_t cap, size_t* len);

#ifdef __cplusplus
}
#endif
#endif
