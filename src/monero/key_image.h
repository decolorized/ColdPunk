// Key image derivation and the outputs.bin -> keyimages.bin flow (TZ 11).
#ifndef MW_KEY_IMAGE_H
#define MW_KEY_IMAGE_H

#include "monero_types.h"

#ifdef __cplusplus
extern "C" {
#endif

// I = x * Hp(P), where x is the one-time secret and P = x*G.
// Verifies x*G == P first and returns MW_ERR_KEY_MISMATCH otherwise (TZ 8.3).
mw_err_t mw_generate_key_image(const mw_pubkey_t* pub, const mw_seckey_t* sec,
                               mw_keyimage_t* out);

// Ring signature over {P} proving knowledge of x and correctness of I. This is
// the "key image export signature" Monero's import_key_images expects.
typedef struct { mw_scalar_t c; mw_scalar_t r; } mw_ring_sig_t;

mw_err_t mw_generate_key_image_signature(const mw_pubkey_t* pub,
                                         const mw_seckey_t* sec,
                                         const mw_keyimage_t* image,
                                         mw_ring_sig_t* sig_out);

mw_err_t mw_check_key_image_signature(const mw_pubkey_t* pub,
                                      const mw_keyimage_t* image,
                                      const mw_ring_sig_t* sig);

// ---------------- transfer record (wallet2 exported_transfer_details) -----
// Only the additional tx public key that belongs to THIS output is kept
// (m_additional_tx_keys[internal_output_index]); that is the only one the
// key image derivation can use, and a transaction may carry up to 16.
typedef struct {
    mw_pubkey_t   tx_pub_key;          // R
    uint32_t      internal_output_index;
    uint64_t      global_output_index;
    mw_pubkey_t   one_time_pubkey;     // P
    uint32_t      subaddr_major;
    uint32_t      subaddr_minor;
    uint64_t      amount;
    uint8_t       flags;               // raw m_flags (bit 2 = m_rct)
    bool          rct;
    bool          has_additional;
    mw_pubkey_t   additional_tx_pub;   // m_additional_tx_keys[internal index]
    uint32_t      additional_count;    // how many the record listed
} mw_exported_output_t;

typedef struct {
    mw_keyimage_t image;
    mw_ring_sig_t sig;
} mw_exported_key_image_t;

// Recomputes the one-time secret for an exported output and derives its key
// image + signature.
mw_err_t mw_key_image_from_output(const mw_account_keys_t* keys,
                                  const mw_exported_output_t* out,
                                  mw_exported_key_image_t* ki_out);

// One-time secret of an output we own: x = Hs(8*a*R || i) + b (+ m for a
// subaddress). Tries the main tx key, then the additional key, and accepts
// only x*G == P. Used by the key image export, the signer and the
// tx_key_images of the signed set.
mw_err_t mw_output_secret(const mw_account_keys_t* keys,
                          const mw_pubkey_t* one_time_pub,
                          const mw_pubkey_t* tx_pub,
                          const mw_pubkey_t* additional_pub /* NULL = none */,
                          uint32_t output_index, uint32_t major, uint32_t minor,
                          mw_seckey_t* x_out);

// Kept for the host tests: every record is attempted, failures are listed.
// The firmware itself aborts on the first failure (a file that does not
// match the wallet must not produce a partial export) - see flows.
typedef struct {
    uint32_t index;      // position in the outputs.bin batch
    mw_err_t err;
} mw_ki_failure_t;

typedef struct {
    uint32_t         processed;   // records that produced a key image
    uint32_t         failed;
    mw_ki_failure_t* failures;    // caller-owned, may be NULL to only count
    uint32_t         failures_cap;
} mw_ki_batch_result_t;

// Progress callback drives the TZ 4.2 progress bar (done / total).
typedef void (*mw_ki_progress_cb)(uint32_t done, uint32_t total, void* user);

// Processes a whole batch. Returns MW_OK when at least one record succeeded;
// per-record errors land in `result`.
mw_err_t mw_key_image_batch(const mw_account_keys_t* keys,
                            const mw_exported_output_t* outputs, uint32_t count,
                            mw_exported_key_image_t* images_out,
                            mw_ki_batch_result_t* result,
                            mw_ki_progress_cb cb, void* user);

#ifdef __cplusplus
}
#endif
#endif
