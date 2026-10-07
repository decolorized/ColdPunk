// End-to-end signing orchestration (TZ 12.2). Runs on the crypto FreeRTOS task
// so the LVGL task keeps repainting (TZ 4.1).
#ifndef MW_SIGN_H
#define MW_SIGN_H

#include "monero_types.h"
#include "tx.h"
#include "clsag.h"
#include "bulletproof_plus.h"

#ifdef __cplusplus
extern "C" {
#endif

typedef enum {
    MW_SIGN_STAGE_PARSE = 0,
    MW_SIGN_STAGE_VERIFY_INPUTS,
    MW_SIGN_STAGE_OUTPUT_KEYS,
    MW_SIGN_STAGE_BULLETPROOF,
    MW_SIGN_STAGE_CLSAG,
    MW_SIGN_STAGE_SERIALIZE,
    MW_SIGN_STAGE_DONE
} mw_sign_stage_t;

typedef void (*mw_sign_progress_cb)(mw_sign_stage_t stage, int permille, void* user);

typedef struct {
    mw_clsag_t     clsag[MW_MAX_INPUTS];
    mw_point_t     pseudo_outs[MW_MAX_INPUTS];
    mw_bpp_proof_t bpp;
    uint8_t        message[32];
    uint8_t        prefix_hash[32];
} mw_signed_data_t;

// Full signing pipeline. Assumes the user already confirmed the summary.
mw_err_t mw_sign_transaction(const mw_account_keys_t* keys, mw_transaction_t* tx,
                             mw_signed_data_t* out,
                             mw_sign_progress_cb cb, void* user);

// Matches input `index` to this wallet (validates its points, re-derives the
// one-time key, finds its subaddress) and returns its key image, without
// signing anything. Used to check the inputs against the key image cache
// before the transaction is shown to the user.
mw_err_t mw_sign_input_key_image(const mw_account_keys_t* keys, mw_transaction_t* tx,
                                 uint8_t index, mw_keyimage_t* ki_out);

// Serializes the RCT signature block for signed_tx_set.bin.
size_t mw_serialize_rct(const mw_transaction_t* tx, const mw_signed_data_t* sd,
                        uint8_t* out, size_t out_cap);

#ifdef __cplusplus
}
#endif
#endif
