// SD card file browser: the platform-independent part (host-tested).
//
// The wallet menu lists the Feather files in the card root that the device
// can process (outputs exports and unsigned transaction sets), newest first,
// and writes each result next to its source with the source's date.
//
// SPDX-License-Identifier: MIT
#ifndef MW_TRANSFER_SD_FILES_H
#define MW_TRANSFER_SD_FILES_H

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#include "../hal/display_drivers.h"     // mw_sd_entry_t

#ifdef __cplusplus
extern "C" {
#endif

typedef enum {
    MW_SDF_NONE = 0,         // not something the device processes
    MW_SDF_OUTPUTS,          // Feather outputs export  -> key images
    MW_SDF_UNSIGNED          // unsigned transaction set -> signed set
} mw_sdf_kind_t;

// Bytes of a file's beginning enough to classify it.
#define MW_SDF_HEAD_LEN 64

// What a file is, from its first bytes (Monero file magic and version).
mw_sdf_kind_t mw_sdf_kind(const uint8_t* head, size_t len);

// A FAT date the PC really set: anything before 2000-01-01 counts as none
// (FAT's own zero is 1980-01-01; a clockless device writes 1980 or garbage).
bool    mw_sdf_time_valid(int64_t t);

// Unix time embedded in a Feather file name ("1789839233_unsigned_monero_tx",
// "wallet_1789637203_outputs"): the first run of exactly 10 digits that is a
// plausible date (2000..2100). false when there is none.
bool    mw_sdf_name_time(const char* name, int64_t* out);

// Ordering time: the FAT date when valid, else the time in the name, else 0.
int64_t mw_sdf_sort_time(const mw_sd_entry_t* e);

// Newest first; equal times by name.
void    mw_sdf_sort(mw_sd_entry_t* e, int n);

// Name of the result written next to `in`:
//   outputs : "<x>_outputs"            -> "<x>_keyImages",   else "<in>_keyImages"
//   unsigned: "...unsigned_monero_tx..."-> "...signed_monero_tx...",
//                                          else "<in>_signed_monero_tx"
// The source part is shortened when the result would not fit `cap`
// (at most MW_SD_ENTRY_NAME). MW_ERR_INVALID_ARG for MW_SDF_NONE.
mw_err_t mw_sdf_result_name(mw_sdf_kind_t k, const char* in, char* out, size_t cap);

// A wallet name made safe as a FAT32 / Windows file name. Wallet names are
// any printable ASCII, so: control and non-ASCII bytes and / \ : * ? " < > |
// become '_', leading spaces and trailing spaces and dots go, a name whose
// stem (up to the first '.') is a reserved device name (CON, PRN, AUX, NUL,
// COM1..9, LPT1..9, any case) gets a leading '_', and an empty result is
// "wallet". `out` must hold at least 8 bytes; the name is cut to fit.
mw_err_t mw_sdf_safe_name(const char* in, char* out, size_t cap);

// File name of the view-only export of wallet `wallet`:
//   n <= 1: "<safe name>_viewonly.txt", n > 1: "<safe name>_viewonly_<n>.txt"
// (the caller counts n up while the name is taken on the card).
mw_err_t mw_sdf_viewonly_name(const char* wallet, int n, char* out, size_t cap);

// The help file written to the card root when it is missing.
extern const char  mw_sdf_readme_name[];
extern const char  mw_sdf_readme_text[];

#ifdef __cplusplus
}
#endif
#endif
