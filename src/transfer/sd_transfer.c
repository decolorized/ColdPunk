// SD-card exchange channel (TZ 3.2).
//
// FAT32, long file names, files up to 64 KB, automounted by the HAL. The four
// exchange files live in the volume root under the canonical names of TZ 9;
// this module is only the path bookkeeping and the size policy around
// mw_sd_read_file() / mw_sd_write_file().
//
// The same volume is what the USB channel exposes to the host, so everything
// here is deliberately plain: no locking, no caching, no partial writes.
//
// SPDX-License-Identifier: MIT

#include "transfer.h"
#include "../hal/hal.h"

#include <string.h>

#define MW_SD_MAX_FILE   MW_TRANSFER_MAX_FILE
#define MW_SD_PATH_MAX   64

// Cached absolute paths, built once so callers can hand them straight to the
// HAL without assembling strings on every transfer.
static char  g_paths[MW_FILE_KIND_COUNT][MW_SD_PATH_MAX];
static bool  g_paths_ready = false;

static void build_paths(void) {
    if (g_paths_ready) return;
    for (int i = 0; i < MW_FILE_KIND_COUNT; i++) {
        const char* name = MW_FILENAME[i];
        g_paths[i][0] = '/';
        size_t n = 0;
        while (name[n] && n + 2 < MW_SD_PATH_MAX) { g_paths[i][n + 1] = name[n]; n++; }
        g_paths[i][n + 1] = '\0';
    }
    g_paths_ready = true;
}

mw_err_t mw_sd_transfer_init(void) {
    build_paths();
    const mw_hal_caps_t* caps = mw_hal_caps();
    if (!caps || !caps->has_sd) return MW_ERR_NOT_SUPPORTED;
    return mw_sd_init();
}

bool mw_sd_transfer_available(void) {
    const mw_hal_caps_t* caps = mw_hal_caps();
    return caps && caps->has_sd && mw_sd_present();
}

const char* mw_sd_transfer_path(mw_file_kind_id_t kind) {
    if ((unsigned)kind >= MW_FILE_KIND_COUNT) return NULL;
    build_paths();
    return g_paths[kind];
}

mw_err_t mw_sd_transfer_read(mw_file_kind_id_t kind, uint8_t* buf, size_t cap,
                             size_t* len) {
    if (!buf || cap == 0) return MW_ERR_INVALID_ARG;
    const char* path = mw_sd_transfer_path(kind);
    if (!path) return MW_ERR_INVALID_ARG;
    if (!mw_sd_transfer_available()) return MW_ERR_IO;
    if (cap > MW_SD_MAX_FILE) cap = MW_SD_MAX_FILE;

    size_t n = 0;
    mw_err_t err = mw_sd_read_file(path, buf, cap, &n);
    if (err != MW_OK) return err;
    if (n == 0) return MW_ERR_FORMAT;                 // an empty file is junk
    if (len) *len = n;
    return MW_OK;
}

mw_err_t mw_sd_transfer_write(mw_file_kind_id_t kind, const uint8_t* buf,
                              size_t len) {
    if (!buf || len == 0) return MW_ERR_INVALID_ARG;
    if (len > MW_SD_MAX_FILE) return MW_ERR_TOO_MANY;
    const char* path = mw_sd_transfer_path(kind);
    if (!path) return MW_ERR_INVALID_ARG;
    if (!mw_sd_transfer_available()) return MW_ERR_IO;
    return mw_sd_write_file(path, buf, len);
}
