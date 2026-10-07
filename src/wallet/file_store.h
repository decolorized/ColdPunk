// Larger persistent records that do not fit NVS (the 20 KiB NVS partition
// holds the wallet directory, the settings and the password record).
//
// Device: FAT on the "storage" data partition (partitions.csv), mounted with
//         FFat. Host: one file per name in the host store directory.
//
// Callers store ONLY sealed data here (mw_seal, secure_storage.h): the FAT
// partition is not covered by the NVS encryption and a flash dump reads it.
#ifndef MW_FILE_STORE_H
#define MW_FILE_STORE_H

#include "../monero/monero_types.h"

#ifdef __cplusplus
extern "C" {
#endif

#define MW_FSTORE_NAME_MAX 32

mw_err_t mw_fstore_init(void);          // mounts (formats on first use)
bool     mw_fstore_ready(void);
// Replaces the file atomically: written to a temporary name, then renamed.
mw_err_t mw_fstore_write(const char* name, const uint8_t* data, size_t len);
// MW_ERR_IO when the file does not exist.
mw_err_t mw_fstore_size(const char* name, size_t* len);
mw_err_t mw_fstore_read(const char* name, uint8_t* buf, size_t cap, size_t* len);
// Overwrites the content with zeros before removing it (best effort on flash
// with wear levelling; see docs/security.md).
mw_err_t mw_fstore_remove(const char* name);
// Factory reset: removes every file this module created.
mw_err_t mw_fstore_wipe_all(void);

#ifdef __cplusplus
}
#endif
#endif
