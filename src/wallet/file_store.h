// Larger persistent records that do not fit NVS (the 20 KiB NVS partition
// holds the wallet directory, the settings and the password record).
//
// Device: LittleFS on the "storage" data partition (partitions.csv); a FAT
//         partition of firmware before 0.3 until mw_fstore_migrate().
//         Host: one file per name in the host store directory.
//
// Callers store ONLY sealed data here (mw_seal, secure_storage.h): the
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
// Names (without the directory) of the files whose name starts with
// `prefix`, at most `max` of them, into names[i][MW_FSTORE_NAME_MAX + 1].
// Returns how many there are in total (may exceed `max`); -1 on an I/O error.
// `names` may be NULL to only count.
int      mw_fstore_list(const char* prefix, char (*names)[MW_FSTORE_NAME_MAX + 1], int max);
// Changes whenever the file `name` is written or removed (0: no such file
// on LittleFS; on the FAT of older firmware any change of any file moves
// it). For callers that cache something read from a file.
uint32_t mw_fstore_seq(const char* name);
// Free bytes of the store.
mw_err_t mw_fstore_free_bytes(size_t* out);
// Factory reset: removes every file (device: erases the whole partition).
mw_err_t mw_fstore_wipe_all(void);

// v0.3: the storage still is the FAT of an older firmware.
bool     mw_fstore_on_fat(void);
// Conversion to LittleFS through PSRAM (file_store_esp32.cpp):
//   prepare()  reads every file into PSRAM, twice, comparing CRCs; the FAT
//              is untouched. *info: how many files and bytes.
//   commit()   erases the partition, formats it as LittleFS and writes the
//              files back (read back against their CRCs). A power cut in
//              here loses the files: mw_fstore_migration_lost() says so at
//              the next start.
//   abort()    drops what prepare() read; the FAT stays in use.
typedef struct { uint32_t files, bytes; } mw_fstore_mig_info_t;
mw_err_t mw_fstore_migrate_prepare(mw_fstore_mig_info_t* info);
mw_err_t mw_fstore_migrate_commit(void);
void     mw_fstore_migrate_abort(void);
bool     mw_fstore_migration_lost(void);
// Progress of prepare() (0..400) and commit() (450..1000).
typedef void (*mw_fstore_progress_fn)(int permille);
void     mw_fstore_set_progress(mw_fstore_progress_fn fn);

#ifdef __cplusplus
}
#endif
#endif
