// file_store.h on the device: LittleFS on the "storage" data partition of
// partitions.csv (v0.3). Only sealed records are ever written here.
//
// LittleFS is copy-on-write: a file being written is committed when it is
// closed, and a power cut leaves the previous version. A replace is "write
// <name>.tmp, rename it over <name>" - one atomic rename in LittleFS (if
// the rename over an existing file is ever refused, the old scheme with a
// .bak is used for that write).
//
// Speed (0.3.2): every lookup of a name LittleFS does not hold reads the
// directory's metadata from flash, so names and sizes are kept in RAM: the
// index is read once at mount (a .tmp left by a cut is dropped, a lone .bak
// put back) and kept up to date by write / remove. size(), list() and the
// existence checks never touch the flash. mw_fstore_seq() tells callers
// that cache something about a file (wallet_store.c, the decoy marks)
// whether it changed since.
//
// Firmware before 0.3 kept the partition as FAT (wear levelling + FatFS),
// which a power cut in the middle of a FAT update can damage as a whole.
// Such a device keeps working on the FAT (mounted here directly through the
// wear levelling layer, whatever the partition's subtype) until the shell
// converts it:
//   1. mw_fstore_migrate_prepare(): every file is read into PSRAM with a
//      CRC, then read again from the FAT and compared;
//   2. the user confirms (the shell);
//   3. mw_fstore_migrate_commit(): NVS "fsmig" = 1, the partition is erased
//      completely and formatted as LittleFS, the files are written back
//      from PSRAM and read back against their CRC, "fsmig" removed.
// A power cut during step 3 loses the files (PSRAM does not survive it);
// the next start finds "fsmig", puts an empty LittleFS in place and says so
// (mw_fstore_migration_lost()). The partition table is not touched beyond
// its subtype (the partition is found by its label).
//
// Flash writes disable the cache, so every caller runs on a task whose stack
// is in internal RAM (the crypto task is created that way).
#if defined(ARDUINO) && !defined(MW_HOST_BUILD)

#include <Arduino.h>
#include <esp_heap_caps.h>

extern "C" {
#include <esp_partition.h>
#include <esp_littlefs.h>
#include <esp_rom_crc.h>
#include <esp_vfs_fat.h>
#include <wear_levelling.h>
#include <diskio_impl.h>
#include <diskio_wl.h>
#include <ff.h>
}

#include "file_store.h"
#include "../crypto/memzero.h"
#include "../hal/log.h"

#include <dirent.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>

// Platform blob API (secure_storage.cpp).
extern "C" mw_err_t mw_store_blob_write(const char* key, const void* data, size_t len);
extern "C" mw_err_t mw_store_blob_read(const char* key, void* out, size_t cap, size_t* len_out);
extern "C" mw_err_t mw_store_blob_erase(const char* key);
// secure_storage.cpp: 1 exists, 0 does not, -1 NVS error.
extern "C" int mw_store_blob_exists(const char* key);

namespace {

constexpr const char* kPartition = "storage";
constexpr const char* kLfsBase   = "/lfs";
constexpr const char* kFatBase   = "/ffat";
constexpr const char* kMigKey    = "fsmig";
bool g_mig_lost;

enum backend_t { BK_NONE, BK_LFS, BK_FAT };
backend_t g_bk = BK_NONE;
mw_fstore_progress_fn g_prog;

const esp_partition_t* part(void) {
    static const esp_partition_t* p;
    if (!p) p = esp_partition_find_first(ESP_PARTITION_TYPE_DATA, ESP_PARTITION_SUBTYPE_ANY,
                                         kPartition);
    return p;
}

const char* base(void) { return g_bk == BK_FAT ? kFatBase : kLfsBase; }

void progress(int pm) {
    if (g_prog) g_prog(pm < 0 ? 0 : pm > 1000 ? 1000 : pm);
}

bool name_ok(const char* name) {
    if (!name) return false;
    const size_t n = strlen(name);
    if (n == 0 || n > MW_FSTORE_NAME_MAX) return false;
    for (size_t i = 0; i < n; i++) {
        const char c = name[i];
        if (!((c >= 'a' && c <= 'z') || (c >= '0' && c <= '9') || c == '_' || c == '.'))
            return false;
    }
    return true;
}

void path_for(const char* name, char* out, size_t cap, const char* suffix) {
    snprintf(out, cap, "%s/%s%s", base(), name, suffix ? suffix : "");
}

bool exists(const char* p) {
    struct stat st;
    return stat(p, &st) == 0;
}

long fsize(const char* p) {
    struct stat st;
    if (stat(p, &st) != 0) return -1;
    return (long)st.st_size;
}

// A lone .bak is the file (a cut between the two renames of a replace).
void recover(const char* name) {
    char p[64], bak[72], tmp[72];
    path_for(name, p, sizeof p, nullptr);
    path_for(name, bak, sizeof bak, ".bak");
    path_for(name, tmp, sizeof tmp, ".tmp");
    if (!exists(p) && exists(bak)) rename(bak, p);
    if (exists(p)) {
        if (exists(bak)) unlink(bak);
        if (exists(tmp)) unlink(tmp);
    }
}

bool write_file(const char* p, const uint8_t* data, size_t len) {
    FILE* f = fopen(p, "wb");
    if (!f) return false;
    size_t done = len ? fwrite(data, 1, len, f) : 0;
    const bool ok = fflush(f) == 0 && done == len;
    return (fclose(f) == 0) && ok;
}

// ---- the RAM index of the LittleFS files --------------------------------
struct idx_t {
    char     name[MW_FSTORE_NAME_MAX + 1];
    uint32_t size;
    uint32_t seq;
};
idx_t*   g_idx;
uint32_t g_idx_n, g_idx_cap;
uint32_t g_seq = 1;          // bumped by every change (also of the FAT)

int idx_find(const char* name) {
    for (uint32_t i = 0; i < g_idx_n; i++)
        if (strcmp(g_idx[i].name, name) == 0) return (int)i;
    return -1;
}

void idx_clear(void) {
    g_idx_n = 0;
    g_seq++;
}

bool idx_put(const char* name, uint32_t size) {
    int i = idx_find(name);
    if (i < 0) {
        if (g_idx_n == g_idx_cap) {
            const uint32_t cap = g_idx_cap ? g_idx_cap * 2u : 64u;
            idx_t* n = (idx_t*)heap_caps_malloc(sizeof(idx_t) * cap,
                                                MALLOC_CAP_SPIRAM | MALLOC_CAP_8BIT);
            if (!n) n = (idx_t*)malloc(sizeof(idx_t) * cap);
            if (!n) return false;
            if (g_idx) { memcpy(n, g_idx, sizeof(idx_t) * g_idx_n); free(g_idx); }
            g_idx = n;
            g_idx_cap = cap;
        }
        i = (int)g_idx_n++;
        snprintf(g_idx[i].name, sizeof g_idx[i].name, "%s", name);
    }
    g_idx[i].size = size;
    g_idx[i].seq = ++g_seq;
    return true;
}

void idx_drop(const char* name) {
    const int i = idx_find(name);
    if (i < 0) return;
    g_idx[i] = g_idx[g_idx_n - 1];
    g_idx_n--;
    g_seq++;
}

bool ends_with(const char* s, const char* suf) {
    const size_t a = strlen(s), b = strlen(suf);
    return a >= b && strcmp(s + a - b, suf) == 0;
}

// Reads the names and sizes of the mounted LittleFS once.
bool idx_build(void) {
    idx_clear();
    DIR* d = opendir(kLfsBase);
    if (!d) return false;
    char baks[16][MW_FSTORE_NAME_MAX + 1];
    int nb = 0;
    struct dirent* de;
    while ((de = readdir(d)) != nullptr) {
        const char* nm = de->d_name;
        if (!nm || nm[0] == '.' || strlen(nm) > MW_FSTORE_NAME_MAX + 4) continue;
        char p[72];
        snprintf(p, sizeof p, "%s/%s", kLfsBase, nm);
        if (ends_with(nm, ".tmp")) { unlink(p); continue; }        // a cut write
        if (ends_with(nm, ".bak")) {
            if (nb < 16) snprintf(baks[nb++], sizeof baks[0], "%.*s",
                                  (int)(strlen(nm) - 4), nm);
            continue;
        }
        if (!name_ok(nm)) continue;
        const long sz = fsize(p);
        if (sz >= 0 && !idx_put(nm, (uint32_t)sz)) { closedir(d); return false; }
    }
    closedir(d);
    // A .bak next to its file is a leftover; alone it is the file.
    for (int i = 0; i < nb; i++) {
        char p[72], bak[80];
        snprintf(p, sizeof p, "%s/%s", kLfsBase, baks[i]);
        snprintf(bak, sizeof bak, "%s/%s.bak", kLfsBase, baks[i]);
        if (idx_find(baks[i]) >= 0) { unlink(bak); continue; }
        if (rename(bak, p) == 0) {
            const long sz = fsize(p);
            if (sz >= 0) (void)idx_put(baks[i], (uint32_t)sz);
        }
    }
    MW_LOGI("fstore", "%u files indexed", (unsigned)g_idx_n);
    return true;
}

// ---- FAT of older firmware (wear levelling + FatFS, mounted by hand so the
// partition's subtype does not matter) -----------------------------------
wl_handle_t g_wl = WL_INVALID_HANDLE;
BYTE        g_pdrv = 0xFF;
FATFS*      g_fat;

void fat_drive(char out[3]) {
    out[0] = (char)('0' + g_pdrv);
    out[1] = ':';
    out[2] = 0;
}

bool fat_mount(void) {
    const esp_partition_t* p = part();
    if (!p) return false;
    if (wl_mount(p, &g_wl) != ESP_OK) { g_wl = WL_INVALID_HANDLE; return false; }
    BYTE pdrv = 0xFF;
    if (ff_diskio_get_drive(&pdrv) != ESP_OK) {
        wl_unmount(g_wl);
        g_wl = WL_INVALID_HANDLE;
        return false;
    }
    g_pdrv = pdrv;
    ff_diskio_register_wl_partition(pdrv, g_wl);
    char drv[3];
    fat_drive(drv);
    esp_vfs_fat_conf_t conf;
    memset(&conf, 0, sizeof conf);
    conf.base_path = kFatBase;
    conf.fat_drive = drv;
    conf.max_files = 4;
    g_fat = nullptr;
    bool ok = esp_vfs_fat_register_cfg(&conf, &g_fat) == ESP_OK;
    if (ok && f_mount(g_fat, drv, 1) != FR_OK) {
        (void)esp_vfs_fat_unregister_path(kFatBase);
        ok = false;
    }
    if (!ok) {
        ff_diskio_unregister(pdrv);
        wl_unmount(g_wl);
        g_wl = WL_INVALID_HANDLE;
        g_pdrv = 0xFF;
        g_fat = nullptr;
    }
    return ok;
}

void fat_unmount(void) {
    if (g_wl == WL_INVALID_HANDLE) return;
    char drv[3];
    fat_drive(drv);
    f_mount(NULL, drv, 0);
    (void)esp_vfs_fat_unregister_path(kFatBase);
    ff_diskio_unregister(g_pdrv);
    wl_unmount(g_wl);
    g_wl = WL_INVALID_HANDLE;
    g_pdrv = 0xFF;
    g_fat = nullptr;
}

size_t fat_free(void) {
    char drv[3];
    DWORD nclst = 0;
    FATFS* fs = nullptr;
    fat_drive(drv);
    if (f_getfree(drv, &nclst, &fs) != FR_OK || !fs) return 0;
#if FF_MAX_SS != FF_MIN_SS
    const size_t ss = fs->ssize;
#else
    const size_t ss = FF_MAX_SS;
#endif
    return (size_t)nclst * fs->csize * ss;
}

// ---- LittleFS --------------------------------------------------------------
bool lfs_mount(void) {
    const esp_partition_t* p = part();
    if (!p) return false;
    if (esp_littlefs_partition_mounted(p)) return true;
    esp_vfs_littlefs_conf_t conf;
    memset(&conf, 0, sizeof conf);
    conf.base_path = kLfsBase;
    conf.partition = p;
    conf.format_if_mount_failed = 0;
    return esp_vfs_littlefs_register(&conf) == ESP_OK;
}

void lfs_unmount(void) {
    const esp_partition_t* p = part();
    if (p && esp_littlefs_partition_mounted(p)) (void)esp_vfs_littlefs_unregister_partition(p);
}

// Erases the whole partition (nothing of the old content survives) and puts
// an empty LittleFS on it, mounted.
void fat_unmount(void);

bool lfs_fresh(void) {
    const esp_partition_t* p = part();
    if (!p) return false;
    lfs_unmount();
    if (g_bk == BK_FAT) fat_unmount();
    g_bk = BK_NONE;
    const size_t step = 64u * 1024u;
    for (size_t off = 0; off < p->size; off += step) {
        const size_t n = (p->size - off < step) ? p->size - off : step;
        if (esp_partition_erase_range(p, off, n) != ESP_OK) return false;
        delay(1);
    }
    if (esp_littlefs_format_partition(p) != ESP_OK) return false;
    if (!lfs_mount()) return false;
    g_bk = BK_LFS;
    idx_clear();
    return true;
}

// ---- conversion through PSRAM -------------------------------------------
struct mig_file_t {
    char     name[MW_FSTORE_NAME_MAX + 1];
    uint32_t size, off, crc;
};
mig_file_t* g_mf;            // the files (PSRAM)
uint32_t    g_mn;
uint8_t*    g_md;            // their contents, back to back (PSRAM)
uint32_t    g_mtotal;

void* ps_alloc(size_t n) {
    void* p = heap_caps_malloc(n ? n : 1, MALLOC_CAP_SPIRAM | MALLOC_CAP_8BIT);
    return p ? p : malloc(n ? n : 1);
}

void mig_release(void) {
    if (g_md) { mw_memzero(g_md, g_mtotal); free(g_md); }
    if (g_mf) { mw_memzero(g_mf, sizeof(mig_file_t) * g_mn); free(g_mf); }
    g_md = nullptr;
    g_mf = nullptr;
    g_mn = 0;
    g_mtotal = 0;
}

// Reads a whole file of the mounted store into dst (exactly `size` bytes).
bool read_all(const char* name, uint8_t* dst, uint32_t size) {
    char p[64];
    path_for(name, p, sizeof p, nullptr);
    FILE* f = fopen(p, "rb");
    if (!f) return false;
    const size_t got = size ? fread(dst, 1, size, f) : 0;
    const int extra = fgetc(f);
    fclose(f);
    return got == size && extra == EOF;
}

}  // namespace

extern "C" void mw_fstore_set_progress(mw_fstore_progress_fn fn) { g_prog = fn; }
extern "C" bool mw_fstore_migration_lost(void) { return g_mig_lost; }

extern "C" mw_err_t mw_fstore_init(void) {
    if (g_bk != BK_NONE) return MW_OK;
    if (!part()) {
        MW_LOGE("fstore", "no '%s' partition", kPartition);
        return MW_ERR_IO;
    }
    if (mw_store_blob_exists(kMigKey) == 1) {
        // A conversion was cut after the FAT was erased: what PSRAM held is
        // gone. An empty (or partly written) LittleFS stays; the shell says so.
        MW_LOGE("fstore", "the storage conversion was interrupted: files lost");
        g_mig_lost = true;
        if (lfs_mount()) { g_bk = BK_LFS; (void)idx_build(); }
        else if (!lfs_fresh()) return MW_ERR_IO;
        (void)mw_store_blob_erase(kMigKey);
        return MW_OK;
    }
    if (lfs_mount()) {
        g_bk = BK_LFS;
        if (!idx_build()) {
            MW_LOGE("fstore", "LittleFS directory unreadable");
            lfs_unmount();
            g_bk = BK_NONE;
            return MW_ERR_IO;
        }
    } else if (fat_mount()) {
        g_bk = BK_FAT;                            // firmware before 0.3
        MW_LOGI("fstore", "FAT storage of an older firmware: to be converted");
    } else {
        // Blank on a freshly flashed board: formatted then. With a password
        // record the partition holds the users' wallets - never format it
        // behind their back (a factory reset does that).
        // Only a definite "no record" counts as a fresh board.
        const bool has_record = mw_store_blob_exists("devauth") != 0;
        if (has_record || !lfs_fresh()) {
            MW_LOGE("fstore", "storage mount failed (partition '%s')%s", kPartition,
                    has_record ? "; not formatted: it holds the wallets" : "");
            return MW_ERR_IO;
        }
    }
    MW_LOGI("fstore", "%s mounted", g_bk == BK_FAT ? "FAT" : "LittleFS");
    return MW_OK;
}

extern "C" bool mw_fstore_ready(void) { return g_bk != BK_NONE; }
extern "C" bool mw_fstore_on_fat(void) { return g_bk == BK_FAT; }

extern "C" mw_err_t mw_fstore_migrate_prepare(mw_fstore_mig_info_t* info) {
    if (info) memset(info, 0, sizeof *info);
    if (g_bk == BK_NONE && mw_fstore_init() != MW_OK) return MW_ERR_IO;
    if (g_bk != BK_FAT) return MW_ERR_NOT_SUPPORTED;
    mig_release();
    progress(0);

    // The names, with any half-finished replace settled first.
    int n = mw_fstore_list("", NULL, 0);
    if (n < 0) return MW_ERR_IO;
    g_mf = (mig_file_t*)ps_alloc(sizeof(mig_file_t) * (size_t)(n + 1));
    if (!g_mf) return MW_ERR_MEMORY;
    char (*names)[MW_FSTORE_NAME_MAX + 1] = (char (*)[MW_FSTORE_NAME_MAX + 1])ps_alloc(
        (size_t)(MW_FSTORE_NAME_MAX + 1) * (size_t)(n + 1));
    if (!names) { mig_release(); return MW_ERR_MEMORY; }
    int got = mw_fstore_list("", names, n + 1);
    for (int i = 0; i < got && i <= n; i++) recover(names[i]);
    got = mw_fstore_list("", names, n + 1);
    if (got < 0 || got > n) { free(names); mig_release(); return MW_ERR_IO; }
    uint64_t total = 0;
    for (int i = 0; i < got; i++) {
        char p[64];
        snprintf(g_mf[i].name, sizeof g_mf[i].name, "%s", names[i]);
        path_for(names[i], p, sizeof p, nullptr);
        const long s = fsize(p);
        if (s < 0) { free(names); mig_release(); return MW_ERR_IO; }
        g_mf[i].size = (uint32_t)s;
        g_mf[i].off = (uint32_t)total;
        total += (uint64_t)s;
    }
    free(names);
    g_mn = (uint32_t)got;
    if (info) { info->files = g_mn; info->bytes = (uint32_t)total; }
    MW_LOGI("fstore", "converting the storage: %u files, %u KiB", (unsigned)g_mn,
            (unsigned)(total / 1024u));
    const esp_partition_t* pt = part();
    if (total + 64u * 1024u > (uint64_t)pt->size) { mig_release(); return MW_ERR_TOO_MANY; }
    g_mtotal = (uint32_t)total;
    g_md = (uint8_t*)heap_caps_malloc(g_mtotal ? g_mtotal : 1, MALLOC_CAP_SPIRAM | MALLOC_CAP_8BIT);
    if (!g_md) {
        MW_LOGE("fstore", "no PSRAM for %u KiB", (unsigned)(g_mtotal / 1024u));
        mig_release();
        return MW_ERR_MEMORY;
    }
    // Read every file, then read it again and compare the CRCs.
    uint8_t* chk = (uint8_t*)ps_alloc(64u * 1024u);
    for (uint32_t i = 0; i < g_mn; i++) {
        mig_file_t* f = &g_mf[i];
        if (!read_all(f->name, g_md + f->off, f->size)) {
            if (chk) free(chk);
            mig_release();
            return MW_ERR_IO;
        }
        f->crc = esp_rom_crc32_le(0, g_md + f->off, f->size);
        uint32_t again = 0;
        bool ok = true;
        if (chk && f->size <= 64u * 1024u) {
            ok = read_all(f->name, chk, f->size);
            again = esp_rom_crc32_le(0, chk, f->size);
        } else {
            // A larger file: read into a temporary of its size.
            uint8_t* t = (uint8_t*)ps_alloc(f->size);
            ok = t && read_all(f->name, t, f->size);
            if (ok) again = esp_rom_crc32_le(0, t, f->size);
            if (t) { mw_memzero(t, f->size); free(t); }
        }
        if (!ok || again != f->crc) {
            MW_LOGE("fstore", "file %u reads differently twice: conversion refused", (unsigned)i);
            if (chk) free(chk);
            mig_release();
            return MW_ERR_IO;
        }
        progress((int)(400u * (i + 1) / (g_mn ? g_mn : 1)));
    }
    if (chk) { mw_memzero(chk, 64u * 1024u); free(chk); }
    return MW_OK;
}

extern "C" void mw_fstore_migrate_abort(void) { mig_release(); }

extern "C" mw_err_t mw_fstore_migrate_commit(void) {
    if (g_bk != BK_FAT || !g_mf || (!g_md && g_mtotal)) return MW_ERR_NOT_SUPPORTED;
    const uint8_t one = 1;
    if (mw_store_blob_write(kMigKey, &one, 1) != MW_OK) { mig_release(); return MW_ERR_IO; }
    mw_err_t e = MW_ERR_IO;
    for (int attempt = 0; attempt < 2 && e != MW_OK; attempt++) {
        progress(450);
        if (!lfs_fresh()) continue;
        e = MW_OK;
        for (uint32_t i = 0; i < g_mn && e == MW_OK; i++) {
            const mig_file_t* f = &g_mf[i];
            e = mw_fstore_write(f->name, g_md + f->off, f->size);
            if (e == MW_OK) {
                // Read back against the CRC, in pieces.
                char p[64];
                path_for(f->name, p, sizeof p, nullptr);
                FILE* fp = fopen(p, "rb");
                uint8_t buf[512];
                uint32_t crc = 0, done = 0;
                if (!fp) e = MW_ERR_IO;
                while (e == MW_OK && done < f->size) {
                    const size_t k = f->size - done < sizeof buf ? f->size - done : sizeof buf;
                    if (fread(buf, 1, k, fp) != k) { e = MW_ERR_IO; break; }
                    crc = esp_rom_crc32_le(crc, buf, k);
                    done += (uint32_t)k;
                }
                if (fp) fclose(fp);
                if (e == MW_OK && crc != f->crc) e = MW_ERR_IO;
            }
            progress(500 + (int)(480u * (i + 1) / (g_mn ? g_mn : 1)));
        }
        if (e != MW_OK) MW_LOGE("fstore", "writing back failed (attempt %d)", attempt + 1);
    }
    const uint32_t files = g_mn;
    mig_release();
    if (e != MW_OK) return e;                   // "fsmig" stays: reported at the next start
    (void)mw_store_blob_erase(kMigKey);
    progress(1000);
    MW_LOGI("fstore", "storage converted to LittleFS (%u files)", (unsigned)files);
    return MW_OK;
}

extern "C" uint32_t mw_fstore_seq(const char* name) {
    if (g_bk == BK_LFS && name) {
        const int i = idx_find(name);
        return i < 0 ? 0 : g_idx[i].seq;
    }
    return g_seq;                                 // FAT: any change counts
}

extern "C" mw_err_t mw_fstore_write(const char* name, const uint8_t* data, size_t len) {
    if (!name_ok(name) || (!data && len)) return MW_ERR_INVALID_ARG;
    if (g_bk == BK_NONE && mw_fstore_init() != MW_OK) return MW_ERR_IO;
    char p[64], tmp[72], bak[72];
    path_for(name, p, sizeof p, nullptr);
    path_for(name, tmp, sizeof tmp, ".tmp");
    path_for(name, bak, sizeof bak, ".bak");

    if (g_bk == BK_LFS) {
        if (!write_file(tmp, data, len)) { unlink(tmp); return MW_ERR_IO; }
        if (rename(tmp, p) != 0) {
            // The rename over an existing file was refused: the old way.
            const bool had = idx_find(name) >= 0;
            unlink(bak);
            if (had && rename(p, bak) != 0) { unlink(tmp); return MW_ERR_IO; }
            if (rename(tmp, p) != 0) {
                if (had) rename(bak, p);
                unlink(tmp);
                return MW_ERR_IO;
            }
            if (had) unlink(bak);
        }
        if (!idx_put(name, (uint32_t)len)) {
            // No RAM for the index: it is rebuilt from the flash.
            (void)idx_build();
        }
        return MW_OK;
    }

    g_seq++;
    recover(name);                                // FAT: a lone .bak is the file
    if (!write_file(tmp, data, len)) { unlink(tmp); return MW_ERR_IO; }
    if (exists(bak)) unlink(bak);
    if (exists(p) && rename(p, bak) != 0) { unlink(tmp); return MW_ERR_IO; }
    if (rename(tmp, p) != 0) {
        rename(bak, p);                           // put the old one back
        unlink(tmp);
        return MW_ERR_IO;
    }
    unlink(bak);
    return MW_OK;
}

extern "C" mw_err_t mw_fstore_size(const char* name, size_t* len) {
    if (!name_ok(name) || !len) return MW_ERR_INVALID_ARG;
    if (g_bk == BK_NONE && mw_fstore_init() != MW_OK) return MW_ERR_IO;
    if (g_bk == BK_LFS) {
        const int i = idx_find(name);
        if (i < 0) return MW_ERR_IO;
        *len = g_idx[i].size;
        return MW_OK;
    }
    recover(name);
    char p[64];
    path_for(name, p, sizeof p, nullptr);
    const long s = fsize(p);
    if (s < 0) return MW_ERR_IO;
    *len = (size_t)s;
    return MW_OK;
}

extern "C" mw_err_t mw_fstore_read(const char* name, uint8_t* buf, size_t cap, size_t* len) {
    if (!name_ok(name) || !buf || !len) return MW_ERR_INVALID_ARG;
    if (g_bk == BK_NONE && mw_fstore_init() != MW_OK) return MW_ERR_IO;
    char p[64];
    path_for(name, p, sizeof p, nullptr);
    long s;
    if (g_bk == BK_LFS) {
        const int i = idx_find(name);
        if (i < 0) return MW_ERR_IO;
        s = (long)g_idx[i].size;
    } else {
        recover(name);
        s = fsize(p);
        if (s < 0) return MW_ERR_IO;
    }
    if ((size_t)s > cap) return MW_ERR_TOO_MANY;
    FILE* f = fopen(p, "rb");
    if (!f) return MW_ERR_IO;
    const size_t done = s ? fread(buf, 1, (size_t)s, f) : 0;
    fclose(f);
    if (done != (size_t)s) return MW_ERR_IO;
    *len = (size_t)s;
    return MW_OK;
}

extern "C" mw_err_t mw_fstore_remove(const char* name) {
    if (!name_ok(name)) return MW_ERR_INVALID_ARG;
    if (g_bk == BK_NONE && mw_fstore_init() != MW_OK) return MW_ERR_IO;
    char p[64];
    path_for(name, p, sizeof p, nullptr);
    if (g_bk == BK_LFS) {
        // LittleFS never rewrites in place: the blocks are freed and reused.
        if (idx_find(name) < 0) return MW_OK;
        if (unlink(p) != 0) return MW_ERR_IO;
        idx_drop(name);
        return MW_OK;
    }
    g_seq++;
    recover(name);
    if (!exists(p)) return MW_OK;
    {
        // Overwrite in place first. FAT on wear-levelled flash does not
        // guarantee the old sectors are gone, but the content was sealed.
        FILE* f = fopen(p, "r+b");
        if (f) {
            static const uint8_t zero[256] = {0};
            long left = fsize(p);
            while (left > 0) {
                const size_t k = (size_t)left < sizeof zero ? (size_t)left : sizeof zero;
                if (fwrite(zero, 1, k, f) != k) break;
                left -= (long)k;
            }
            fclose(f);
        }
    }
    return unlink(p) == 0 ? MW_OK : MW_ERR_IO;
}

extern "C" int mw_fstore_list(const char* prefix, char (*names)[MW_FSTORE_NAME_MAX + 1],
                              int max) {
    if (!prefix) return -1;
    if (g_bk == BK_NONE && mw_fstore_init() != MW_OK) return -1;
    const size_t pl = strlen(prefix);
    int n = 0;
    if (g_bk == BK_LFS) {
        for (uint32_t i = 0; i < g_idx_n; i++) {
            if (strncmp(g_idx[i].name, prefix, pl) != 0) continue;
            if (names && n < max) snprintf(names[n], MW_FSTORE_NAME_MAX + 1, "%s", g_idx[i].name);
            n++;
        }
        return n;
    }
    DIR* d = opendir(base());
    if (!d) return -1;
    struct dirent* de;
    while ((de = readdir(d)) != nullptr) {
        const char* nm = de->d_name;
        if (nm && name_ok(nm) && strncmp(nm, prefix, pl) == 0 &&
            !strstr(nm, ".tmp") && !strstr(nm, ".bak")) {
            if (names && n < max) snprintf(names[n], MW_FSTORE_NAME_MAX + 1, "%s", nm);
            n++;
        }
    }
    closedir(d);
    return n;
}

extern "C" mw_err_t mw_fstore_free_bytes(size_t* out) {
    if (!out) return MW_ERR_INVALID_ARG;
    if (g_bk == BK_NONE && mw_fstore_init() != MW_OK) return MW_ERR_IO;
    if (g_bk == BK_FAT) {
        *out = fat_free();
        return MW_OK;
    }
    // From the index, not esp_littlefs_partition_info() (that walks the
    // whole file system): every file takes its 4 KiB blocks plus one for its
    // metadata, and a few blocks go to the directory and spare copies -
    // on the safe side.
    uint64_t used = 16u * 4096u;
    for (uint32_t i = 0; i < g_idx_n; i++)
        used += ((uint64_t)g_idx[i].size + 4095u) / 4096u * 4096u + 4096u;
    const uint64_t total = part()->size;
    *out = total > used ? (size_t)(total - used) : 0;
    return MW_OK;
}

// Factory reset: the whole partition is erased (whatever it held, FAT or
// LittleFS, mounted or not) and a fresh LittleFS put on it.
extern "C" mw_err_t mw_fstore_wipe_all(void) {
    if (!part()) return MW_ERR_IO;
    mig_release();
    (void)mw_store_blob_erase(kMigKey);
    return lfs_fresh() ? MW_OK : MW_ERR_IO;
}

#endif  // ARDUINO && !MW_HOST_BUILD
