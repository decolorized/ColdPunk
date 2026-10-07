// file_store.h on the device: FAT (FFat) on the "storage" data partition of
// partitions.csv. Only sealed records are ever written here.
//
// Flash writes disable the cache, so every caller runs on a task whose stack
// is in internal RAM (the crypto task is created that way).
#if defined(ARDUINO) && !defined(MW_HOST_BUILD)

#include <Arduino.h>
#include <FFat.h>

#include "file_store.h"
#include "../hal/log.h"

#include <string.h>

namespace {

constexpr const char* kPartition = "storage";
constexpr const char* kBase      = "/ffat";
bool g_ready = false;

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
    snprintf(out, cap, "/%s%s", name, suffix ? suffix : "");
}

}  // namespace

extern "C" mw_err_t mw_fstore_init(void) {
    if (g_ready) return MW_OK;
    // formatOnFail = true: the partition is blank on a freshly flashed board.
    if (!FFat.begin(true, kBase, 4, kPartition)) {
        MW_LOGE("fstore", "FFat mount failed (partition '%s')", kPartition);
        return MW_ERR_IO;
    }
    g_ready = true;
    MW_LOGI("fstore", "FFat mounted: %u KiB free",
            (unsigned)(FFat.freeBytes() / 1024u));
    return MW_OK;
}

extern "C" bool mw_fstore_ready(void) { return g_ready; }

extern "C" mw_err_t mw_fstore_write(const char* name, const uint8_t* data, size_t len) {
    if (!name_ok(name) || (!data && len)) return MW_ERR_INVALID_ARG;
    if (!g_ready && mw_fstore_init() != MW_OK) return MW_ERR_IO;
    char p[48], tmp[56];
    path_for(name, p, sizeof p, nullptr);
    path_for(name, tmp, sizeof tmp, ".tmp");

    File f = FFat.open(tmp, FILE_WRITE);
    if (!f) return MW_ERR_IO;
    size_t done = 0;
    while (done < len) {
        const size_t w = f.write(data + done, len - done);
        if (w == 0) break;
        done += w;
    }
    f.close();
    if (done != len) { FFat.remove(tmp); return MW_ERR_IO; }
    if (FFat.exists(p)) FFat.remove(p);
    if (!FFat.rename(tmp, p)) { FFat.remove(tmp); return MW_ERR_IO; }
    return MW_OK;
}

extern "C" mw_err_t mw_fstore_size(const char* name, size_t* len) {
    if (!name_ok(name) || !len) return MW_ERR_INVALID_ARG;
    if (!g_ready && mw_fstore_init() != MW_OK) return MW_ERR_IO;
    char p[48];
    path_for(name, p, sizeof p, nullptr);
    if (!FFat.exists(p)) return MW_ERR_IO;
    File f = FFat.open(p, FILE_READ);
    if (!f) return MW_ERR_IO;
    *len = f.size();
    f.close();
    return MW_OK;
}

extern "C" mw_err_t mw_fstore_read(const char* name, uint8_t* buf, size_t cap, size_t* len) {
    if (!name_ok(name) || !buf || !len) return MW_ERR_INVALID_ARG;
    if (!g_ready && mw_fstore_init() != MW_OK) return MW_ERR_IO;
    char p[48];
    path_for(name, p, sizeof p, nullptr);
    if (!FFat.exists(p)) return MW_ERR_IO;
    File f = FFat.open(p, FILE_READ);
    if (!f) return MW_ERR_IO;
    const size_t size = f.size();
    if (size > cap) { f.close(); return MW_ERR_TOO_MANY; }
    size_t done = 0;
    while (done < size) {
        const int r = f.read(buf + done, size - done);
        if (r <= 0) break;
        done += (size_t)r;
    }
    f.close();
    if (done != size) return MW_ERR_IO;
    *len = size;
    return MW_OK;
}

extern "C" mw_err_t mw_fstore_remove(const char* name) {
    if (!name_ok(name)) return MW_ERR_INVALID_ARG;
    if (!g_ready && mw_fstore_init() != MW_OK) return MW_ERR_IO;
    char p[48];
    path_for(name, p, sizeof p, nullptr);
    if (!FFat.exists(p)) return MW_OK;
    {
        // Overwrite in place first. FAT on wear-levelled flash does not
        // guarantee the old sectors are gone, but the content was sealed.
        File f = FFat.open(p, "r+");
        if (f) {
            static const uint8_t zero[256] = {0};
            size_t left = f.size();
            f.seek(0);
            while (left) {
                const size_t k = left < sizeof zero ? left : sizeof zero;
                if (f.write(zero, k) != k) break;
                left -= k;
            }
            f.close();
        }
    }
    return FFat.remove(p) ? MW_OK : MW_ERR_IO;
}

extern "C" mw_err_t mw_fstore_wipe_all(void) {
    if (!g_ready && mw_fstore_init() != MW_OK) return MW_ERR_IO;
    // Collect the names first: removing while iterating confuses the FAT
    // directory walk.
    char names[64][MW_FSTORE_NAME_MAX + 1];
    int n = 0;
    File root = FFat.open("/");
    if (root) {
        File f = root.openNextFile();
        while (f && n < 64) {
            const char* nm = f.name();
            if (nm && *nm == '/') nm++;
            if (nm && name_ok(nm)) {
                snprintf(names[n], sizeof names[n], "%s", nm);
                n++;
            }
            f.close();
            f = root.openNextFile();
        }
        root.close();
    }
    for (int i = 0; i < n; i++) (void)mw_fstore_remove(names[i]);
    return MW_OK;
}

#endif  // ARDUINO && !MW_HOST_BUILD
