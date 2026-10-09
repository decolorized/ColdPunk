// microSD: over SPI (sharing the display bus, TZ 2.2 / 3.2) or over SDIO
// (SD_MMC) when the board header sets MW_SD_SDMMC (ES3C28P).
//
// FAT32 with long file names, files up to MW_SD_FILE_MAX (256 KB, the same
// ceiling as the USB link).  A file is always read whole into the caller's
// buffer: mw_sd_read_file() refuses anything that would not fit before it
// opens the file, so no streaming parser is ever needed.
//
// Bus sharing
// -----------
// The card and the panel sit on the same SCK/MOSI/MISO.  Two rules keep that
// working:
//   1. Arduino_GFX is built on Arduino_HWSPI with is_shared_interface = true
//      (see display.cpp), so both users arbitrate through SPIClass
//      beginTransaction()/endTransaction().
//   2. A chip select that is not being talked to must be driven high.  The SD
//      library leaves SD_CS high between transactions; TFT_CS is forced high
//      here before the card is probed, because an ST7789 that is still
//      selected will happily eat the card's initialisation clocks.
//
// Path handling
// -------------
// Every path from the outside world goes through sd_path(), which bounds the
// length, forces a leading '/', and rejects "..".  Nothing in this file
// copies into a fixed buffer without checking the length first.
#if defined(ARDUINO) && !defined(MW_HOST_BUILD)

#include <Arduino.h>
#include <string.h>
#include "display_drivers.h"

#if !HAS_SD

mw_err_t mw_sd_init(void)  { return MW_ERR_NOT_SUPPORTED; }
bool     mw_sd_present(void) { return false; }
mw_err_t mw_sd_read_file(const char* p, uint8_t* b, size_t c, size_t* l)
{ (void)p; (void)b; (void)c; if (l) *l = 0; return MW_ERR_NOT_SUPPORTED; }
mw_err_t mw_sd_write_file(const char* p, const uint8_t* b, size_t l)
{ (void)p; (void)b; (void)l; return MW_ERR_NOT_SUPPORTED; }
mw_err_t mw_sd_list(const char* d, char (*n)[64], int m, int* c)
{ (void)d; (void)n; (void)m; if (c) *c = 0; return MW_ERR_NOT_SUPPORTED; }
mw_err_t mw_sd_format(void) { return MW_ERR_NOT_SUPPORTED; }
mw_err_t mw_sd_unlink(const char* p) { (void)p; return MW_ERR_NOT_SUPPORTED; }
mw_err_t mw_sd_list_files(const char* d, mw_sd_entry_t* o, int m, int* c)
{ (void)d; (void)o; (void)m; if (c) *c = 0; return MW_ERR_NOT_SUPPORTED; }
mw_err_t mw_sd_read_head(const char* p, uint8_t* b, size_t c, size_t* l)
{ (void)p; (void)b; (void)c; if (l) *l = 0; return MW_ERR_NOT_SUPPORTED; }
bool     mw_sd_exists(const char* p) { (void)p; return false; }
mw_err_t mw_sd_set_mtime(const char* p, int64_t t) { (void)p; (void)t; return MW_ERR_NOT_SUPPORTED; }
mw_err_t mw_sd_ensure(void) { return MW_ERR_NOT_SUPPORTED; }
void     mw_sd_release(void) {}

#else   // ================= HAS_SD ==========================================

#include <FS.h>
#include <sys/stat.h>
#include <utime.h>
#if MW_SD_SDMMC
#include <SD_MMC.h>
#define MW_SD_MOUNT "/sdcard"
#define SDFS SD_MMC
#else
#include <SPI.h>
#include <SD.h>
#define MW_SD_MOUNT "/sd"
#define SDFS SD
#endif

// SD cards must see their first commands at 100..400 kHz; only after the card
// answers CMD8/ACMD41 may the host go fast.  The Arduino SD library fixes the
// clock at SD.begin() time, so we mount twice: once slow to bring the card up,
// once at speed for the actual transfers.
#define MW_SD_INIT_HZ  400000U
#define MW_SD_FAST_HZ  20000000U
#define MW_SD_SAFE_HZ  4000000U

static bool s_sd_ready = false;

// --------------------------------------------------------------------------
// Bounded path normalisation
// --------------------------------------------------------------------------
// Returns MW_OK and writes a '/'-prefixed copy of `in` into `out`, which must
// be MW_SD_PATH_MAX bytes.  Rejects: NULL, empty, longer than the buffer, any
// ".." component, and embedded backslashes (a Windows-authored file name that
// would otherwise escape the directory).
static mw_err_t sd_path(char out[MW_SD_PATH_MAX], const char* in)
{
    if (!out || !in) return MW_ERR_INVALID_ARG;

    size_t len = strnlen(in, MW_SD_PATH_MAX);
    if (len == 0 || len >= MW_SD_PATH_MAX) return MW_ERR_INVALID_ARG;

    size_t need = (in[0] == '/') ? len : len + 1;
    if (need >= MW_SD_PATH_MAX) return MW_ERR_INVALID_ARG;

    size_t o = 0;
    if (in[0] != '/') out[o++] = '/';
    memcpy(out + o, in, len);
    out[o + len] = '\0';

    // Reject traversal and separators the FAT layer does not understand.
    for (const char* p = out; *p; ++p) {
        if (*p == '\\') return MW_ERR_INVALID_ARG;
        if (p[0] == '.' && p[1] == '.' &&
            (p == out || p[-1] == '/') &&
            (p[2] == '/' || p[2] == '\0')) return MW_ERR_INVALID_ARG;
    }
    return MW_OK;
}

// --------------------------------------------------------------------------
// Mount
// --------------------------------------------------------------------------
#if MW_SD_SDMMC
// SDIO: 4-bit first; a card or a slot that only does 1-bit still mounts.
static bool sd_mount_sdmmc(void)
{
    if (SD_MMC.setPins(SD_CLK, SD_CMD, SD_D0, SD_D1, SD_D2, SD_D3) &&
        SD_MMC.begin(MW_SD_MOUNT, false /* 4-bit */, false /* never format */,
                     SDMMC_FREQ_DEFAULT, 5)) {
        return true;
    }
    SD_MMC.end();
    return SD_MMC.setPins(SD_CLK, SD_CMD, SD_D0) &&
           SD_MMC.begin(MW_SD_MOUNT, true /* 1-bit */, false, SDMMC_FREQ_DEFAULT, 5);
}

mw_err_t mw_sd_init(void)
{
    if (s_sd_ready) return MW_OK;
    if (SD_DETECT >= 0) {
        pinMode(SD_DETECT, INPUT_PULLUP);
        if (digitalRead(SD_DETECT) != LOW) return MW_ERR_IO;   // no card
    }
    if (!sd_mount_sdmmc()) { SD_MMC.end(); return MW_ERR_IO; }
    if (SD_MMC.cardType() == CARD_NONE) { SD_MMC.end(); return MW_ERR_IO; }
    s_sd_ready = true;
    return MW_OK;
}
#else
static bool sd_mount(uint32_t hz)
{
    return SD.begin((uint8_t)SD_CS, SPI, hz, MW_SD_MOUNT, 5 /* max open files */,
                    false /* never format behind the user's back */);
}

mw_err_t mw_sd_init(void)
{
    if (s_sd_ready) return MW_OK;

    // Park every other chip select on the shared bus first.
    if (TFT_CS >= 0) { pinMode(TFT_CS, OUTPUT); digitalWrite(TFT_CS, HIGH); }
#if HAS_TOUCH && (TOUCH_DRIVER == TOUCH_XPT2046)
    if (TOUCH_CS >= 0) { pinMode(TOUCH_CS, OUTPUT);
                         digitalWrite(TOUCH_CS, HIGH); }
#endif
    pinMode(SD_CS, OUTPUT);
    digitalWrite(SD_CS, HIGH);

    if (SD_DETECT >= 0) {
        pinMode(SD_DETECT, INPUT_PULLUP);
        if (digitalRead(SD_DETECT) != LOW) return MW_ERR_IO;   // no card
    }

#if !MW_SPI_BUS_SHARED
    // Exclusive bus (the display is an OLED or an RGB panel): bring it up here.
    SPI.begin(SD_SCK, SD_MISO, SD_MOSI, -1);
#endif

    // Slow probe, then remount at speed.  If the fast mount fails - long
    // jumper wires, a marginal card - fall back to 4 MHz rather than giving up.
    if (!sd_mount(MW_SD_INIT_HZ)) return MW_ERR_IO;
    SD.end();
    if (!sd_mount(MW_SD_FAST_HZ)) {
        if (!sd_mount(MW_SD_SAFE_HZ)) return MW_ERR_IO;
    }

    if (SD.cardType() == CARD_NONE) { SD.end(); return MW_ERR_IO; }

    s_sd_ready = true;
    return MW_OK;
}
#endif

bool mw_sd_present(void)
{
    if (SD_DETECT >= 0 && digitalRead(SD_DETECT) != LOW) return false;
    return s_sd_ready && SDFS.cardType() != CARD_NONE;
}

// The card is a removable courier: it may have been pulled out and another
// one (or the same one, edited on the PC) put in at any time. A volume that
// stays mounted keeps FAT and directory sectors cached and keeps answering
// from them after the card is gone, and the SDMMC host then refuses to bring
// up the new card. So every use starts with a fresh mount, and the volume is
// released again as soon as the work is done (mw_sd_release()).
mw_err_t mw_sd_ensure(void)
{
    mw_sd_release();
    return mw_sd_init();
}

// Flushes everything still cached for the volume (FAT, directory entries,
// file data) to the card and unmounts it; the card can be pulled out safely
// afterwards.
void mw_sd_release(void)
{
    if (!s_sd_ready) return;
    SDFS.end();
    s_sd_ready = false;
}

// --------------------------------------------------------------------------
// Read
// --------------------------------------------------------------------------
mw_err_t mw_sd_read_file(const char* path, uint8_t* buf, size_t cap,
                         size_t* len)
{
    if (len) *len = 0;
    if (!buf || cap == 0) return MW_ERR_INVALID_ARG;
    if (!s_sd_ready)      return MW_ERR_IO;

    char full[MW_SD_PATH_MAX];
    mw_err_t e = sd_path(full, path);
    if (e != MW_OK) return e;

    File f = SDFS.open(full, FILE_READ);
    if (!f) return MW_ERR_IO;
    if (f.isDirectory()) { f.close(); return MW_ERR_INVALID_ARG; }

    size_t size = (size_t)f.size();
    if (size > MW_SD_FILE_MAX) { f.close(); return MW_ERR_TOO_MANY; }
    if (size > cap)            { f.close(); return MW_ERR_MEMORY; }

    size_t got = 0;
    while (got < size) {
        int n = f.read(buf + got, size - got);
        if (n <= 0) break;
        got += (size_t)n;
    }
    f.close();

    if (got != size) return MW_ERR_IO;
    if (len) *len = got;
    return MW_OK;
}

// --------------------------------------------------------------------------
// Write
// --------------------------------------------------------------------------
mw_err_t mw_sd_write_file(const char* path, const uint8_t* buf, size_t len)
{
    if (!buf && len) return MW_ERR_INVALID_ARG;
    if (len > MW_SD_FILE_MAX) return MW_ERR_TOO_MANY;
    if (!s_sd_ready) return MW_ERR_IO;

    char full[MW_SD_PATH_MAX];
    mw_err_t e = sd_path(full, path);
    if (e != MW_OK) return e;

    File f = SDFS.open(full, FILE_WRITE);   // FILE_WRITE truncates on this core
    if (!f) return MW_ERR_IO;

    size_t put = 0;
    while (put < len) {
        // Chunked so a short write is detected instead of silently truncating.
        size_t chunk = len - put;
        if (chunk > 4096) chunk = 4096;
        size_t n = f.write(buf + put, chunk);
        if (n != chunk) { f.close(); SDFS.remove(full); return MW_ERR_IO; }
        put += n;
    }
    f.flush();                // file data and size reach the card here...
    f.close();                // ...and the directory entry with f_close()
    return MW_OK;
}

// --------------------------------------------------------------------------
// List
// --------------------------------------------------------------------------
mw_err_t mw_sd_list(const char* dir, char (*names)[64], int max, int* count)
{
    if (count) *count = 0;
    if (!names || max <= 0) return MW_ERR_INVALID_ARG;
    if (!s_sd_ready)        return MW_ERR_IO;

    char full[MW_SD_PATH_MAX];
    mw_err_t e = sd_path(full, (dir && dir[0]) ? dir : "/");
    if (e != MW_OK) return e;

    File d = SDFS.open(full);
    if (!d) return MW_ERR_IO;
    if (!d.isDirectory()) { d.close(); return MW_ERR_INVALID_ARG; }

    int n = 0;
    for (File f = d.openNextFile(); f; f = d.openNextFile()) {
        if (n >= max) { f.close(); break; }

        // f.name() is the bare LFN on core 2.x+ and a full path on older
        // cores; take whatever follows the last '/' either way.
        const char* nm = f.name();
        if (!nm) { f.close(); continue; }
        const char* slash = strrchr(nm, '/');
        if (slash) nm = slash + 1;

        // Bounded copy: MW_SD_NAME_MAX - 1 bytes plus the terminator, never
        // more, whatever the card claims the name length is.
        size_t nl = strnlen(nm, MW_SD_NAME_MAX);
        if (nl >= MW_SD_NAME_MAX) nl = MW_SD_NAME_MAX - 1;
        memcpy(names[n], nm, nl);
        names[n][nl] = '\0';
        ++n;
        f.close();
    }
    d.close();

    if (count) *count = n;
    return MW_OK;
}

// --------------------------------------------------------------------------
// File browser helpers
// --------------------------------------------------------------------------
mw_err_t mw_sd_list_files(const char* dir, mw_sd_entry_t* out, int max, int* count)
{
    if (count) *count = 0;
    if (!out || max <= 0) return MW_ERR_INVALID_ARG;
    if (!s_sd_ready)      return MW_ERR_IO;

    char full[MW_SD_PATH_MAX];
    mw_err_t e = sd_path(full, (dir && dir[0]) ? dir : "/");
    if (e != MW_OK) return e;

    File d = SDFS.open(full);
    if (!d) return MW_ERR_IO;
    if (!d.isDirectory()) { d.close(); return MW_ERR_INVALID_ARG; }

    int n = 0;
    for (File f = d.openNextFile(); f; f = d.openNextFile()) {
        if (n >= max) { f.close(); break; }
        if (f.isDirectory()) { f.close(); continue; }
        const char* nm = f.name();
        const char* slash = nm ? strrchr(nm, '/') : NULL;
        if (slash) nm = slash + 1;
        const size_t nl = nm ? strnlen(nm, MW_SD_ENTRY_NAME) : 0;
        // Skip what cannot be opened again by name: too long, hidden/system.
        if (nl == 0 || nl >= MW_SD_ENTRY_NAME || nm[0] == '.') { f.close(); continue; }
        memcpy(out[n].name, nm, nl);
        out[n].name[nl] = '\0';
        out[n].size  = (uint32_t)f.size();
        out[n].mtime = (int64_t)f.getLastWrite();
        ++n;
        f.close();
    }
    d.close();
    if (count) *count = n;
    return MW_OK;
}

mw_err_t mw_sd_read_head(const char* path, uint8_t* buf, size_t cap, size_t* len)
{
    if (len) *len = 0;
    if (!buf || cap == 0) return MW_ERR_INVALID_ARG;
    if (!s_sd_ready)      return MW_ERR_IO;
    char full[MW_SD_PATH_MAX];
    mw_err_t e = sd_path(full, path);
    if (e != MW_OK) return e;
    File f = SDFS.open(full, FILE_READ);
    if (!f) return MW_ERR_IO;
    if (f.isDirectory()) { f.close(); return MW_ERR_INVALID_ARG; }
    const int n = f.read(buf, cap);
    f.close();
    if (n < 0) return MW_ERR_IO;
    if (len) *len = (size_t)n;
    return MW_OK;
}

bool mw_sd_exists(const char* path)
{
    if (!s_sd_ready) return false;
    char full[MW_SD_PATH_MAX];
    if (sd_path(full, path) != MW_OK) return false;
    return SDFS.exists(full);
}

mw_err_t mw_sd_set_mtime(const char* path, int64_t unix_time)
{
    if (!s_sd_ready) return MW_ERR_IO;
    if (unix_time <= 0) return MW_ERR_INVALID_ARG;
    char full[MW_SD_PATH_MAX];
    mw_err_t e = sd_path(full, path);
    if (e != MW_OK) return e;
    // The FS layer has no utime(): go through the VFS mount point.
    char vfs[sizeof(MW_SD_MOUNT) + MW_SD_PATH_MAX];
    snprintf(vfs, sizeof(vfs), "%s%s", MW_SD_MOUNT, full);
    struct utimbuf t;
    t.actime  = (time_t)unix_time;
    t.modtime = (time_t)unix_time;
    return utime(vfs, &t) == 0 ? MW_OK : MW_ERR_IO;
}

// --------------------------------------------------------------------------
// Format
// --------------------------------------------------------------------------
// Neither Arduino SD library exposes a partition-level format, and the
// ESP-IDF one is behind a card handle this library keeps private.  What is
// implemented here is therefore a *quick erase*: every entry below the root is
// removed, leaving the existing FAT32 volume in place.
//
// That is the right behaviour for this device anyway - the card is the
// air-gap courier (TZ 3.2), and a user who asks to wipe it wants the
// outputs/keyimages/tx files gone, not a new partition table.  Nothing secret
// is ever written to the card unencrypted, so a quick erase is not a security
// downgrade either.
static mw_err_t sd_rm_tree(const char* path, int depth)
{
    if (depth > 8) return MW_ERR_TOO_MANY;      // bounded recursion

    File d = SDFS.open(path);
    if (!d) return MW_ERR_IO;
    if (!d.isDirectory()) { d.close(); return SDFS.remove(path) ? MW_OK
                                                             : MW_ERR_IO; }

    mw_err_t rc = MW_OK;
    for (File f = d.openNextFile(); f; f = d.openNextFile()) {
        char child[MW_SD_PATH_MAX];
        const char* nm = f.name();
        const char* slash = nm ? strrchr(nm, '/') : NULL;
        if (slash) nm = slash + 1;
        bool is_dir = f.isDirectory();
        f.close();
        if (!nm || !nm[0]) continue;

        // Bounded join: "<path>" + "/" + "<name>" + NUL must fit.
        size_t pl = strnlen(path, MW_SD_PATH_MAX);
        size_t nl = strnlen(nm,   MW_SD_NAME_MAX);
        bool   need_sep = (pl > 0 && path[pl - 1] != '/');
        if (pl + (need_sep ? 1u : 0u) + nl + 1u > MW_SD_PATH_MAX) {
            rc = MW_ERR_RANGE;                  // skip, but report
            continue;
        }
        memcpy(child, path, pl);
        size_t o = pl;
        if (need_sep) child[o++] = '/';
        memcpy(child + o, nm, nl);
        child[o + nl] = '\0';

        if (is_dir) {
            mw_err_t e = sd_rm_tree(child, depth + 1);
            if (e != MW_OK) rc = e;
            if (!SDFS.rmdir(child)) rc = MW_ERR_IO;
        } else if (!SDFS.remove(child)) {
            rc = MW_ERR_IO;
        }
    }
    d.close();
    return rc;
}

mw_err_t mw_sd_format(void)
{
    if (!s_sd_ready) return MW_ERR_IO;
    return sd_rm_tree("/", 0);
}

mw_err_t mw_sd_unlink(const char* path)
{
    char full[MW_SD_PATH_MAX];
    if (!s_sd_ready)      return MW_ERR_NOT_SUPPORTED;

    mw_err_t err = sd_path(full, path);
    if (err != MW_OK) return err;
    if (!SDFS.exists(full)) return MW_ERR_IO;
    return SDFS.remove(full) ? MW_OK : MW_ERR_IO;
}

#endif  // HAS_SD
#endif  // ARDUINO && !MW_HOST_BUILD
