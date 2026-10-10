// Host-only backend for secure_storage.h.
//
// ############################################################################
// #  THIS FILE IS NOT SECURE AND IS NEVER COMPILED INTO THE FIRMWARE.        #
// #                                                                          #
// #  It emulates the eFuse-backed sealing layer with a plain file on disk so  #
// #  that the unit tests can exercise the full provision / seal / unseal /    #
// #  wipe lifecycle on a PC.  The "hardware" root key is a 32-byte file that  #
// #  anybody can read.  There is no key isolation, no read protection and no  #
// #  encrypted NVS.  Do not reuse this code for anything but tests.           #
// ############################################################################
//
// The device implementation lives in secure_storage.cpp; the two are selected
// by the MW_HOST_BUILD guard so both can sit in the same directory.

#ifdef MW_HOST_BUILD

#include "secure_storage.h"
#include "file_store.h"
#include "../config/app_config.h"
#include "../crypto/aes_gcm.h"
#include "../crypto/hash.h"
#include "../crypto/memzero.h"
#include "../crypto/random.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <dirent.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <unistd.h>
#if defined(_WIN32)
#  include <direct.h>
#endif

// ---------------------------------------------------------------------------
// Internal blob API - the wallet store talks to the platform through these
// three functions.  secure_storage.cpp provides the NVS-backed twin.
// ---------------------------------------------------------------------------
mw_err_t mw_store_blob_write(const char* key, const void* data, size_t len);
mw_err_t mw_store_blob_read(const char* key, void* out, size_t cap, size_t* len_out);
mw_err_t mw_store_blob_erase(const char* key);

// Test-only hooks, declared by the test suites (not part of the frozen API).
void mw_host_store_set_dir(const char* dir);
void mw_host_store_reset(void);
void mw_settings_test_set_display(int has_touch, int width, int height);
void mw_host_store_fail_writes(const char* key, int n);
void mw_host_store_fail_reads(const char* key, int n);

#define MW_HOST_STORE_DEFAULT_DIR "./.mw_host_store"
#define MW_HOST_ROOT_KEY_FILE     "efuse_hmac_key0.bin"
#define MW_SETTINGS_BLOB_KEY      "settings"
// v2 (task2): usb_mode is gone, kb_layout and debug_log were added.
#define MW_SETTINGS_VERSION       2
#define MW_SETTINGS_BLOB_LEN      40

static char g_dir[512] = MW_HOST_STORE_DEFAULT_DIR;

// AUTO-keyboard inputs (TZ 5.5).  On the device these come from board_config.h;
// on the host the tests drive them explicitly.
static int g_has_touch = 0;
static int g_width     = 0;
static int g_height    = 0;

// Fault injection: the next n writes (or reads) of `key` fail with MW_ERR_IO.
static char g_fail_wkey[32];
static int  g_fail_wn;
static int  g_fail_wskip;            // writes of g_fail_wkey let through first
static char g_fail_rkey[32];
static int  g_fail_rn;

void mw_host_store_fail_writes(const char* key, int n)
{
    snprintf(g_fail_wkey, sizeof g_fail_wkey, "%s", key ? key : "");
    g_fail_wn = (key && n > 0) ? n : 0;
    g_fail_wskip = 0;
}

// Lets `skip` writes of `key` through, then fails the next `n` (a power cut
// at a chosen point of a multi-write operation).
void mw_host_store_fail_writes_after(const char* key, int skip, int n)
{
    mw_host_store_fail_writes(key, n);
    g_fail_wskip = (key && skip > 0) ? skip : 0;
}

void mw_host_store_fail_reads(const char* key, int n)
{
    snprintf(g_fail_rkey, sizeof g_fail_rkey, "%s", key ? key : "");
    g_fail_rn = (key && n > 0) ? n : 0;
}

static int injected_fail(const char* key, const char* fkey, int* n)
{
    if (*n <= 0 || strcmp(key, fkey) != 0) return 0;
    --*n;
    return 1;
}

void mw_host_store_set_dir(const char* dir)
{
    if (!dir) return;
    snprintf(g_dir, sizeof g_dir, "%s", dir);
}

void mw_settings_test_set_display(int has_touch, int width, int height)
{
    g_has_touch = has_touch;
    g_width     = width;
    g_height    = height;
}

static void path_for(const char* key, char* out, size_t cap)
{
    snprintf(out, cap, "%s/%s", g_dir, key);
}

static int ensure_dir(void)
{
    struct stat st;
    if (stat(g_dir, &st) == 0) return 0;
#if defined(_WIN32)
    return _mkdir(g_dir);            /* mingw-w64 host: no mode argument */
#else
    return mkdir(g_dir, 0700);
#endif
}

void mw_host_store_reset(void)
{
    static const char* keys[] = {
        MW_HOST_ROOT_KEY_FILE, MW_SETTINGS_BLOB_KEY, "wallets", "devauth", NULL
    };
    char p[640];
    for (int i = 0; keys[i]; i++) {
        path_for(keys[i], p, sizeof p);
        (void)remove(p);
    }
    // Key image cache generations ("kig<id><variant>", ki_cache.c).
    for (unsigned long id = 0; id < 64; id++) {
        for (unsigned v = 0; v < 2; v++) {
            char k[16];
            snprintf(k, sizeof k, "kig%08lx%u", id, v);
            path_for(k, p, sizeof p);
            (void)remove(p);
        }
    }
    (void)mw_fstore_wipe_all();
    // Leave no litter in the source tree when the suites finish.
    (void)rmdir(g_dir);
}

// ---------------------------------------------------------------------------
// Blob storage (a file per key)
// ---------------------------------------------------------------------------

mw_err_t mw_store_blob_write(const char* key, const void* data, size_t len)
{
    char p[640];
    FILE* f;
    if (!key || (!data && len)) return MW_ERR_INVALID_ARG;
    if (g_fail_wskip > 0 && g_fail_wn > 0 && strcmp(key, g_fail_wkey) == 0) {
        g_fail_wskip--;                      // let this one through
    } else if (injected_fail(key, g_fail_wkey, &g_fail_wn)) {
        return MW_ERR_IO;
    }
    if (ensure_dir() != 0) return MW_ERR_IO;
    path_for(key, p, sizeof p);
    f = fopen(p, "wb");
    if (!f) return MW_ERR_IO;
    if (len && fwrite(data, 1, len, f) != len) { fclose(f); return MW_ERR_IO; }
    if (fflush(f) != 0) { fclose(f); return MW_ERR_IO; }
    fclose(f);
    return MW_OK;
}

mw_err_t mw_store_blob_read(const char* key, void* out, size_t cap, size_t* len_out)
{
    char p[640];
    FILE* f;
    size_t n;
    if (!key || !out) return MW_ERR_INVALID_ARG;
    if (injected_fail(key, g_fail_rkey, &g_fail_rn)) return MW_ERR_IO;
    path_for(key, p, sizeof p);
    f = fopen(p, "rb");
    if (!f) return MW_ERR_IO;                 // "not found"
    n = fread(out, 1, cap, f);
    // Anything longer than `cap` means a layout mismatch, not a short read.
    if (!feof(f) && fgetc(f) != EOF) { fclose(f); return MW_ERR_FORMAT; }
    fclose(f);
    if (len_out) *len_out = n;
    return MW_OK;
}

mw_err_t mw_store_blob_erase(const char* key)
{
    char p[640];
    if (!key) return MW_ERR_INVALID_ARG;
    path_for(key, p, sizeof p);
    if (remove(p) != 0) return MW_ERR_IO;
    return MW_OK;
}

// ---------------------------------------------------------------------------
// "eFuse" root key emulation
// ---------------------------------------------------------------------------

static mw_err_t read_root_key(uint8_t out[32])
{
    size_t len = 0;
    mw_err_t err = mw_store_blob_read(MW_HOST_ROOT_KEY_FILE, out, 32, &len);
    if (err != MW_OK) return err;
    if (len != 32) return MW_ERR_FORMAT;
    return MW_OK;
}

mw_err_t mw_secure_key_status(void)
{
    uint8_t k[32];
    mw_err_t err = read_root_key(k);
    mw_memzero(k, sizeof k);
    return (err == MW_OK) ? MW_OK : MW_ERR_NOT_SUPPORTED;
}

mw_err_t mw_secure_key_provision(void)
{
    uint8_t k[32];
    mw_err_t err;
    if (mw_secure_key_status() == MW_OK) return MW_OK;   // already provisioned
    mw_random_bytes(k, sizeof k);
    err = mw_store_blob_write(MW_HOST_ROOT_KEY_FILE, k, sizeof k);
    mw_memzero(k, sizeof k);
    return err;
}

/* Emulated key blocks: the "wallet key" sits in BLOCK_KEY5 once provisioned. */
int mw_secure_key_block(void)
{
    return (mw_secure_key_status() == MW_OK) ? 5 : -1;
}

int mw_secure_key_target_block(void)
{
    return 5;
}

mw_err_t mw_secure_key_blocks(mw_key_block_info_t out[MW_SECURE_KEY_BLOCKS])
{
    if (!out) return MW_ERR_INVALID_ARG;
    const bool have = mw_secure_key_status() == MW_OK;
    for (int i = 0; i < MW_SECURE_KEY_BLOCKS; ++i) {
        out[i].used = out[i].read_protected = out[i].wallet_key = (have && i == 5);
        out[i].purpose = out[i].used ? "HMAC UP" : "free";
    }
    return MW_OK;
}

// ---------------------------------------------------------------------------
// User password key (task2 item 1) - mirrors secure_storage.cpp.
// ---------------------------------------------------------------------------
static uint8_t g_user_key[32];
static int     g_user_key_set = 0;

mw_err_t mw_secure_user_key_set(const uint8_t key[32])
{
    if (!key) return MW_ERR_INVALID_ARG;
    if (mw_ct_is_zero(key, 32)) return MW_ERR_INVALID_ARG;
    memcpy(g_user_key, key, 32);
    g_user_key_set = 1;
    return MW_OK;
}

void mw_secure_user_key_clear(void)
{
    mw_memzero(g_user_key, sizeof g_user_key);
    g_user_key_set = 0;
}

bool mw_secure_user_key_present(void)
{
    return g_user_key_set != 0;
}

// HMAC-SHA256(user key, label || data): names of the user's files.
mw_err_t mw_secure_user_mac(const char* label, const uint8_t* data, size_t len,
                                       uint8_t out[32])
{
    uint8_t msg[96];
    const size_t ll = label ? strlen(label) : 0;
    if (!label || !out || (!data && len) || ll + len > sizeof msg) return MW_ERR_INVALID_ARG;
    if (!g_user_key_set) return MW_ERR_NOT_SUPPORTED;
    memcpy(msg, label, ll);
    if (len) memcpy(msg + ll, data, len);
    mw_hmac_sha256(g_user_key, sizeof g_user_key, msg, ll + len, out);
    mw_memzero(msg, sizeof msg);
    return MW_OK;
}

mw_err_t mw_secure_user_key_copy(uint8_t out[32])
{
    if (!out) return MW_ERR_INVALID_ARG;
    if (!g_user_key_set) return MW_ERR_NOT_SUPPORTED;
    memcpy(out, g_user_key, 32);
    return MW_OK;
}

// Mirrors secure_storage.cpp: the emulated root key when "provisioned",
// otherwise the same public-constant fallback the device uses in bring-up.
mw_err_t mw_secure_hw_hmac(const uint8_t* msg, size_t len, uint8_t out[32], bool* bound)
{
    uint8_t root[32];
    if ((!msg && len) || !out) return MW_ERR_INVALID_ARG;
    if (bound) *bound = false;
    if (read_root_key(root) == MW_OK) {
        mw_hmac_sha256(root, sizeof root, msg, len, out);
        mw_memzero(root, sizeof root);
        if (bound) *bound = true;
        return MW_OK;
    }
    mw_memzero(root, sizeof root);
    {
        static const char k_fallback[] = "mw.hw.hmac.fallback (eFuse not provisioned)";
        mw_hmac_sha256((const uint8_t*)k_fallback, sizeof k_fallback - 1, msg, len, out);
    }
    return MW_OK;
}

// Per-label key derivation.  On the device this is esp_hmac_calculate() with
// the read-protected eFuse block; here it is a software HMAC-SHA256 over a key
// that is sitting in a file.  Same construction, zero security.  The result is
// then mixed with the user password key exactly as on the device:
//     key = HMAC-SHA256(user_key, hw_key || label)
static mw_err_t derive_label_key(const char* label, uint8_t out[32], bool legacy)
{
    uint8_t root[32], hw[32], msg[32 + 64];
    size_t  llen;
    mw_err_t err;
    if (!label || !*label) return MW_ERR_INVALID_ARG;
    llen = strlen(label);
    if (llen > 64) return MW_ERR_INVALID_ARG;
    if (legacy) {
        mw_keccak256((const uint8_t*)label, llen, hw);   /* old bring-up mode */
    } else {
        err = read_root_key(root);
        if (err != MW_OK) { mw_memzero(root, sizeof root); return MW_ERR_NOT_SUPPORTED; }
        mw_hmac_sha256(root, sizeof root, (const uint8_t*)label, llen, hw);
        mw_memzero(root, sizeof root);
    }

    if (!g_user_key_set) {
        mw_memzero(hw, sizeof hw);
        return MW_ERR_NOT_SUPPORTED;        /* no password entered this session */
    }
    memcpy(msg, hw, 32);
    memcpy(msg + 32, label, llen);
    mw_hmac_sha256(g_user_key, sizeof g_user_key, msg, 32 + llen, out);
    mw_memzero(hw, sizeof hw);
    mw_memzero(msg, sizeof msg);
    return MW_OK;
}

static mw_err_t seal_with(const char* label, const uint8_t* pt, size_t pt_len,
                          uint8_t* iv16, uint8_t* tag16, uint8_t* ct, size_t ct_cap,
                          bool legacy)
{
    uint8_t key[32];
    mw_err_t err;
    int rc;

    if (!label || !iv16 || !tag16 || (pt_len && (!pt || !ct)) || ct_cap < pt_len)
        return MW_ERR_INVALID_ARG;

    err = derive_label_key(label, key, legacy);
    if (err != MW_OK) { mw_memzero(key, sizeof key); return err; }

    mw_random_bytes(iv16, MW_GCM_IV_BYTES);
    rc = mw_aes256_gcm_encrypt(key, iv16, MW_GCM_IV_BYTES, NULL, 0,
                               pt, pt_len, ct, tag16);
    mw_memzero(key, sizeof key);
    return (rc == MW_AES_GCM_OK) ? MW_OK : MW_ERR_INVALID_ARG;
}

mw_err_t mw_seal(const char* label, const uint8_t* pt, size_t pt_len,
                 uint8_t* iv16, uint8_t* tag16, uint8_t* ct, size_t ct_cap)
{
    return seal_with(label, pt, pt_len, iv16, tag16, ct, ct_cap, false);
}

mw_err_t mw_host_seal_legacy(const char* label, const uint8_t* pt, size_t pt_len,
                             uint8_t* iv16, uint8_t* tag16, uint8_t* ct, size_t ct_cap)
{
    return seal_with(label, pt, pt_len, iv16, tag16, ct, ct_cap, true);
}

static bool g_last_legacy = false;

bool mw_secure_last_unseal_legacy(void)
{
    return g_last_legacy;
}

mw_err_t mw_unseal(const char* label, const uint8_t* ct, size_t ct_len,
                   const uint8_t* iv16, const uint8_t* tag16,
                   uint8_t* pt, size_t pt_cap)
{
    uint8_t key[32];
    mw_err_t err;
    int rc;

    g_last_legacy = false;
    if (!label || !iv16 || !tag16 || (ct_len && (!ct || !pt)) || pt_cap < ct_len)
        return MW_ERR_INVALID_ARG;

    err = derive_label_key(label, key, false);
    if (err != MW_OK) { mw_memzero(key, sizeof key); return err; }

    rc = mw_aes256_gcm_decrypt(key, iv16, MW_GCM_IV_BYTES, NULL, 0,
                               ct, ct_len, tag16, pt);
    if (rc == MW_AES_GCM_BAD_TAG) {            /* mirrors the device */
        err = derive_label_key(label, key, true);
        if (err == MW_OK &&
            mw_aes256_gcm_decrypt(key, iv16, MW_GCM_IV_BYTES, NULL, 0,
                                  ct, ct_len, tag16, pt) == MW_AES_GCM_OK) {
            g_last_legacy = true;
            rc = MW_AES_GCM_OK;
        } else if (ct_len) {
            mw_memzero(pt, ct_len);
        }
    }
    mw_memzero(key, sizeof key);
    if (rc == MW_AES_GCM_BAD_TAG) return MW_ERR_DECRYPT;
    return (rc == MW_AES_GCM_OK) ? MW_OK : MW_ERR_INVALID_ARG;
}

// ---------------------------------------------------------------------------
// Settings (TZ 4.2, 5.5)
// ---------------------------------------------------------------------------

// Mirrors secure_storage.cpp: TZ 2.2 / 5.5, the board's pinned
// DEFAULT_SEED_INPUT_MODE wins and only SEED_INPUT_AUTO falls through to the
// resolution rule. The host build has no board_config.h, so unless a test
// defines it on the command line this compiles to the AUTO branch alone.
#ifndef DEFAULT_SEED_INPUT_MODE
#define DEFAULT_SEED_INPUT_MODE SEED_INPUT_AUTO
#endif

// AUTO rule, verbatim:
//   no touch                       -> KEYBOARD_SCROLL
//   touch and >= 240x240           -> KEYBOARD_FULL
//   touch and <  240x240           -> KEYBOARD_SCROLL
keyboard_type_t mw_settings_default_keyboard(void)
{
#if DEFAULT_SEED_INPUT_MODE == SEED_INPUT_FULL_KB
    return KEYBOARD_FULL;
#elif DEFAULT_SEED_INPUT_MODE == SEED_INPUT_SCROLL_KB
    return KEYBOARD_SCROLL;
#else
    if (!g_has_touch) return KEYBOARD_SCROLL;
    if (g_width >= 240 && g_height >= 240) return KEYBOARD_FULL;
    return KEYBOARD_SCROLL;
#endif
}

static void settings_defaults(mw_settings_t* s)
{
    memset(s, 0, sizeof *s);
    s->keyboard         = mw_settings_default_keyboard();
    s->kb_layout        = KB_LAYOUT_QWERTY;
    s->brightness       = 80;
    s->autolock_min     = MW_AUTOLOCK_DEFAULT_MIN;
    s->touch_calibrated = false;
    s->network          = MW_DEFAULT_NETWORK;
    s->debug_log        = false;
    s->version          = MW_SETTINGS_VERSION;
}

static void put_u16(uint8_t* p, uint16_t v) { p[0] = (uint8_t)v; p[1] = (uint8_t)(v >> 8); }
static uint16_t get_u16(const uint8_t* p)   { return (uint16_t)(p[0] | ((uint16_t)p[1] << 8)); }
static void put_i32(uint8_t* p, int32_t v)
{
    uint32_t u = (uint32_t)v;
    p[0] = (uint8_t)u; p[1] = (uint8_t)(u >> 8);
    p[2] = (uint8_t)(u >> 16); p[3] = (uint8_t)(u >> 24);
}
static int32_t get_i32(const uint8_t* p)
{
    uint32_t u = (uint32_t)p[0] | ((uint32_t)p[1] << 8) |
                 ((uint32_t)p[2] << 16) | ((uint32_t)p[3] << 24);
    return (int32_t)u;
}

// Explicit little-endian serialisation: the struct layout may change between
// firmware revisions, the blob layout may not without a version bump.
static void settings_serialize(const mw_settings_t* s, uint8_t b[MW_SETTINGS_BLOB_LEN])
{
    memset(b, 0, MW_SETTINGS_BLOB_LEN);
    b[0] = 'M'; b[1] = 'W'; b[2] = 'S'; b[3] = 'T';
    b[4] = MW_SETTINGS_VERSION;
    b[5] = (uint8_t)s->keyboard;
    b[6] = (uint8_t)s->kb_layout;
    b[7] = s->brightness;
    put_u16(b + 8, s->autolock_min);
    b[10] = s->touch_calibrated ? 1u : 0u;
    b[11] = (uint8_t)s->network;
    for (int i = 0; i < 6; i++) put_i32(b + 12 + 4 * i, s->touch_calib[i]);
    b[36] = s->debug_log ? 1u : 0u;
    memcpy(b + 37, s->touch_cal_tag, 3);   // touch calibration tag
}

static mw_err_t settings_deserialize(mw_settings_t* s, const uint8_t* b, size_t len)
{
    if (len != MW_SETTINGS_BLOB_LEN) return MW_ERR_FORMAT;
    if (b[0] != 'M' || b[1] != 'W' || b[2] != 'S' || b[3] != 'T') return MW_ERR_MAGIC;
    if (b[4] != MW_SETTINGS_VERSION) return MW_ERR_VERSION;
    memset(s, 0, sizeof *s);
    s->keyboard         = (b[5] == (uint8_t)KEYBOARD_FULL) ? KEYBOARD_FULL : KEYBOARD_SCROLL;
    s->kb_layout        = (b[6] == (uint8_t)KB_LAYOUT_ABC) ? KB_LAYOUT_ABC : KB_LAYOUT_QWERTY;
    s->brightness       = (b[7] <= 100u) ? b[7] : 100u;
    s->autolock_min     = get_u16(b + 8);
    s->touch_calibrated = (b[10] != 0);
    s->network          = (b[11] <= (uint8_t)MW_NET_STAGENET) ? (mw_network_t)b[11] : MW_NET_MAINNET;
    for (int i = 0; i < 6; i++) s->touch_calib[i] = get_i32(b + 12 + 4 * i);
    s->debug_log        = (b[36] != 0);
    memcpy(s->touch_cal_tag, b + 37, 3);
    s->version          = MW_SETTINGS_VERSION;
    return MW_OK;
}

mw_err_t mw_settings_load(mw_settings_t* out)
{
    uint8_t blob[MW_SETTINGS_BLOB_LEN];
    size_t len = 0;
    if (!out) return MW_ERR_INVALID_ARG;
    // A missing, truncated or older blob is not an error: a firmware upgrade
    // must never read garbage, it must fall back to the defaults (TZ 4.2).
    if (mw_store_blob_read(MW_SETTINGS_BLOB_KEY, blob, sizeof blob, &len) != MW_OK ||
        settings_deserialize(out, blob, len) != MW_OK) {
        settings_defaults(out);
        return MW_OK;
    }
    return MW_OK;
}

mw_err_t mw_settings_save(const mw_settings_t* s)
{
    uint8_t blob[MW_SETTINGS_BLOB_LEN];
    if (!s) return MW_ERR_INVALID_ARG;
    if (s->brightness > 100) return MW_ERR_RANGE;
    settings_serialize(s, blob);
    return mw_store_blob_write(MW_SETTINGS_BLOB_KEY, blob, sizeof blob);
}

// ---------------------------------------------------------------------------
// File store (file_store.h): files named "fs_<name>" in the same directory,
// so mw_host_store_reset() / mw_fstore_wipe_all() can find them.
// ---------------------------------------------------------------------------

static int fstore_name_ok(const char* name)
{
    size_t n;
    if (!name) return 0;
    n = strlen(name);
    if (n == 0 || n > MW_FSTORE_NAME_MAX) return 0;
    for (size_t i = 0; i < n; i++) {
        const char c = name[i];
        if (!((c >= 'a' && c <= 'z') || (c >= '0' && c <= '9') || c == '_' || c == '.'))
            return 0;
    }
    return 1;
}

static void fstore_path(const char* name, char* out, size_t cap)
{
    snprintf(out, cap, "%s/fs_%s", g_dir, name);
}

static int host_exists(const char* p)
{
    struct stat st;
    return stat(p, &st) == 0;
}

// Same replace protocol as file_store_esp32.cpp: .tmp, old -> .bak, .tmp ->
// name, drop .bak; a cut leaves the old file or its .bak (put back here).
static void fstore_recover(const char* name)
{
    char p[640], bak[660], tmp[660];
    fstore_path(name, p, sizeof p);
    snprintf(bak, sizeof bak, "%s.bak", p);
    snprintf(tmp, sizeof tmp, "%s.tmp", p);
    if (!host_exists(p) && host_exists(bak)) (void)rename(bak, p);
    if (host_exists(p)) {
        (void)remove(bak);
        (void)remove(tmp);
    }
}

mw_err_t mw_fstore_init(void) { return ensure_dir() == 0 ? MW_OK : MW_ERR_IO; }
bool     mw_fstore_ready(void) { return true; }

mw_err_t mw_fstore_write(const char* name, const uint8_t* data, size_t len)
{
    char p[640], tmp[660];
    FILE* f;
    if (!fstore_name_ok(name) || (!data && len)) return MW_ERR_INVALID_ARG;
    if (ensure_dir() != 0) return MW_ERR_IO;
    fstore_recover(name);                // a lone .bak is the file
    fstore_path(name, p, sizeof p);
    snprintf(tmp, sizeof tmp, "%s.tmp", p);
    f = fopen(tmp, "wb");
    if (!f) return MW_ERR_IO;
    if (len && fwrite(data, 1, len, f) != len) { fclose(f); remove(tmp); return MW_ERR_IO; }
    if (fclose(f) != 0) { remove(tmp); return MW_ERR_IO; }
    {
        // rename() does not replace on Windows: the old file steps aside.
        char bak[660];
        snprintf(bak, sizeof bak, "%s.bak", p);
        (void)remove(bak);
        if (host_exists(p) && rename(p, bak) != 0) { remove(tmp); return MW_ERR_IO; }
        if (rename(tmp, p) != 0) {
            (void)rename(bak, p);
            remove(tmp);
            return MW_ERR_IO;
        }
        (void)remove(bak);
    }
    return MW_OK;
}

mw_err_t mw_fstore_size(const char* name, size_t* len)
{
    char p[640];
    struct stat st;
    if (!fstore_name_ok(name) || !len) return MW_ERR_INVALID_ARG;
    fstore_recover(name);
    fstore_path(name, p, sizeof p);
    if (stat(p, &st) != 0) return MW_ERR_IO;
    *len = (size_t)st.st_size;
    return MW_OK;
}

mw_err_t mw_fstore_read(const char* name, uint8_t* buf, size_t cap, size_t* len)
{
    char p[640];
    FILE* f;
    size_t n;
    if (!fstore_name_ok(name) || !buf || !len) return MW_ERR_INVALID_ARG;
    fstore_recover(name);
    fstore_path(name, p, sizeof p);
    f = fopen(p, "rb");
    if (!f) return MW_ERR_IO;
    n = fread(buf, 1, cap, f);
    if (!feof(f) && fgetc(f) != EOF) { fclose(f); return MW_ERR_TOO_MANY; }
    fclose(f);
    *len = n;
    return MW_OK;
}

mw_err_t mw_fstore_remove(const char* name)
{
    char p[640];
    size_t len = 0;
    if (!fstore_name_ok(name)) return MW_ERR_INVALID_ARG;
    if (mw_fstore_size(name, &len) != MW_OK) return MW_OK;     // nothing there
    fstore_path(name, p, sizeof p);
    {
        FILE* f = fopen(p, "r+b");
        if (f) {
            static const uint8_t zero[256] = {0};
            size_t left = len;
            while (left) {
                size_t k = left < sizeof zero ? left : sizeof zero;
                if (fwrite(zero, 1, k, f) != k) break;
                left -= k;
            }
            fclose(f);
        }
    }
    return remove(p) == 0 ? MW_OK : MW_ERR_IO;
}

int mw_fstore_list(const char* prefix, char (*names)[MW_FSTORE_NAME_MAX + 1], int max)
{
    DIR* d;
    struct dirent* de;
    int n = 0;
    size_t pl;
    if (!prefix) return -1;
    if (ensure_dir() != 0) return -1;
    pl = strlen(prefix);
    d = opendir(g_dir);
    if (!d) return -1;
    while ((de = readdir(d)) != NULL) {
        const char* nm = de->d_name;
        if (strncmp(nm, "fs_", 3) != 0) continue;
        nm += 3;
        if (!fstore_name_ok(nm) || strncmp(nm, prefix, pl) != 0) continue;
        if (strstr(nm, ".tmp") || strstr(nm, ".bak")) continue;
        if (names && n < max) snprintf(names[n], MW_FSTORE_NAME_MAX + 1, "%s", nm);
        n++;
    }
    closedir(d);
    return n;
}

mw_err_t mw_fstore_wipe_all(void)
{
    // Every file of the store, .tmp and .bak leftovers included.
    for (int round = 0; round < 64; round++) {
        DIR* d;
        struct dirent* de;
        char p[1024];
        int n = 0;
        if (ensure_dir() != 0) return MW_ERR_IO;
        d = opendir(g_dir);
        if (!d) return MW_ERR_IO;
        while ((de = readdir(d)) != NULL) {
            if (strncmp(de->d_name, "fs_", 3) != 0) continue;
            snprintf(p, sizeof p, "%s/%s", g_dir, de->d_name);
            (void)remove(p);
            n++;
        }
        closedir(d);
        if (n == 0) break;
    }
    return MW_OK;
}

#else  /* !MW_HOST_BUILD */
// Keep the translation unit non-empty for ISO C when building for the device.
typedef int mw_secure_storage_host_not_built;
#endif
