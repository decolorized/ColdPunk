// ESP32-S3 implementation of secure_storage.h (TZ 8.1, 4.2).
//
// Key hierarchy
//   eFuse BLOCK_KEYn (32 bytes, purpose HMAC_UP, read-protected; n is picked
//        |            at provisioning, see "eFuse key block" below)
//        |  esp_hmac_calculate(HMAC_KEYn, label)        <- runs in hardware,
//        v                                                 key never leaves the
//   per-label AES-256 key                                  eFuse block
//        |  AES-256-GCM (random 128-bit IV, 128-bit tag)
//        v
//   sealed blob stored in (already encrypted) NVS
//
// The eFuse key is not readable by software.  Even with a full flash dump and
// arbitrary code execution on a *different* chip the sealed blobs are useless;
// see docs/security.md for the complete threat model.
//
// This file is compiled only for the device.  The host test build uses
// secure_storage_host.c instead, selected by the MW_HOST_BUILD guard below.
//
// ---------------------------------------------------------------------------
// No eFuse key, no sealing
//
// The firmware asks for the eFuse key at the very first start, before the
// device password (flows.cpp), and nothing is sealed without it: mw_seal()
// and mw_secure_hw_hmac() refuse with MW_ERR_NOT_SUPPORTED.
//
// Records written by older firmware in the bring-up mode (hardware part =
// keccak256(label), a public value) can still be OPENED: mw_unseal() tries
// that key when the eFuse one does not authenticate, and reports it through
// mw_secure_last_unseal_legacy(). Such records are re-sealed under the eFuse
// key by the first password-record upgrade after provisioning (device_auth.c
// re-keys every wallet and key image cache). Nothing new is ever sealed that
// way.
// ---------------------------------------------------------------------------

#ifndef MW_HOST_BUILD

#include "secure_storage.h"
#include "../config/app_config.h"
#include "../crypto/aes_gcm.h"
#include "../crypto/hash.h"        // mw_keccak256 (debug fallback only)
#include "../crypto/memzero.h"
#include "../crypto/random.h"
#include "../hal/hal.h"
// Pulls in board_config.h (and therefore HAS_TOUCH, DISPLAY_*, and the
// DEFAULT_SEED_INPUT_MODE of TZ 2.2) with the fallbacks the HAL already
// defines for boards that leave an optional define out.
#include "../hal/display_drivers.h"

#include <string.h>

extern "C" {
#include "esp_attr.h"
#include "esp_err.h"
#include "esp_efuse.h"
#include "esp_hmac.h"
#include "esp_random.h"
#include "nvs.h"
#include "nvs_flash.h"
}


#define MW_NVS_NAMESPACE      "mwallet"
#define MW_SETTINGS_BLOB_KEY  "settings"
// v2 (task2): usb_mode is gone, kb_layout and debug_log were added.
#define MW_SETTINGS_VERSION   2
#define MW_SETTINGS_BLOB_LEN  40

// ---------------------------------------------------------------------------
// eFuse key block
//
// The ESP32-S3 has six 256-bit key blocks, BLOCK_KEY0..5. The chip itself
// keeps nothing there (calibration and MAC live in BLOCK1/2); they are taken
// only by features someone turns on: flash encryption (1-2 blocks) and secure
// boot (up to 3 digests), which ESP-IDF puts into the FIRST free block. So
// the wallet key goes into the HIGHEST free block, KEY5 down, and leaves the
// low ones to them.
//
// The block in use is the one with purpose HMAC_UP and read protection. Its
// number is remembered in NVS ("hw_kblk") so a second HMAC_UP block burned
// later by someone else cannot replace it; without the hint (older firmware
// used KEY0) the highest such block is taken.
// ---------------------------------------------------------------------------
#define MW_KEY_BLOCKS 6
#define MW_NVS_KBLK   "hw_kblk"

static int s_kblk = -2;                   // -2 not looked up yet, -1 none

static esp_efuse_block_t key_blk(int i) { return (esp_efuse_block_t)(EFUSE_BLK_KEY0 + i); }

static bool blk_is_wallet_key(int i)
{
    const esp_efuse_block_t b = key_blk(i);
    return !esp_efuse_key_block_unused(b) &&
           esp_efuse_get_key_purpose(b) == ESP_EFUSE_KEY_PURPOSE_HMAC_UP &&
           esp_efuse_get_key_dis_read(b);
}

static void kblk_remember(int i)
{
    nvs_handle_t h;
    if (nvs_open(MW_NVS_NAMESPACE, NVS_READWRITE, &h) != ESP_OK) return;
    if (nvs_set_u8(h, MW_NVS_KBLK, (uint8_t)i) == ESP_OK) (void)nvs_commit(h);
    nvs_close(h);
}

static int key_block(void)
{
    if (s_kblk >= 0 && blk_is_wallet_key(s_kblk)) return s_kblk;
    nvs_handle_t h;
    uint8_t v = 0xFF;
    if (nvs_open(MW_NVS_NAMESPACE, NVS_READONLY, &h) == ESP_OK) {
        if (nvs_get_u8(h, MW_NVS_KBLK, &v) != ESP_OK) v = 0xFF;
        nvs_close(h);
    }
    if (v < MW_KEY_BLOCKS && blk_is_wallet_key(v)) return s_kblk = v;
    for (int i = MW_KEY_BLOCKS - 1; i >= 0; --i) {
        if (blk_is_wallet_key(i)) {
            kblk_remember(i);
            return s_kblk = i;
        }
    }
    return s_kblk = -1;
}

static hmac_key_id_t hmac_id(int i) { return (hmac_key_id_t)(HMAC_KEY0 + i); }

extern "C" int mw_secure_key_block(void)
{
    return key_block();
}

extern "C" int mw_secure_key_target_block(void)
{
    const int cur = key_block();
    if (cur >= 0) return cur;
    for (int i = MW_KEY_BLOCKS - 1; i >= 0; --i) {
        if (esp_efuse_key_block_unused(key_blk(i))) return i;
    }
    return -1;
}

static const char* purpose_name(esp_efuse_purpose_t p)
{
    switch (p) {
    case ESP_EFUSE_KEY_PURPOSE_USER:                        return "USER";
    case ESP_EFUSE_KEY_PURPOSE_RESERVED:                    return "RESERVED";
    case ESP_EFUSE_KEY_PURPOSE_XTS_AES_256_KEY_1:           return "FLASH ENC 256/1";
    case ESP_EFUSE_KEY_PURPOSE_XTS_AES_256_KEY_2:           return "FLASH ENC 256/2";
    case ESP_EFUSE_KEY_PURPOSE_XTS_AES_128_KEY:             return "FLASH ENC 128";
    case ESP_EFUSE_KEY_PURPOSE_HMAC_DOWN_ALL:               return "HMAC DOWN ALL";
    case ESP_EFUSE_KEY_PURPOSE_HMAC_DOWN_JTAG:              return "HMAC JTAG";
    case ESP_EFUSE_KEY_PURPOSE_HMAC_DOWN_DIGITAL_SIGNATURE: return "HMAC DS";
    case ESP_EFUSE_KEY_PURPOSE_HMAC_UP:                     return "HMAC UP";
    case ESP_EFUSE_KEY_PURPOSE_SECURE_BOOT_DIGEST0:         return "SECURE BOOT 0";
    case ESP_EFUSE_KEY_PURPOSE_SECURE_BOOT_DIGEST1:         return "SECURE BOOT 1";
    case ESP_EFUSE_KEY_PURPOSE_SECURE_BOOT_DIGEST2:         return "SECURE BOOT 2";
    default:                                                return "OTHER";
    }
}

extern "C" mw_err_t mw_secure_key_blocks(mw_key_block_info_t out[MW_SECURE_KEY_BLOCKS])
{
    if (!out) return MW_ERR_INVALID_ARG;
    const int ours = key_block();
    for (int i = 0; i < MW_KEY_BLOCKS; ++i) {
        const esp_efuse_block_t b = key_blk(i);
        out[i].used           = !esp_efuse_key_block_unused(b);
        out[i].read_protected = esp_efuse_get_key_dis_read(b);
        out[i].wallet_key     = (i == ours);
        out[i].purpose        = out[i].used ? purpose_name(esp_efuse_get_key_purpose(b))
                                            : "free";
    }
    return MW_OK;
}

// ---------------------------------------------------------------------------
// Internal blob API shared with wallet_store.c (mirrors secure_storage_host.c)
// ---------------------------------------------------------------------------
extern "C" {
mw_err_t mw_store_blob_write(const char* key, const void* data, size_t len);
mw_err_t mw_store_blob_read(const char* key, void* out, size_t cap, size_t* len_out);
mw_err_t mw_store_blob_erase(const char* key);
}

static mw_err_t nvs_err_to_mw(esp_err_t e)
{
    switch (e) {
        case ESP_OK:                     return MW_OK;
        case ESP_ERR_NVS_NOT_FOUND:      return MW_ERR_IO;
        case ESP_ERR_NVS_INVALID_LENGTH: return MW_ERR_FORMAT;
        case ESP_ERR_NO_MEM:             return MW_ERR_MEMORY;
        default:                         return MW_ERR_IO;
    }
}

extern "C" mw_err_t mw_store_blob_write(const char* key, const void* data, size_t len)
{
    nvs_handle_t h;
    esp_err_t e;
    if (!key || (!data && len)) return MW_ERR_INVALID_ARG;
    e = nvs_open(MW_NVS_NAMESPACE, NVS_READWRITE, &h);
    if (e != ESP_OK) return nvs_err_to_mw(e);
    e = nvs_set_blob(h, key, data, len);
    if (e == ESP_OK) e = nvs_commit(h);
    nvs_close(h);
    return nvs_err_to_mw(e);
}

extern "C" mw_err_t mw_store_blob_read(const char* key, void* out, size_t cap, size_t* len_out)
{
    nvs_handle_t h;
    esp_err_t e;
    size_t len = cap;
    if (!key || !out) return MW_ERR_INVALID_ARG;
    e = nvs_open(MW_NVS_NAMESPACE, NVS_READONLY, &h);
    if (e != ESP_OK) return nvs_err_to_mw(e);
    e = nvs_get_blob(h, key, out, &len);
    nvs_close(h);
    if (e != ESP_OK) return nvs_err_to_mw(e);
    if (len_out) *len_out = len;
    return MW_OK;
}

// 1 when the key exists, 0 when NVS says it does not, -1 on any other error.
extern "C" int mw_store_blob_exists(const char* key)
{
    nvs_handle_t h;
    size_t len = 0;
    if (!key) return -1;
    esp_err_t e = nvs_open(MW_NVS_NAMESPACE, NVS_READONLY, &h);
    if (e == ESP_ERR_NVS_NOT_FOUND) return 0;          // namespace never written
    if (e != ESP_OK) return -1;
    e = nvs_get_blob(h, key, NULL, &len);
    nvs_close(h);
    if (e == ESP_OK) return 1;
    if (e == ESP_ERR_NVS_NOT_FOUND) return 0;
    return -1;
}

extern "C" mw_err_t mw_store_blob_erase(const char* key)
{
    nvs_handle_t h;
    esp_err_t e;
    if (!key) return MW_ERR_INVALID_ARG;
    e = nvs_open(MW_NVS_NAMESPACE, NVS_READWRITE, &h);
    if (e != ESP_OK) return nvs_err_to_mw(e);
    e = nvs_erase_key(h, key);
    if (e == ESP_OK) e = nvs_commit(h);
    nvs_close(h);
    return nvs_err_to_mw(e);
}

// ---------------------------------------------------------------------------
// eFuse key state
// ---------------------------------------------------------------------------

// TZ 8.1: a block with purpose HMAC_UP AND read protection - without the
// protection the "hardware" key is just a constant any firmware can dump.
extern "C" mw_err_t mw_secure_key_status(void)
{
    return (key_block() >= 0) ? MW_OK : MW_ERR_NOT_SUPPORTED;
}

// ###########################################################################
// #                         !!!  IRREVERSIBLE  !!!                          #
// #                                                                         #
// #  This burns an eFuse key block and permanently disables reading it.     #
// #  eFuse bits can only go 0 -> 1: the key can NEVER be changed, read back  #
// #  or erased.  Losing it makes every sealed wallet on this device          #
// #  unrecoverable - the only recovery path is the seed phrase on paper.     #
// #  TZ 8.1: "HMAC key is programmed before first use; updating it means     #
// #  replacing the chip."                                                    #
// #                                                                         #
// #  The UI must reach this call ONLY after a double confirmation screen     #
// #  (see docs/security.md, "eFuse provisioning").  It deliberately takes no  #
// #  arguments so it cannot be invoked accidentally through a generic        #
// #  settings dispatcher.                                                    #
// ###########################################################################
extern "C" mw_err_t mw_secure_key_provision(void)
{
    uint8_t key[32];
    uint8_t extra[32];
    esp_err_t e;

    // Already provisioned correctly -> nothing to do (and nothing CAN be done).
    if (mw_secure_key_status() == MW_OK) return MW_OK;

    // The highest completely unused block; a block burned with another
    // purpose cannot be reclaimed.
    const int blk_i = mw_secure_key_target_block();
    if (blk_i < 0) return MW_ERR_NOT_SUPPORTED;
    const esp_efuse_block_t blk = key_blk(blk_i);
    if (!esp_efuse_key_block_unused(blk)) return MW_ERR_NOT_SUPPORTED;

    // Two independent TRNG reads, XORed: mw_random_bytes() is the health-tested
    // path (TZ 8.2), esp_fill_random() is the raw hardware source.
    mw_random_bytes(key, sizeof key);
    esp_fill_random(extra, sizeof extra);
    for (size_t i = 0; i < sizeof key; i++) key[i] ^= extra[i];
    mw_memzero(extra, sizeof extra);

    if (mw_ct_is_zero(key, sizeof key)) {      // paranoia: never burn an all-zero key
        mw_memzero(key, sizeof key);
        return MW_ERR_MEMORY;
    }

    // esp_efuse_write_key() writes the block, sets the key purpose, write-
    // protects it and - for HMAC_UP - read-protects it.
    e = esp_efuse_write_key(blk, ESP_EFUSE_KEY_PURPOSE_HMAC_UP, key, sizeof key);
    mw_memzero(key, sizeof key);
    if (e != ESP_OK) return MW_ERR_IO;

    // Belt and braces: make read protection explicit even if the IDF version
    // in use does not apply it automatically for this purpose.
    if (!esp_efuse_get_key_dis_read(blk)) {
        if (esp_efuse_set_key_dis_read(blk) != ESP_OK) return MW_ERR_IO;
    }

    kblk_remember(blk_i);
    s_kblk = -2;                                 // look it up again
    return mw_secure_key_status();
}

// ---------------------------------------------------------------------------
// User password key (task2 item 1) - internal RAM only, never PSRAM.
// ---------------------------------------------------------------------------
#ifndef DRAM_ATTR
#  define DRAM_ATTR __attribute__((section(".dram1")))
#endif
static DRAM_ATTR uint8_t g_user_key[32];
static DRAM_ATTR bool    g_user_key_set = false;

extern "C" mw_err_t mw_secure_user_key_set(const uint8_t key[32])
{
    if (!key) return MW_ERR_INVALID_ARG;
    if (mw_ct_is_zero(key, 32)) return MW_ERR_INVALID_ARG;
    memcpy(g_user_key, key, 32);
    g_user_key_set = true;
    return MW_OK;
}

extern "C" void mw_secure_user_key_clear(void)
{
    mw_memzero(g_user_key, sizeof g_user_key);
    g_user_key_set = false;
}

extern "C" bool mw_secure_user_key_present(void)
{
    return g_user_key_set;
}

// HMAC-SHA256(user key, label || data): names of the user's files.
extern "C" mw_err_t mw_secure_user_mac(const char* label, const uint8_t* data, size_t len,
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

extern "C" mw_err_t mw_secure_user_key_copy(uint8_t out[32])
{
    if (!out) return MW_ERR_INVALID_ARG;
    if (!g_user_key_set) return MW_ERR_NOT_SUPPORTED;
    memcpy(out, g_user_key, 32);
    return MW_OK;
}

// ---------------------------------------------------------------------------
// Sealing
// ---------------------------------------------------------------------------

extern "C" mw_err_t mw_secure_hw_hmac(const uint8_t* msg, size_t len, uint8_t out[32],
                                     bool* bound)
{
    if ((!msg && len) || !out) return MW_ERR_INVALID_ARG;
    if (bound) *bound = false;
    const int kb = key_block();
    if (kb < 0) return MW_ERR_NOT_SUPPORTED;           // no eFuse key: no binding
    // esp_hmac_calculate() serialises access to the peripheral itself.
    if (esp_hmac_calculate(hmac_id(kb), (const void*)msg, len, out) != ESP_OK)
        return MW_ERR_IO;
    if (bound) *bound = true;
    return MW_OK;
}

// Per-label AES key: SHA-256 keyed by the unreachable eFuse secret,
// evaluated in the HMAC peripheral, then mixed with the user password key:
//     key = HMAC-SHA256(user_key, hw_key || label)
// so neither the chip alone nor the password alone can open a record.
//
// legacy = true: the hardware part of records from the old bring-up mode,
// keccak256(label) - for OPENING such records only (file header).
static mw_err_t derive_label_key(const char* label, uint8_t out[32], bool legacy)
{
    uint8_t hw[32];
    uint8_t msg[32 + 64];
    size_t  llen;

    if (!label || !*label) return MW_ERR_INVALID_ARG;
    llen = strlen(label);
    if (llen > 64) return MW_ERR_INVALID_ARG;

    if (legacy) {
        mw_keccak256((const uint8_t*)label, llen, hw);
    } else {
        const int kb = key_block();
        if (kb < 0) return MW_ERR_NOT_SUPPORTED;
        esp_err_t e = esp_hmac_calculate(hmac_id(kb), (const void*)label, llen, hw);
        if (e != ESP_OK) return MW_ERR_NOT_SUPPORTED;
    }

    if (!g_user_key_set) {
        mw_memzero(hw, sizeof hw);
        return MW_ERR_NOT_SUPPORTED;        // no password entered this session
    }
    memcpy(msg, hw, 32);
    memcpy(msg + 32, label, llen);
    mw_hmac_sha256(g_user_key, sizeof g_user_key, msg, 32 + llen, out);
    mw_memzero(hw, sizeof hw);
    mw_memzero(msg, sizeof msg);
    return MW_OK;
}

extern "C" mw_err_t mw_seal(const char* label, const uint8_t* pt, size_t pt_len,
                            uint8_t* iv16, uint8_t* tag16, uint8_t* ct, size_t ct_cap)
{
    uint8_t key[32];
    mw_err_t err;
    int rc;

    if (!label || !iv16 || !tag16 || (pt_len && (!pt || !ct)) || ct_cap < pt_len)
        return MW_ERR_INVALID_ARG;

    err = derive_label_key(label, key, false);
    if (err != MW_OK) { mw_memzero(key, sizeof key); return err; }

    mw_random_bytes(iv16, MW_GCM_IV_BYTES);
    rc = mw_aes256_gcm_encrypt(key, iv16, MW_GCM_IV_BYTES, NULL, 0,
                               pt, pt_len, ct, tag16);
    mw_memzero(key, sizeof key);
    return (rc == MW_AES_GCM_OK) ? MW_OK : MW_ERR_INVALID_ARG;
}

static bool g_last_legacy = false;

extern "C" mw_err_t mw_unseal(const char* label, const uint8_t* ct, size_t ct_len,
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
    if (rc == MW_AES_GCM_BAD_TAG) {
        // A record from the old bring-up mode? Opened, never written so.
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

extern "C" bool mw_secure_last_unseal_legacy(void)
{
    return g_last_legacy;
}

// ---------------------------------------------------------------------------
// Settings (TZ 4.2, 5.5)
// ---------------------------------------------------------------------------

// Fallbacks for boards whose board_config.h is not on the include path of this
// translation unit; mw_hal_caps() is the primary source.
#ifndef HAS_TOUCH
#define HAS_TOUCH 0
#endif
#ifndef DISPLAY_WIDTH
#define DISPLAY_WIDTH 0
#endif
#ifndef DISPLAY_HEIGHT
#define DISPLAY_HEIGHT 0
#endif
// TZ 2.2 makes the field mandatory but a board may predate it.
#ifndef DEFAULT_SEED_INPUT_MODE
#define DEFAULT_SEED_INPUT_MODE SEED_INPUT_AUTO
#endif

// TZ 2.2 / 5.5: the board's DEFAULT_SEED_INPUT_MODE wins. AUTO - and only
// AUTO - falls through to the resolution rule below. A board that pins
// SEED_INPUT_SCROLL_KB does so because the full 6x5 grid does not physically
// fit its panel (the round 240x240 glass cuts the corner caps off), and the
// AUTO rule, which only knows the bounding box, cannot see that.
//
// AUTO rule, verbatim:
//   no touch                -> KEYBOARD_SCROLL
//   touch and >= 240x240    -> KEYBOARD_FULL
//   touch and <  240x240    -> KEYBOARD_SCROLL
extern "C" keyboard_type_t mw_settings_default_keyboard(void)
{
#if DEFAULT_SEED_INPUT_MODE == SEED_INPUT_FULL_KB
    return KEYBOARD_FULL;
#elif DEFAULT_SEED_INPUT_MODE == SEED_INPUT_SCROLL_KB
    return KEYBOARD_SCROLL;
#else
    bool     has_touch = (HAS_TOUCH != 0);
    uint16_t w = (uint16_t)DISPLAY_WIDTH;
    uint16_t h = (uint16_t)DISPLAY_HEIGHT;

    const mw_hal_caps_t* caps = mw_hal_caps();
    if (caps) {
        has_touch = caps->has_touch;
        // Rotation swaps the logical axes; the rule is about the usable area.
        w = caps->width;
        h = caps->height;
    }

    if (!has_touch) return KEYBOARD_SCROLL;
    if (w >= 240 && h >= 240) return KEYBOARD_FULL;
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

extern "C" mw_err_t mw_settings_load(mw_settings_t* out)
{
    uint8_t blob[MW_SETTINGS_BLOB_LEN];
    size_t len = 0;
    if (!out) return MW_ERR_INVALID_ARG;
    // Missing / truncated / older blob -> defaults, never garbage (TZ 4.2).
    if (mw_store_blob_read(MW_SETTINGS_BLOB_KEY, blob, sizeof blob, &len) != MW_OK ||
        settings_deserialize(out, blob, len) != MW_OK) {
        settings_defaults(out);
        return MW_OK;
    }
    return MW_OK;
}

extern "C" mw_err_t mw_settings_save(const mw_settings_t* s)
{
    uint8_t blob[MW_SETTINGS_BLOB_LEN];
    if (!s) return MW_ERR_INVALID_ARG;
    if (s->brightness > 100) return MW_ERR_RANGE;
    settings_serialize(s, blob);
    return mw_store_blob_write(MW_SETTINGS_BLOB_KEY, blob, sizeof blob);
}

#endif  /* !MW_HOST_BUILD */