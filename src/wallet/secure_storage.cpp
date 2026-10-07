// ESP32-S3 implementation of secure_storage.h (TZ 8.1, 4.2).
//
// Key hierarchy
//   eFuse BLOCK_KEY0 (32 bytes, purpose HMAC_UP, read-protected)
//        |  esp_hmac_calculate(HMAC_KEY0, label)        <- runs in hardware,
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
// DEBUG FALLBACK
//
// When the eFuse HMAC key is not provisioned, derive_label_key() falls back
// to keccak256(label).  That lets wallets be created during bring-up without
// burning eFuse.  It is INSECURE - the derived "key" is a public function of
// a public label, so anyone with the NVS ciphertext can decrypt it.
//
// Define MW_SECURE_ALLOW_FALLBACK=0 (or comment the branch out) before
// shipping and provision the eFuse as TZ 8.1 requires.
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

// 1 -> allow keccak256(label) when the eFuse key is missing (bring-up only).
// 0 -> refuse; wallets cannot be created until the eFuse is provisioned.
#ifndef MW_SECURE_ALLOW_FALLBACK
#  define MW_SECURE_ALLOW_FALLBACK 1
#endif

#define MW_NVS_NAMESPACE      "mwallet"
#define MW_SETTINGS_BLOB_KEY  "settings"
// v2 (task2): usb_mode is gone, kb_layout and debug_log were added.
#define MW_SETTINGS_VERSION   2
#define MW_SETTINGS_BLOB_LEN  40

// Which eFuse block and which HMAC key id the project uses (TZ 8.1 fixes both
// at 0; MW_HMAC_EFUSE_KEY_ID lives in app_config.h).
#define MW_EFUSE_BLOCK  ((esp_efuse_block_t)(EFUSE_BLK_KEY0 + MW_HMAC_EFUSE_KEY_ID))
#define MW_HMAC_KEY_ID  ((hmac_key_id_t)(HMAC_KEY0 + MW_HMAC_EFUSE_KEY_ID))

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

extern "C" mw_err_t mw_secure_key_status(void)
{
    const esp_efuse_block_t blk = MW_EFUSE_BLOCK;

    if (esp_efuse_key_block_unused(blk)) return MW_ERR_NOT_SUPPORTED;   // not burned

    esp_efuse_purpose_t purpose = esp_efuse_get_key_purpose(blk);
    if (purpose != ESP_EFUSE_KEY_PURPOSE_HMAC_UP) return MW_ERR_NOT_SUPPORTED;

    // TZ 8.1 also demands read protection - without it the "hardware" key is
    // just a constant that any firmware can dump.
    if (!esp_efuse_get_key_dis_read(blk)) return MW_ERR_NOT_SUPPORTED;

    return MW_OK;
}

// ###########################################################################
// #                         !!!  IRREVERSIBLE  !!!                          #
// #                                                                         #
// #  This burns eFuse BLOCK_KEY0 and then permanently disables reading it.   #
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

    // The block must be completely unused; a block burned with a different
    // purpose cannot be reclaimed.
    if (!esp_efuse_key_block_unused(MW_EFUSE_BLOCK)) return MW_ERR_NOT_SUPPORTED;

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
    e = esp_efuse_write_key(MW_EFUSE_BLOCK, ESP_EFUSE_KEY_PURPOSE_HMAC_UP,
                            key, sizeof key);
    mw_memzero(key, sizeof key);
    if (e != ESP_OK) return MW_ERR_IO;

    // Belt and braces: make read protection explicit even if the IDF version
    // in use does not apply it automatically for this purpose.
    if (!esp_efuse_get_key_dis_read(MW_EFUSE_BLOCK)) {
        if (esp_efuse_set_key_dis_read(MW_EFUSE_BLOCK) != ESP_OK) return MW_ERR_IO;
    }

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

// ---------------------------------------------------------------------------
// Sealing
// ---------------------------------------------------------------------------

extern "C" mw_err_t mw_secure_hw_hmac(const uint8_t* msg, size_t len, uint8_t out[32],
                                     bool* bound)
{
    if ((!msg && len) || !out) return MW_ERR_INVALID_ARG;
    if (bound) *bound = false;
    if (mw_secure_key_status() == MW_OK) {
        // esp_hmac_calculate() serialises access to the peripheral itself.
        if (esp_hmac_calculate(MW_HMAC_KEY_ID, (const void*)msg, len, out) != ESP_OK)
            return MW_ERR_IO;
        if (bound) *bound = true;
        return MW_OK;
    }
#if MW_SECURE_ALLOW_FALLBACK
    static const char k_fallback[] = "mw.hw.hmac.fallback (eFuse not provisioned)";
    mw_hmac_sha256((const uint8_t*)k_fallback, sizeof k_fallback - 1, msg, len, out);
    return MW_OK;
#else
    return MW_ERR_NOT_SUPPORTED;
#endif
}

// Per-label AES key.
//
// When the eFuse HMAC key is provisioned this is the real thing: SHA-256
// keyed by an unreachable eFuse secret, evaluated in the HMAC peripheral.
//
// When it is not, and MW_SECURE_ALLOW_FALLBACK is 1, the "key" is just
// keccak256(label).  That is only there so a wallet can be created before
// the eFuse is burned; see the file header.
//
// Either way the result is then mixed with the user password key:
//     key = HMAC-SHA256(user_key, hw_key || label)
// so neither the chip alone nor the password alone can open a record.
static mw_err_t derive_label_key(const char* label, uint8_t out[32])
{
    uint8_t hw[32];
    uint8_t msg[32 + 64];
    size_t  llen;

    if (!label || !*label) return MW_ERR_INVALID_ARG;
    llen = strlen(label);
    if (llen > 64) return MW_ERR_INVALID_ARG;

    if (mw_secure_key_status() == MW_OK) {
        esp_err_t e = esp_hmac_calculate(MW_HMAC_KEY_ID,
                                         (const void*)label, llen, hw);
        if (e != ESP_OK) return MW_ERR_NOT_SUPPORTED;
    } else {
#if MW_SECURE_ALLOW_FALLBACK
        // Insecure bring-up path.  A constant output for a constant label means
        // the sealed blob is only as protected as the user password.
        mw_keccak256((const uint8_t*)label, llen, hw);
#else
        return MW_ERR_NOT_SUPPORTED;
#endif
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

    err = derive_label_key(label, key);
    if (err != MW_OK) { mw_memzero(key, sizeof key); return err; }

    mw_random_bytes(iv16, MW_GCM_IV_BYTES);
    rc = mw_aes256_gcm_encrypt(key, iv16, MW_GCM_IV_BYTES, NULL, 0,
                               pt, pt_len, ct, tag16);
    mw_memzero(key, sizeof key);
    return (rc == MW_AES_GCM_OK) ? MW_OK : MW_ERR_INVALID_ARG;
}

extern "C" mw_err_t mw_unseal(const char* label, const uint8_t* ct, size_t ct_len,
                              const uint8_t* iv16, const uint8_t* tag16,
                              uint8_t* pt, size_t pt_cap)
{
    uint8_t key[32];
    mw_err_t err;
    int rc;

    if (!label || !iv16 || !tag16 || (ct_len && (!ct || !pt)) || pt_cap < ct_len)
        return MW_ERR_INVALID_ARG;

    err = derive_label_key(label, key);
    if (err != MW_OK) { mw_memzero(key, sizeof key); return err; }

    rc = mw_aes256_gcm_decrypt(key, iv16, MW_GCM_IV_BYTES, NULL, 0,
                               ct, ct_len, tag16, pt);
    mw_memzero(key, sizeof key);
    if (rc == MW_AES_GCM_BAD_TAG) return MW_ERR_DECRYPT;
    return (rc == MW_AES_GCM_OK) ? MW_OK : MW_ERR_INVALID_ARG;
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