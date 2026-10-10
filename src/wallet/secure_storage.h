// eFuse HMAC key + user password key + encrypted NVS + device settings
// (TZ 8.1, 4.2; task2 item 1).
#ifndef MW_SECURE_STORAGE_H
#define MW_SECURE_STORAGE_H

#include "../monero/monero_types.h"

#ifdef __cplusplus
extern "C" {
#endif

typedef enum { KEYBOARD_FULL = 0, KEYBOARD_SCROLL = 1 } keyboard_type_t;

// task2 item 4: letter order of the touch keyboard.
typedef enum { KB_LAYOUT_QWERTY = 0, KB_LAYOUT_ABC = 1 } kb_layout_t;

typedef struct {
    keyboard_type_t keyboard;
    kb_layout_t     kb_layout;
    uint8_t         brightness;        // 0..100
    uint16_t        autolock_min;
    int32_t         touch_calib[6];
    bool            touch_calibrated;
    mw_network_t    network;
    // task2 item 3: when false only progress/error lines reach the host
    // console; the full debug stream needs this on.
    bool            debug_log;
    // Geometry tag of touch_calib (blob bytes 37..39, zero = untagged);
    // written and checked by src/hal/touch_map.h, opaque to storage.
    uint8_t         touch_cal_tag[3];
    uint8_t         version;
} mw_settings_t;

mw_err_t mw_settings_load(mw_settings_t* out);
mw_err_t mw_settings_save(const mw_settings_t* s);
// TZ 5.5 AUTO rule, applied once on first boot.
keyboard_type_t mw_settings_default_keyboard(void);

// ---------------- eFuse-backed sealing -------------------------------------
// Returns MW_OK if the HMAC key is present and read-protected.
mw_err_t mw_secure_key_status(void);
// One-shot provisioning: burns a TRNG key into the highest free key block
// (BLOCK_KEY5 down) with purpose HMAC_UP and read-protects it.
// IRREVERSIBLE (TZ 8.1). MW_ERR_NOT_SUPPORTED when no key block is free.
mw_err_t mw_secure_key_provision(void);
// Key block (0..5) holding the wallet key, or -1.
int      mw_secure_key_block(void);
// Block mw_secure_key_provision() would burn (the one in use when there is
// one), or -1 when every key block is taken.
int      mw_secure_key_target_block(void);

#define MW_SECURE_KEY_BLOCKS 6
typedef struct {
    bool        used;            // some bit of the block is burned
    bool        read_protected;
    bool        wallet_key;      // the block this firmware uses
    const char* purpose;         // "free", "HMAC UP", "FLASH ENC 128", ...
} mw_key_block_info_t;
// State of BLOCK_KEY0..5, for the read-only Settings page.
mw_err_t mw_secure_key_blocks(mw_key_block_info_t out[MW_SECURE_KEY_BLOCKS]);

// Raw HMAC of `msg` under the eFuse key (device) / the emulated root key
// (host), for binding the device-password derivation to the chip
// (device_auth.c): an offline guess then needs the chip for every attempt.
//   *bound = true   the result really comes from the eFuse key
//   *bound = false  the key is not provisioned and the build allows the
//                   bring-up fallback: HMAC-SHA256 under a PUBLIC constant,
//                   i.e. no binding at all (security.md §4)
// MW_ERR_NOT_SUPPORTED when neither is available.
mw_err_t mw_secure_hw_hmac(const uint8_t* msg, size_t len, uint8_t out[32], bool* bound);
// (Device firmware: without the eFuse key it is MW_ERR_NOT_SUPPORTED; the
// public-constant fallback above exists only in the host emulation.)

// ---------------- user password key (task2 item 1) --------------------------
// Every sealed blob is encrypted under a key that mixes the eFuse HMAC output
// with a key derived from the device password (device_auth.h). Without the
// user key mw_seal()/mw_unseal() refuse with MW_ERR_NOT_SUPPORTED: a stolen
// device with a re-flashed firmware cannot decrypt anything without the
// password, even though the eFuse key is still in the chip.
//
// The key lives in internal RAM for the whole power-on session and is set by
// mw_device_auth_verify() / mw_device_auth_set().
mw_err_t mw_secure_user_key_set(const uint8_t key[32]);
void     mw_secure_user_key_clear(void);
bool     mw_secure_user_key_present(void);
// HMAC-SHA256(user key, label || data), len(label) + len <= 96. Names the
// files of the user that is logged in (multi-user: they are unlinkable
// without the key). MW_ERR_NOT_SUPPORTED without a user key.
mw_err_t mw_secure_user_mac(const char* label, const uint8_t* data, size_t len,
                            uint8_t out[32]);
// A copy of the installed user key (to restore it after a temporary switch).
mw_err_t mw_secure_user_key_copy(uint8_t out[32]);

// AES-256-GCM using a key derived from the eFuse HMAC over `label`, mixed
// with the user key.
mw_err_t mw_seal(const char* label, const uint8_t* pt, size_t pt_len,
                 uint8_t* iv16, uint8_t* tag16, uint8_t* ct, size_t ct_cap);
mw_err_t mw_unseal(const char* label, const uint8_t* ct, size_t ct_len,
                   const uint8_t* iv16, const uint8_t* tag16,
                   uint8_t* pt, size_t pt_cap);
// True when the last mw_unseal() succeeded only with the hardware part of
// the old bring-up mode (keccak256(label) instead of the eFuse HMAC): such a
// record still opens and is re-sealed under the eFuse key by the next re-key.
bool     mw_secure_last_unseal_legacy(void);
#ifdef MW_HOST_BUILD
// Host tests only: seals the way the old bring-up mode did.
mw_err_t mw_host_seal_legacy(const char* label, const uint8_t* pt, size_t pt_len,
                             uint8_t* iv16, uint8_t* tag16, uint8_t* ct, size_t ct_cap);
#endif

#ifdef __cplusplus
}
#endif
#endif
