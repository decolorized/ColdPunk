// ---------------------------------------------------------------------------
//  The device shell (task 3). Everything in this file runs on the CRYPTO task,
//  pinned to core 1 (TZ 4.1): it owns the seeds, the passphrases and the
//  derived keys and never touches an LVGL object. It reaches the UI only
//  through the blocking helpers of screen_common.h / ui.h.
//
//  The crypto task simply runs mw_shell_run():
//
//      ┌────────────┐ triple tap on  ┌──────────┐ ok  ┌───────────────┐
//      │ Minesweeper│ the exploded ─►│ password │ ──► │ main menu     │
//      └────────────┘ mine           └──────────┘     │  Wallets      │
//            ▲            cancel / lock / autolock    │  Settings     │
//            └────────────────────────────────────────┤  Lock         │
//                                                     └──────┬────────┘
//                  wallet list ─► passphrase (if the wallet has one)
//                              ─► wallet menu: address / view key (text,
//                                 QR), rename, delete, close; files and
//                                 requests from the PC are handled here.
//
//  While a wallet menu is open the USB link accepts outputs and unsigned
//  transaction files (and address / view-only requests); the link wakes the
//  menu and the file is processed with an on-device confirmation.
//
//  Security rules (task 3 "Ключевые моменты"):
//    * the private view key leaves the device only after a typed-number
//      confirmation on the device;
//    * the private spend key, the seed and the passphrase never leave it;
//    * key image generation and every transaction are confirmed on screen;
//    * the change address is re-derived from the wallet's own keys
//      (wallet_ops.c / tx.c) - a substituted change address is refused.
//
//  Buffer policy: files and signing state are far too large for a task
//  stack; they come from PSRAM, are wiped with mw_memzero() and freed on
//  every exit path.
// ---------------------------------------------------------------------------
#include "screen_common.h"
#include "keyboard.h"

#include "../config/app_config.h"
#include "../crypto/ed25519.h"
#include "../crypto/memzero.h"
#include "../crypto/random.h"
#include "../crypto/hash.h"
#include "../hal/hal.h"
#include "../hal/log.h"
#include "../monero/address.h"
#include "../monero/file_formats.h"
#include "../monero/key_image.h"
#include "../monero/mnemonic.h"
#include "../monero/sign.h"
#include "../monero/tx.h"
#include "../transfer/transfer.h"
#include "../transfer/link.h"
#include "../transfer/sd_files.h"
#include "../hal/display_drivers.h"
#include "../wallet/device_auth.h"
#include "../wallet/file_store.h"
#include "../wallet/ki_cache.h"
#include "../wallet/session.h"
#include "../wallet/wallet_ops.h"
#include "../wallet/wallet_store.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

#if defined(__has_include)
#  if __has_include(<esp_heap_caps.h>)
#    define MW_FLOWS_ESP_HEAP 1
#  endif
#endif
#ifndef MW_FLOWS_ESP_HEAP
#  define MW_FLOWS_ESP_HEAP 0
#endif
#if MW_FLOWS_ESP_HEAP
#  include <esp_heap_caps.h>
#endif

#define MW_FLOW_WORD_CAP   24
// A received file plus room for the sealed answer around it.
#define MW_FLOW_FILE_CAP   (MW_TRANSFER_MAX_FILE + 512u)

// ---------------------------------------------------------------------------
// Large allocations
// ---------------------------------------------------------------------------
static void* big_alloc(size_t n) {
#if MW_FLOWS_ESP_HEAP
    void* p = heap_caps_malloc(n, MALLOC_CAP_SPIRAM | MALLOC_CAP_8BIT);
    if (p) return p;
#endif
    return malloc(n);
}

static void big_free(void* p, size_t n) {
    if (!p) return;
    mw_memzero(p, n);
    free(p);
}

// ---------------------------------------------------------------------------
// Small shared helpers
// ---------------------------------------------------------------------------
static void ui_err(mw_err_t e) {
    mw_ui_progress_close();
    MW_LOGE("flow", "operation failed: %s", mw_err_str(e));
    mw_ui_message(T(STR_ERR_GENERIC), mw_err_str(e));
}

// A refusal with an explanation: shown on the device and sent to the PC log
// in full (task 3 step 4: "подробная ошибка + отладочные сообщения").
static void show_refusal(const char* headline, const mw_ops_error_t* er) {
    mw_ui_progress_close();
    MW_LOGE("file", "%s: %s", headline, er->text[0] ? er->text : mw_err_str(er->err));
    char body[256];
    snprintf(body, sizeof(body), "%s\n\n%s", headline,
             er->text[0] ? er->text : mw_err_str(er->err));
    mw_ui_message(TX(XSTR_FILE_ERROR), body);
}

static void hex32(const uint8_t* in, char out[65]) {
    static const char digits[] = "0123456789abcdef";
    for (int i = 0; i < 32; i++) {
        out[2 * i]     = digits[in[i] >> 4];
        out[2 * i + 1] = digits[in[i] & 0x0F];
    }
    out[64] = '\0';
}

static mw_network_t active_network(void) {
    return mw_ui_settings()->network;
}

static mw_err_t ask_text(const char* title, char* out, size_t cap) {
    mw_kb_ctx_t kc;
    memset(&kc, 0, sizeof(kc));
    kc.mode       = MW_KB_MODE_FREE_TEXT;
    kc.type       = mw_ui_settings()->keyboard;
    kc.title      = title;
    kc.allow_back = false;
    return mw_kb_run(&kc, out, cap);
}

static bool lock_requested(void) { return mw_ui_lock_requested(); }

// The device has no clock. A polyseed carries its birthday, which sets where
// a restore starts scanning: ask for the current year and month once
// ("2026-10" or "2026 10"); an empty answer keeps the epoch (scan from 2021).
// Returns the unix time of the first day of that month, 0 when unknown.
static uint64_t ask_birth_month(void) {
    char in[16];
    for (;;) {
        memset(in, 0, sizeof(in));
        if (ask_text(TX(XSTR_BIRTH_MONTH), in, sizeof(in)) != MW_OK || !in[0]) return 0;
        unsigned y = 0, m = 0;
        if (sscanf(in, "%u%*[-./ ]%u", &y, &m) == 2 && y >= 2021 && y <= 2200 &&
            m >= 1 && m <= 12) {
            // days_from_civil (H. Hinnant), month start.
            const int yy = (int)y - (m <= 2 ? 1 : 0);
            const int era = yy / 400;
            const unsigned yoe = (unsigned)(yy - era * 400);
            const unsigned mp = (m + 9) % 12;
            const unsigned doy = (153 * mp + 2) / 5;
            const unsigned doe = yoe * 365 + yoe / 4 - yoe / 100 + doy;
            const long days = (long)era * 146097 + (long)doe - 719468;
            return (uint64_t)days * 86400ull;
        }
        mw_ui_message(T(STR_ERR_GENERIC), TX(XSTR_BIRTH_MONTH_BAD));
    }
}

// ===========================================================================
//  TZ 5.2 passphrase at wallet creation - the double-entry screen
// ===========================================================================
mw_err_t mw_flow_passphrase(char* out, size_t out_cap) {
    return mw_screen_passphrase_run(out, out_cap);
}

// ===========================================================================
//  Seed helpers
// ===========================================================================
static const mw_wordlist_t* wl_for(mw_seed_type_t t) {
    return mw_wordlist(t == MW_SEED_POLYSEED ? MW_WL_POLYSEED_EN : MW_WL_MONERO_EN);
}

static mw_kb_mode_t kb_mode_for(mw_seed_type_t t) {
    return (t == MW_SEED_POLYSEED) ? MW_KB_MODE_SEED_POLYSEED : MW_KB_MODE_SEED_LEGACY;
}

static bool address_string(const mw_account_keys_t* keys, char* str, size_t cap) {
    mw_address_t addr;
    if (mw_address_from_keys(keys, active_network(), &addr) != MW_OK) return false;
    return mw_address_encode(&addr, str, cap) == MW_OK;
}

// task 3: the address as text, and separately as a single static QR code.
static void show_address_text(const mw_account_keys_t* keys) {
    char str[MW_ADDRESS_STR_MAX];
    if (address_string(keys, str, sizeof(str))) mw_ui_text_view(TX(XSTR_ADDRESS), str);
}

static void show_address_qr(const mw_account_keys_t* keys) {
    char str[MW_ADDRESS_STR_MAX];
    if (address_string(keys, str, sizeof(str))) mw_screen_qr_static_run(TX(XSTR_ADDRESS), str);
}

// The private view key: explicit request, warning first, own screen.
static void show_view_key(const mw_account_keys_t* keys, bool qr) {
    if (keys->view_only && mw_sc_is_zero(&keys->sec.view)) return;
    if (!mw_ui_confirm(TX(XSTR_VIEWKEY_TITLE), TX(XSTR_VIEWKEY_WARN),
                       TX(XSTR_YES), TX(XSTR_NO))) {
        return;
    }
    char hex[65];
    hex32(keys->sec.view.b, hex);
    MW_LOGI("wallet", "private view key shown on the screen (%s)", qr ? "QR" : "text");
    if (qr) mw_screen_qr_static_run(TX(XSTR_VIEWKEY_TITLE), hex);
    else    mw_ui_text_view(TX(XSTR_VIEWKEY_TITLE), hex);
    mw_memzero(hex, sizeof(hex));
}

// ===========================================================================
//  Device password (task2 item 1; task 3 item 2: required on first start)
// ===========================================================================
static void auth_report(mw_err_t e) {
    char msg[64];
    if (e == MW_ERR_DECRYPT) {
        snprintf(msg, sizeof(msg), TX(XSTR_PW_WRONG), (int)mw_device_auth_failed_attempts());
        mw_ui_message(T(STR_ERR_GENERIC), msg);
    } else if (e == MW_ERR_ABORTED) {
        const uint32_t ms = mw_device_auth_lockout_ms();
        snprintf(msg, sizeof(msg), TX(XSTR_PW_LOCKED), (int)((ms + 999u) / 1000u));
        mw_ui_message_timeout(T(STR_ERR_GENERIC), msg, ms ? ms : 1000u);
    } else {
        ui_err(e);
    }
}

// Live progress of the password check / upgrade / re-key (several seconds on
// the device). Runs on the crypto task; mw_ui_progress() posts to the UI
// task. Redrawn at most once per percent.
static void auth_progress_cb(int stage, int permille, void* ctx) {
    static int s_last_stage = -1, s_last_pct = -1;
    const int pct = permille / 10;
    if (stage == s_last_stage && pct == s_last_pct) return;
    s_last_stage = stage;
    s_last_pct   = pct;
    const char* what;
    switch (stage) {
    case MW_AUTH_STAGE_UPGRADE: what = TX(XSTR_PW_STAGE_UPGRADE); break;
    case MW_AUTH_STAGE_NEW:     what = TX(XSTR_PW_STAGE_NEW);     break;
    case MW_AUTH_STAGE_REKEY:   what = TX(XSTR_PW_STAGE_REKEY);   break;
    case MW_AUTH_STAGE_CHECK:
    default:                    what = TX(XSTR_PW_STAGE_CHECK);   break;
    }
    mw_ui_progress((const char*)ctx, permille, what);
}

void mw_flow_auth_progress_on(const char* title) {
    mw_device_auth_set_progress(auth_progress_cb, (void*)title);
}

void mw_flow_auth_progress_off(void) {
    mw_device_auth_set_progress(NULL, NULL);
}

// Returns true once the user key is installed; false when the user backed
// out (the shell returns to the game).
static bool device_auth(void) {
    char pw[MW_DEVICE_PW_MAX + 1];
    char again[MW_DEVICE_PW_MAX + 1];
    bool ok = false;
    memset(pw, 0, sizeof(pw));
    memset(again, 0, sizeof(again));

    if (mw_device_auth_state() == MW_AUTH_CORRUPT) {
        // The record is damaged or lost while wallets exist: a new password
        // would derive a different key and orphan them. The only way out is
        // a factory reset (and the seeds on paper), offered right here
        // because Settings are behind the password.
        MW_LOGE("auth", "password record damaged: offering a factory reset");
        mw_ui_message(T(STR_ERR_GENERIC), TX(XSTR_PW_CORRUPT));
        if (mw_ui_confirm_code(T(STR_SETTINGS_RESET), T(STR_RESET_CONFIRM))) {
            MW_LOGE("auth", "factory reset after a damaged password record");
            (void)mw_device_auth_erase();
            (void)mw_fstore_wipe_all();
            mw_factory_reset();                 // never returns
        }
        return false;
    }

    if (!mw_device_auth_is_set()) {
        // First start: a password has to be created before anything else.
        MW_LOGI("auth", "no device password yet: asking the user to set one");
        mw_ui_message(TX(XSTR_PW_TITLE), TX(XSTR_PW_SET_HINT));
        for (;;) {
            if (ask_text(TX(XSTR_PW_ENTER), pw, sizeof(pw)) != MW_OK) break;
            if (strlen(pw) < MW_DEVICE_PW_MIN) {
                mw_ui_message(T(STR_ERR_GENERIC), TX(XSTR_PW_RULES));
                continue;
            }
            if (ask_text(TX(XSTR_PW_REPEAT), again, sizeof(again)) != MW_OK) break;
            if (strcmp(pw, again) != 0) {
                mw_ui_message(T(STR_ERR_GENERIC), TX(XSTR_PW_MISMATCH));
                continue;
            }
            mw_ui_progress(TX(XSTR_PW_TITLE), 0, TX(XSTR_PW_STAGE_NEW));
            mw_flow_auth_progress_on(TX(XSTR_PW_TITLE));
            const mw_err_t e = mw_device_auth_set(pw);
            mw_flow_auth_progress_off();
            mw_ui_progress_close();
            if (e == MW_OK) { ok = true; break; }
            ui_err(e);
        }
    } else {
        MW_LOGI("auth", "waiting for the device password");
        for (;;) {
            if (mw_device_auth_lockout_ms()) { auth_report(MW_ERR_ABORTED); continue; }
            if (ask_text(TX(XSTR_PW_ENTER), pw, sizeof(pw)) != MW_OK) break;
            const uint8_t fails_before = mw_device_auth_failed_attempts();
            mw_ui_progress(TX(XSTR_PW_TITLE), 0, TX(XSTR_PW_STAGE_CHECK));
            mw_flow_auth_progress_on(TX(XSTR_PW_TITLE));
            const mw_err_t e = mw_device_auth_verify(pw);
            mw_flow_auth_progress_off();
            mw_ui_progress_close();
            mw_memzero(pw, sizeof(pw));
            if (e == MW_OK) {
                ok = true;
                if (mw_device_auth_save_pending())
                    MW_LOGE("auth", "failed-attempt counter not cleared in storage, will retry");
                if (fails_before > 0) {
                    char note[80];
                    snprintf(note, sizeof(note), TX(XSTR_PW_FAILED_SINCE), (int)fails_before);
                    mw_ui_message(TX(XSTR_PW_TITLE), note);
                }
                break;
            }
            if (e == MW_ERR_INVALID_ARG) {            // empty input: not an attempt
                mw_ui_message(T(STR_ERR_GENERIC), TX(XSTR_PW_EMPTY));
                continue;
            }
            if (e == MW_ERR_DECRYPT)
                MW_LOGE("auth", "wrong device password (%u failed attempts)",
                        (unsigned)mw_device_auth_failed_attempts());
            auth_report(e);
        }
    }

    mw_memzero(pw, sizeof(pw));
    mw_memzero(again, sizeof(again));
    mw_session_wipe_input();
    MW_LOGI("auth", ok ? "device unlocked" : "password entry left");
    return ok;
}

// ===========================================================================
//  eFuse-backed sealing (TZ 8.1)
// ===========================================================================
static bool ensure_secure_key(void) {
    if (mw_secure_key_status() == MW_OK) return true;
    if (!mw_ui_confirm(TX(XSTR_EFUSE_PROVISION), TX(XSTR_EFUSE_NEEDED),
                       TX(XSTR_YES), TX(XSTR_NO))) {
        return false;
    }
    return mw_screen_efuse_provision_run();
}

// Stores a seed wallet, recording its passphrase variant (task 3 item 5):
// with a passphrase the record opens two wallets - "" gives the plain one.
static mw_err_t store_seed_wallet(const char* name, mw_seed_type_t type,
                                  const uint8_t* material, size_t material_len,
                                  uint32_t restore_height, const char* pass,
                                  uint32_t* id, mw_account_keys_t* shown) {
    mw_account_keys_t pp;
    mw_err_t e;
    memset(&pp, 0, sizeof(pp));
    const bool with_pp = pass && pass[0];
    mw_ui_progress(TX(XSTR_WALLET_UNLOCK), 0, NULL);
    e = mw_seed_to_keys(type, material, material_len, with_pp ? pass : "", &pp);
    if (e == MW_OK) {
        e = mw_wallet_create_pp(name, type, material, material_len, restore_height,
                                with_pp ? &pp : NULL, id);
    }
    mw_ui_progress_close();
    if (e == MW_OK && shown) *shown = pp;
    mw_memzero(&pp, sizeof(pp));
    return e;
}

// ===========================================================================
//  Create wallet (TZ 4.2, 6.5)
// ===========================================================================
static mw_err_t flow_create_wallet(void) {
    char           name[WALLET_NAME_LEN];
    char           pass[MW_PASSPHRASE_MAX];
    uint8_t        entropy[32];
    uint8_t        material[MW_POLYSEED_BLOB_MAX];
    size_t         material_len = 0;
    uint16_t       indices[MW_MAX_SEED_WORDS];
    const char*    words[MW_MAX_SEED_WORDS];
    mw_polyseed_t  ps;
    mw_account_keys_t keys;
    uint32_t       restore_height = 0;
    uint32_t       id = 0;
    mw_err_t       e;

    memset(name, 0, sizeof(name));
    memset(pass, 0, sizeof(pass));
    memset(entropy, 0, sizeof(entropy));
    memset(material, 0, sizeof(material));
    memset(&ps, 0, sizeof(ps));
    memset(&keys, 0, sizeof(keys));

    if (!ensure_secure_key()) return MW_ERR_ABORTED;

    if (ask_text(TX(XSTR_WALLET_NAME), name, sizeof(name)) != MW_OK) return MW_ERR_ABORTED;
    if (name[0] == '\0') snprintf(name, sizeof(name), "%s", TX(XSTR_CREATE_TITLE));

    const char* fmt_items[] = { T(STR_SEED_LEGACY25), T(STR_SEED_POLYSEED16) };
    const int   fmt = mw_ui_choose(T(STR_SEED_TYPE), fmt_items, 2, 0);
    if (fmt < 0) return MW_ERR_ABORTED;
    const mw_seed_type_t type = (fmt == 1) ? MW_SEED_POLYSEED : MW_SEED_MONERO_LEGACY;
    const int n_words = (type == MW_SEED_POLYSEED) ? MW_POLYSEED_WORDS : MW_LEGACY_SEED_WORDS;
    const mw_wordlist_t* wl = wl_for(type);

    const char* ent_items[] = { T(STR_ENTROPY_TRNG), T(STR_ENTROPY_DICE) };
    const int   src = mw_ui_choose(TX(XSTR_ENTROPY_SOURCE), ent_items, 2, 0);
    if (src < 0) return MW_ERR_ABORTED;

    if (src == 0) {
        if (mw_random_selftest() != MW_RNG_OK) {
            mw_ui_message(T(STR_ERR_GENERIC), T(STR_ERR_GENERIC));
            return MW_ERR_IO;
        }
        mw_random_bytes(entropy, sizeof(entropy));
    } else {
        uint8_t rolls[MW_DICE_MAX_ROLLS];
        int     rolled = 0;
        memset(rolls, 0, sizeof(rolls));
        if (!mw_screen_dice_run(rolls, (int)sizeof(rolls), &rolled)) {
            mw_memzero(rolls, sizeof(rolls));
            return MW_ERR_ABORTED;
        }
        const mw_err_t de = mw_dice_to_entropy(rolls, (size_t)rolled, entropy);
        mw_memzero(rolls, sizeof(rolls));
        if (de != MW_OK) { ui_err(de); e = de; goto fail; }

        // The rolls are combined with the hardware TRNG, not used alone:
        //     entropy = HMAC-SHA512(key = TRNG(32), dice_entropy)[0..32)
        // The seed is at least as strong as the better of the two sources -
        // biased dice cannot weaken it and a broken TRNG is covered by the
        // dice. (Consequence: the seed cannot be recomputed from the rolls.)
        if (mw_random_selftest() != MW_RNG_OK) {
            mw_ui_message(T(STR_ERR_GENERIC), T(STR_ERR_GENERIC));
            e = MW_ERR_IO;
            goto fail;
        }
        {
            uint8_t trng[32], mixed[64];
            mw_random_bytes(trng, sizeof(trng));
            mw_hmac_sha512(trng, sizeof(trng), entropy, sizeof(entropy), mixed);
            memcpy(entropy, mixed, sizeof(entropy));
            mw_memzero(trng, sizeof(trng));
            mw_memzero(mixed, sizeof(mixed));
        }
        MW_LOGP("dice rolls mixed with the hardware TRNG");
        mw_ui_message(TX(XSTR_ENTROPY_SOURCE), TX(XSTR_DICE_MIXED));
    }

    if (type == MW_SEED_MONERO_LEGACY) {
        // Canonical phrase (audit round 2, item 3): Monero encodes the spend
        // key already reduced mod l. Raw 256-bit entropy exceeds l in ~15 of
        // 16 cases, and Feather / monero-cli would then show a different
        // phrase for the same address after a restore.
        mw_scalar_t sk;
        memcpy(sk.b, entropy, 32);
        mw_sc_reduce32(&sk);
        memcpy(material, sk.b, 32);
        mw_memzero(&sk, sizeof(sk));
        material_len = 32;
        e = mw_legacy_seed_encode(material, wl, indices);
    } else {
        e = mw_polyseed_create(entropy, sizeof(entropy), ask_birth_month(), 0, &ps);
        if (e == MW_OK) e = mw_polyseed_encode(&ps, wl, indices);
        if (e == MW_OK) e = mw_polyseed_pack(&ps, material, sizeof(material), &material_len);
        if (e == MW_OK) restore_height = mw_polyseed_restore_height(&ps, active_network());
    }
    mw_memzero(entropy, sizeof(entropy));
    if (e != MW_OK) { ui_err(e); goto fail; }

    for (int i = 0; i < n_words; i++) words[i] = mw_wordlist_word(wl, indices[i]);

    if (!mw_screen_seed_display_run(words, n_words)) { e = MW_ERR_ABORTED; goto fail; }
    mw_ui_message(T(STR_VERIFY_SEED), TX(XSTR_SEED_WRITTEN_Q));
    if (!mw_screen_seed_verify_run(words, n_words, kb_mode_for(type))) {
        e = MW_ERR_ABORTED;
        goto fail;
    }

    // TZ 5.2: the passphrase, after the seed was verified.
    e = mw_flow_passphrase(pass, sizeof(pass));
    if (e != MW_OK) goto fail;

    e = store_seed_wallet(name, type, material, material_len, restore_height, pass,
                          &id, &keys);
    if (e != MW_OK) { ui_err(e); goto fail; }
    mw_wallet_set_active(id);
    MW_LOGI("wallet", "wallet created (%s, %s)",
            type == MW_SEED_POLYSEED ? "polyseed" : "legacy 25 words",
            pass[0] ? "with passphrase" : "no passphrase");

    // The address of the wallet the user will use, to compare with Feather.
    show_address_text(&keys);
    mw_ui_message(T(STR_SUCCESS), TX(XSTR_WALLET_CREATED));
    e = MW_OK;

fail:
    mw_memzero(&keys, sizeof(keys));
    mw_memzero(&ps, sizeof(ps));
    mw_memzero(material, sizeof(material));
    mw_memzero(entropy, sizeof(entropy));
    mw_memzero(indices, sizeof(indices));
    mw_memzero(pass, sizeof(pass));
    mw_memzero(name, sizeof(name));
    mw_session_wipe_input();
    return e;
}

// ===========================================================================
//  Raw key import (TZ 4.2) - no seed, therefore no passphrase variant
// ===========================================================================
static int hex_digit(char c) {
    if (c >= '0' && c <= '9') return c - '0';
    if (c >= 'a' && c <= 'f') return c - 'a' + 10;
    if (c >= 'A' && c <= 'F') return c - 'A' + 10;
    return -1;
}

static bool parse_hex32(const char* in, uint8_t out[32]) {
    if (!in || strlen(in) != 64) return false;
    for (int i = 0; i < 32; i++) {
        const int hi = hex_digit(in[2 * i]);
        const int lo = hex_digit(in[2 * i + 1]);
        if (hi < 0 || lo < 0) return false;
        out[i] = (uint8_t)((hi << 4) | lo);
    }
    return true;
}

enum { HEX_OK = 1, HEX_EMPTY = 0, HEX_CANCEL = -1, HEX_BAD = -2 };

static int ask_hex32(const char* title, uint8_t out[32]) {
    char hex[80];
    memset(hex, 0, sizeof(hex));
    if (ask_text(title, hex, sizeof(hex)) != MW_OK) {
        mw_memzero(hex, sizeof(hex));
        return HEX_CANCEL;
    }
    if (hex[0] == '\0') { mw_memzero(hex, sizeof(hex)); return HEX_EMPTY; }
    const bool ok = parse_hex32(hex, out);
    mw_memzero(hex, sizeof(hex));
    return ok ? HEX_OK : HEX_BAD;
}

static mw_err_t hex_result(int r, bool required, bool* filled) {
    *filled = (r == HEX_OK);
    if (r == HEX_OK)     return MW_OK;
    if (r == HEX_CANCEL) return MW_ERR_ABORTED;
    if (r == HEX_EMPTY && !required) return MW_OK;
    mw_ui_message(T(STR_ERR_GENERIC), TX(XSTR_KEY_HEX_BAD));
    return MW_ERR_INVALID_ARG;
}

static mw_err_t flow_import_keys(void) {
    char        name[WALLET_NAME_LEN];
    char        height_txt[16];
    mw_seckey_t spend, view;
    mw_pubkey_t spend_pub;
    mw_account_keys_t keys;
    bool        have_spend = false, have_view = false;
    uint32_t    restore_height = 0;
    uint32_t    id = 0;
    mw_err_t    e  = MW_OK;
    int         r;

    memset(name, 0, sizeof(name));
    memset(height_txt, 0, sizeof(height_txt));
    memset(&spend, 0, sizeof(spend));
    memset(&view, 0, sizeof(view));
    memset(&spend_pub, 0, sizeof(spend_pub));
    memset(&keys, 0, sizeof(keys));

    if (!ensure_secure_key()) return MW_ERR_ABORTED;
    if (ask_text(TX(XSTR_WALLET_NAME), name, sizeof(name)) != MW_OK) return MW_ERR_ABORTED;
    if (name[0] == '\0') snprintf(name, sizeof(name), "%s", TX(XSTR_IMPORT_TITLE));

    r = ask_hex32(TX(XSTR_KEY_SPEND_SEC), spend.b);
    e = hex_result(r, false, &have_spend);
    if (e != MW_OK) goto fail;
    if (have_spend && (!mw_sc_check(&spend) || mw_sc_is_zero(&spend))) {
        mw_ui_message(T(STR_ERR_GENERIC), TX(XSTR_KEY_HEX_BAD));
        e = MW_ERR_INVALID_ARG;
        goto fail;
    }

    r = ask_hex32(TX(XSTR_KEY_VIEW_SEC), view.b);
    e = hex_result(r, !have_spend, &have_view);
    if (e != MW_OK) goto fail;
    if (have_view && (!mw_sc_check(&view) || mw_sc_is_zero(&view))) {
        mw_ui_message(T(STR_ERR_GENERIC), TX(XSTR_KEY_HEX_BAD));
        e = MW_ERR_INVALID_ARG;
        goto fail;
    }

    if (!have_spend) {
        bool have_pub = false;
        r = ask_hex32(TX(XSTR_KEY_SPEND_PUB), spend_pub.b);
        e = hex_result(r, true, &have_pub);
        if (e != MW_OK) goto fail;
        if (!mw_point_check_public(&spend_pub)) {
            mw_ui_message(T(STR_ERR_GENERIC), TX(XSTR_KEY_HEX_BAD));
            e = MW_ERR_SUBGROUP;
            goto fail;
        }
        mw_ui_message(TX(XSTR_IMPORT_KEYS), TX(XSTR_KEY_VIEW_ONLY));
    }

    if (ask_text(TX(XSTR_RESTORE_HEIGHT_HINT), height_txt, sizeof(height_txt)) == MW_OK) {
        restore_height = (uint32_t)strtoul(height_txt, NULL, 10);
    }

    e = mw_wallet_create_from_keys(name, have_spend ? &spend : NULL,
                                   have_view ? &view : NULL,
                                   have_spend ? NULL : &spend_pub, restore_height, &id);
    if (e != MW_OK) { ui_err(e); goto fail; }
    mw_wallet_set_active(id);
    MW_LOGI("wallet", "wallet imported from keys (%s)", have_spend ? "full" : "view-only");

    if (mw_wallet_load_keys(id, "", &keys) == MW_OK) show_address_text(&keys);
    mw_ui_message(T(STR_SUCCESS), TX(XSTR_WALLET_CREATED));
    e = MW_OK;

fail:
    mw_memzero(&keys, sizeof(keys));
    mw_memzero(&spend, sizeof(spend));
    mw_memzero(&view, sizeof(view));
    mw_memzero(&spend_pub, sizeof(spend_pub));
    mw_memzero(name, sizeof(name));
    mw_memzero(height_txt, sizeof(height_txt));
    mw_session_wipe_input();
    return e;
}

static int checksum_suspect(mw_seed_type_t type) {
    return (type == MW_SEED_POLYSEED) ? 0 : (MW_LEGACY_SEED_WORDS - 1);
}

// ===========================================================================
//  Import wallet (TZ 4.2, 5.7, 5.8)
// ===========================================================================
static mw_err_t flow_import_wallet(void) {
    char     name[WALLET_NAME_LEN];
    char     pass[MW_PASSPHRASE_MAX];
    char     word[MW_FLOW_WORD_CAP];
    char     height_txt[16];
    uint16_t indices[MW_MAX_SEED_WORDS];
    uint8_t  material[MW_POLYSEED_BLOB_MAX];
    size_t   material_len = 0;
    mw_polyseed_t ps;
    mw_account_keys_t keys;
    uint32_t restore_height = 0;
    uint32_t id = 0;
    mw_err_t e = MW_OK;
    mw_seed_type_t type = MW_SEED_MONERO_LEGACY;
    int      n_words = MW_LEGACY_SEED_WORDS;
    const mw_wordlist_t* wl = NULL;
    int      start   = 0;
    int      suspect = -1;

    memset(name, 0, sizeof(name));
    memset(pass, 0, sizeof(pass));
    memset(word, 0, sizeof(word));
    memset(indices, 0, sizeof(indices));
    memset(material, 0, sizeof(material));
    memset(&ps, 0, sizeof(ps));
    memset(&keys, 0, sizeof(keys));

    {
        const char* fmt_items[] = { T(STR_SEED_LEGACY25), T(STR_SEED_POLYSEED16),
                                    TX(XSTR_IMPORT_KEYS) };
        const int   fmt = mw_ui_choose(T(STR_SEED_TYPE), fmt_items, 3, 0);
        if (fmt < 0) return MW_ERR_ABORTED;
        if (fmt == 2) return flow_import_keys();
        type = (fmt == 1) ? MW_SEED_POLYSEED : MW_SEED_MONERO_LEGACY;
    }
    n_words = (type == MW_SEED_POLYSEED) ? MW_POLYSEED_WORDS : MW_LEGACY_SEED_WORDS;
    wl = wl_for(type);

    if (!ensure_secure_key()) return MW_ERR_ABORTED;
    if (ask_text(TX(XSTR_WALLET_NAME), name, sizeof(name)) != MW_OK) return MW_ERR_ABORTED;
    if (name[0] == '\0') snprintf(name, sizeof(name), "%s", TX(XSTR_IMPORT_TITLE));

    for (;;) {
        for (int i = start; i < n_words; ) {
            mw_kb_ctx_t kc;
            memset(&kc, 0, sizeof(kc));
            kc.mode       = kb_mode_for(type);
            kc.type       = mw_ui_settings()->keyboard;
            kc.title      = TX(XSTR_IMPORT_TITLE);
            kc.word_index = i + 1;
            kc.word_total = n_words;
            kc.allow_back = (i > 0);
            kc.highlight  = (i == suspect);

            const mw_err_t r = mw_kb_run(&kc, word, sizeof(word));
            if (r == MW_KB_BACK)    { if (i > 0) i--; continue; }
            if (r == MW_KB_RESTART) {
                i = 0; start = 0; suspect = -1;
                memset(indices, 0, sizeof(indices));
                continue;
            }
            if (r != MW_OK)         { e = MW_ERR_ABORTED; goto fail; }

            const int idx = mw_wordlist_find(wl, word);
            if (idx < 0) {
                char msg[64];
                snprintf(msg, sizeof(msg), TX(XSTR_SEED_WORD_BAD), i + 1);
                mw_ui_message(T(STR_ERR_GENERIC), msg);
                continue;
            }
            indices[i] = (uint16_t)idx;
            i++;
        }
        mw_memzero(word, sizeof(word));

        if (type == MW_SEED_MONERO_LEGACY) {
            e = mw_legacy_seed_decode(indices, wl, material);
            material_len = 32;
        } else {
            e = mw_polyseed_decode(indices, wl, &ps);
            if (e == MW_OK) {
                e = mw_polyseed_pack(&ps, material, sizeof(material), &material_len);
                if (e != MW_OK) { ui_err(e); goto fail; }
                restore_height = mw_polyseed_restore_height(&ps, active_network());
            }
        }
        if (e == MW_OK) break;

        suspect = checksum_suspect(type);
        start   = suspect;
        {
            char msg[96];
            snprintf(msg, sizeof(msg), "%s\n", T(STR_CHECKSUM_FAIL));
            const size_t used = strlen(msg);
            snprintf(msg + used, sizeof(msg) - used, TX(XSTR_SEED_FIX_WORD), suspect + 1);
            if (!mw_ui_confirm(T(STR_ERR_GENERIC), msg, T(STR_NEXT), T(STR_CANCEL))) {
                goto fail;
            }
        }
    }

    // Cake Wallet / Cupcake phrases carry polyseed's "encrypted" flag: the
    // passphrase unmasks the phrase (no seed offset) and cannot be skipped.
    // Feather / ColdPunk phrases are plain; their passphrase is optional.
    {
        const bool cake = type == MW_SEED_POLYSEED && mw_polyseed_is_encrypted(&ps);
        if (cake) {
            MW_LOGI("wallet", "encrypted polyseed (Cake / Cupcake format)");
            mw_ui_message(T(STR_PASSPHRASE), TX(XSTR_SEED_CAKE));
        }
        for (;;) {
            e = mw_flow_passphrase(pass, sizeof(pass));
            if (e != MW_OK) goto fail;
            if (!cake || pass[0]) break;
            mw_ui_message(T(STR_PASSPHRASE), TX(XSTR_PP_REQUIRED));
        }
    }

    if (type == MW_SEED_MONERO_LEGACY) {
        memset(height_txt, 0, sizeof(height_txt));
        if (ask_text(TX(XSTR_RESTORE_HEIGHT_HINT), height_txt, sizeof(height_txt)) == MW_OK) {
            restore_height = (uint32_t)strtoul(height_txt, NULL, 10);
        }
    }

    e = store_seed_wallet(name, type, material, material_len, restore_height, pass,
                          &id, &keys);
    if (e != MW_OK) { ui_err(e); goto fail; }
    mw_wallet_set_active(id);
    MW_LOGI("wallet", "wallet imported (%s, %s)",
            type == MW_SEED_POLYSEED ? "polyseed" : "legacy 25 words",
            pass[0] ? "with passphrase" : "no passphrase");

    show_address_text(&keys);
    mw_ui_message(T(STR_SUCCESS), TX(XSTR_WALLET_CREATED));
    e = MW_OK;

fail:
    mw_memzero(&keys, sizeof(keys));
    mw_memzero(&ps, sizeof(ps));
    mw_memzero(material, sizeof(material));
    mw_memzero(indices, sizeof(indices));
    mw_memzero(word, sizeof(word));
    mw_memzero(pass, sizeof(pass));
    mw_memzero(name, sizeof(name));
    mw_session_wipe_input();
    return e;
}

// ===========================================================================
//  The open wallet: state shared with the USB link's INFO
// ===========================================================================
static struct {
    bool     open;
    uint32_t id;
    uint8_t  variant;                     // 0 no passphrase, 1 with
    char     name[WALLET_NAME_LEN];
    uint32_t restore_height;
} s_open;

extern "C" void mw_shell_info(char* name, size_t cap, uint8_t* variant, uint8_t* network) {
    if (name && cap) snprintf(name, cap, "%s", s_open.open ? s_open.name : "");
    if (variant) *variant = s_open.open ? s_open.variant : 0;
    if (network) *network = (uint8_t)active_network();
}

static void link_state(uint8_t state) {
    uint8_t mask = 0;
    if (state == MW_LINK_STATE_WALLET)
        mask = (uint8_t)((1u << MW_FILE_KIND_OUTPUTS) | (1u << MW_FILE_KIND_UNSIGNED_TX));
    mw_link_set_state(state, mask);
}

// Progress of the long operations: a repaint per few percent and on every new
// stage. Also leaves a crash crumb (op/stage enums only) and, in debug mode,
// the crypto-task stack headroom. Never log from inside the crypto code.
typedef struct {
    const char* title;
    int         last;
    uint8_t     op;
    char        stage[48];
} op_progress_t;

static uint8_t crumb_stage_for(const char* stage) {
    if (!stage) return MW_CRUMB_STAGE_NONE;
    if (strstr(stage, "CLSAG"))        return MW_CRUMB_STAGE_CLSAG;
    if (strstr(stage, "bulletproof"))  return MW_CRUMB_STAGE_BPP;
    if (strstr(stage, "sealing"))      return MW_CRUMB_STAGE_SEAL;
    return MW_CRUMB_STAGE_KEYS;
}

static void ops_progress(void* user, const char* stage, uint32_t done, uint32_t total) {
    op_progress_t* p = (op_progress_t*)user;
    const int permille = total ? (int)((uint64_t)done * 1000u / total) : 0;
    const bool new_stage = stage && strncmp(p->stage, stage, sizeof(p->stage)) != 0;
    if (!new_stage && p->last >= 0 && permille - p->last < 20 && permille < 1000) return;
    if (new_stage) {
        snprintf(p->stage, sizeof(p->stage), "%s", stage);
        mw_hal_crumb_set(p->op, crumb_stage_for(stage));
        if (mw_log_debug_enabled())
            MW_LOGD("stack", "crypto min free %u B at %s", (unsigned)mw_stack_free_min(), stage);
    }
    p->last = permille;
    mw_ui_progress(p->title, permille, stage);
}

// ===========================================================================
//  Files from the PC (task 3, algorithm steps 2-10)
// ===========================================================================
// Where a result goes: the USB link outbox (files from the PC) or the SD card
// (wallet menu -> SD card files). An SD sink names the file it wrote.
typedef struct result_sink {
    mw_err_t (*put)(struct result_sink* s, int kind, const uint8_t* data, size_t len);
    void*       ctx;
    const char* saved_as;     // set by the SD sink after a successful write
} result_sink_t;

static mw_err_t link_sink_put(result_sink_t* s, int kind, const uint8_t* data, size_t len) {
    MW_UNUSED(s);
    return mw_link_outbox_put((mw_file_kind_id_t)kind, data, len);
}
static result_sink_t s_link_sink = { link_sink_put, NULL, NULL };

// The key image cache is full: the result is valid, but the device can no
// longer track some outputs (a later transaction spending them is refused).
static void cache_full_warning(void) {
    const uint32_t lost = mw_ops_cache_overflow();
    if (!lost) return;
    char msg[200];
    snprintf(msg, sizeof(msg), TX(XSTR_KI_CACHE_FULL), (unsigned)MW_KI_CACHE_MAX,
             (unsigned)lost);
    mw_ui_message(T(STR_ERR_GENERIC), msg);
}

static void handle_outputs(const mw_account_keys_t* keys, uint8_t* file, size_t len,
                           uint8_t* out, result_sink_t* sink) {
    mw_ops_error_t er;
    mw_ki_export_info_t info;
    size_t plain_len = 0;
    memset(&er, 0, sizeof(er));

    MW_LOGI("file", "outputs export received (%u bytes): checking", (unsigned)len);
    mw_ui_progress(TX(XSTR_PROCESSING), 0, NULL);
    mw_err_t e = mw_ops_outputs_inspect(keys, file, len, &plain_len, &info, &er);
    mw_ui_progress_close();
    if (e != MW_OK) { show_refusal(TX(XSTR_KI_REFUSED), &er); return; }

    MW_LOGI("file", "outputs: %u records, offset %u, %u already known",
            (unsigned)info.count, (unsigned)info.offset, (unsigned)info.known);
    char body[192];
    snprintf(body, sizeof(body), TX(XSTR_KI_CONFIRM), (unsigned)info.count,
             (unsigned)info.known);
    if (!mw_ui_confirm(T(STR_KI_SYNC), body, TX(XSTR_YES), TX(XSTR_NO))) {
        MW_LOGI("file", "key image export declined on the device");
        return;
    }

    op_progress_t p = { T(STR_KI_SYNC), -1, MW_CRUMB_OP_KEYIMAGES, "" };
    mw_ops_cb_t cb = { ops_progress, &p };
    size_t out_len = 0;
    mw_ui_progress(T(STR_KI_SYNC), 0, NULL);
    e = mw_ops_outputs_to_keyimages(keys, file, plain_len, out, MW_FLOW_FILE_CAP,
                                    &out_len, &cb, &er);
    mw_ui_progress_close();
    if (e != MW_OK) { show_refusal(TX(XSTR_KI_REFUSED), &er); return; }

    e = sink->put(sink, MW_FILE_KIND_KEYIMAGES, out, out_len);
    mw_memzero(out, out_len);
    if (e != MW_OK) { ui_err(e); return; }
    MW_LOGI("file", "key images ready: %u records, %u bytes (cache: %u)",
            (unsigned)info.count, (unsigned)out_len, (unsigned)mw_ki_cache_count());
    if (sink->saved_as) snprintf(body, sizeof(body), TX(XSTR_SD_SAVED), sink->saved_as);
    else                snprintf(body, sizeof(body), TX(XSTR_KI_DONE), (unsigned)info.count);
    mw_ui_message(T(STR_SUCCESS), body);
    cache_full_warning();
}

static void handle_unsigned(const mw_account_keys_t* keys, uint8_t* file, size_t len,
                            uint8_t* out, result_sink_t* sink) {
    mw_ops_error_t er;
    mw_tx_review_t* rv = (mw_tx_review_t*)big_alloc(sizeof(mw_tx_review_t));
    mw_sign_session_t* s = (mw_sign_session_t*)big_alloc(sizeof(mw_sign_session_t));
    memset(&er, 0, sizeof(er));
    if (!rv || !s) {
        big_free(rv, sizeof(mw_tx_review_t));
        big_free(s, sizeof(mw_sign_session_t));
        ui_err(MW_ERR_MEMORY);
        return;
    }
    memset(s, 0, sizeof(*s));

    MW_LOGI("file", "unsigned transaction set received (%u bytes): checking", (unsigned)len);
    mw_ui_progress(TX(XSTR_PROCESSING), 0, NULL);
    mw_err_t e = mw_ops_unsigned_inspect(keys, active_network(), file, len, s, true, rv, &er);
    mw_ui_progress_close();
    if (e != MW_OK) {
        show_refusal(TX(XSTR_TX_REFUSED), &er);
        goto done;
    }
    MW_LOGI("file", "unsigned set: %u tx, %u inputs, fee %llu, %u key images requested",
            (unsigned)rv->n_txes, (unsigned)rv->n_inputs,
            (unsigned long long)rv->total_fee, (unsigned)rv->new_transfers);

    if (rv->spent_before > 0) {
        char warn[200];
        snprintf(warn, sizeof(warn), TX(XSTR_TX_SPENT_WARN), (unsigned)rv->spent_before);
        MW_LOGI("file", "%u inputs were already spent by a transaction signed earlier",
                (unsigned)rv->spent_before);
        if (!mw_ui_confirm(T(STR_TX_SIGN), warn, T(STR_NEXT), T(STR_CANCEL))) {
            MW_LOGI("file", "signing declined on the device");
            goto done;
        }
    }

    // Every transaction of the set is reviewed and confirmed on the device.
    for (uint32_t i = 0; i < rv->n_txes; ++i) {
        if (rv->n_txes > 1) {
            char t[48];
            snprintf(t, sizeof(t), TX(XSTR_TX_OF), (unsigned)(i + 1), (unsigned)rv->n_txes);
            mw_ui_message_timeout(T(STR_TX_SIGN), t, 1500);
        }
        MW_LOGI("file", "waiting for the user to review transaction %u", (unsigned)(i + 1));
        if (!mw_screen_tx_run(&rv->sum[i], 0)) {
            MW_LOGI("file", "signing declined on the device");
            goto done;
        }
        // Dropped change silently becomes fee: an unusual fee needs a second yes.
        if (rv->sum[i].high_fee) {
            char fee[32];
            char warn[256];
            mw_format_amount(rv->sum[i].fee, fee, sizeof(fee));
            snprintf(warn, sizeof(warn), TX(XSTR_TX_HIGH_FEE_BODY), fee);
            MW_LOGI("file", "tx %u: high fee %s XMR, second confirmation", (unsigned)(i + 1), fee);
            if (!mw_ui_confirm(TX(XSTR_TX_HIGH_FEE_TITLE), warn, T(STR_TX_SIGN), T(STR_CANCEL))) {
                MW_LOGI("file", "signing declined on the device (high fee)");
                goto done;
            }
        }
    }

    {
        op_progress_t p = { T(STR_SIGNING), -1, MW_CRUMB_OP_SIGN, "" };
        mw_ops_cb_t cb = { ops_progress, &p };
        size_t out_len = 0;
        mw_ui_progress(T(STR_SIGNING), 0, NULL);
        MW_LOGI("file", "signing");
        e = mw_ops_unsigned_sign(keys, s, out, MW_FLOW_FILE_CAP, &out_len, &cb, &er);
        mw_ui_progress_close();
        if (e != MW_OK) { show_refusal(TX(XSTR_TX_REFUSED), &er); goto done; }
        e = sink->put(sink, MW_FILE_KIND_SIGNED_TX, out, out_len);
        mw_memzero(out, out_len);
        if (e != MW_OK) { ui_err(e); goto done; }
        MW_LOGI("file", "signed transaction set ready (%u bytes)", (unsigned)out_len);
        if (sink->saved_as) {
            char body[160];
            snprintf(body, sizeof(body), TX(XSTR_SD_SAVED), sink->saved_as);
            mw_ui_message(T(STR_SUCCESS), body);
        } else {
            mw_ui_message(T(STR_SUCCESS), TX(XSTR_TX_DONE));
        }
        cache_full_warning();
    }

done:
    big_free(rv, sizeof(mw_tx_review_t));
    big_free(s, sizeof(mw_sign_session_t));
}

static void handle_file(const mw_account_keys_t* keys, int kind) {
    size_t len = 0;
    uint8_t* file = (uint8_t*)big_alloc(MW_FLOW_FILE_CAP);
    uint8_t* out  = (uint8_t*)big_alloc(MW_FLOW_FILE_CAP);
    if (!file || !out) {
        big_free(file, MW_FLOW_FILE_CAP);
        big_free(out, MW_FLOW_FILE_CAP);
        mw_link_inbox_clear((mw_file_kind_id_t)kind);
        ui_err(MW_ERR_MEMORY);
        return;
    }
    link_state(MW_LINK_STATE_BUSY);
    mw_hal_crumb_set(kind == MW_FILE_KIND_UNSIGNED_TX ? MW_CRUMB_OP_SIGN : MW_CRUMB_OP_KEYIMAGES,
                     MW_CRUMB_STAGE_LOAD);
    mw_err_t e = mw_link_inbox_take((mw_file_kind_id_t)kind, file, MW_FLOW_FILE_CAP, &len);
    if (e != MW_OK) {
        mw_link_inbox_clear((mw_file_kind_id_t)kind);
        ui_err(e);
    } else if (kind == MW_FILE_KIND_OUTPUTS) {
        handle_outputs(keys, file, len, out, &s_link_sink);
    } else if (kind == MW_FILE_KIND_UNSIGNED_TX) {
        handle_unsigned(keys, file, len, out, &s_link_sink);
    }
    big_free(file, MW_FLOW_FILE_CAP);
    big_free(out, MW_FLOW_FILE_CAP);
    mw_hal_crumb_clear();
    mw_link_bump_seq();
    link_state(MW_LINK_STATE_WALLET);
    if (mw_log_debug_enabled())
        MW_LOGD("stack", "crypto min free %u B after file", (unsigned)mw_stack_free_min());
}

// Host requests: the address, or the view-only data (address + private view
// key) Feather needs to create a view-only wallet. Never the spend key.
static void handle_request(const mw_account_keys_t* keys, uint8_t req) {
    char json[512];
    size_t len = 0;
    const bool vk = (req == MW_LINK_REQ_VIEWONLY);
    MW_LOGI("req", "the PC asks for %s", vk ? "the view-only wallet data" : "the address");
    link_state(MW_LINK_STATE_BUSY);

    bool ok;
    if (vk) {
        if (keys->view_only && mw_sc_is_zero(&keys->sec.view)) ok = false;
        // A plain Yes / No on the device (the user asked for this instead of
        // the typed code): the screen spells out what leaves the device.
        else ok = mw_ui_confirm(TX(XSTR_VIEWKEY_TITLE), TX(XSTR_REQ_VK_Q),
                                TX(XSTR_YES), TX(XSTR_NO));
    } else {
        ok = mw_ui_confirm(TX(XSTR_ADDRESS), TX(XSTR_REQ_ADDR_Q), TX(XSTR_YES), TX(XSTR_NO));
    }
    if (!ok) {
        MW_LOGI("req", "request declined on the device");
        mw_ui_message_timeout(TX(XSTR_ADDRESS), TX(XSTR_REQ_DENIED), 1500);
        link_state(MW_LINK_STATE_WALLET);
        return;
    }
    const mw_err_t e = mw_ops_wallet_export(keys, active_network(), s_open.name,
                                            s_open.restore_height, vk, json,
                                            sizeof(json), &len);
    if (e == MW_OK) {
        const mw_err_t pe = mw_link_outbox_put(MW_FILE_KIND_WALLET_EXPORT,
                                               (const uint8_t*)json, len);
        if (pe == MW_OK) {
            MW_LOGI("req", "%s sent to the PC", vk ? "view-only wallet data" : "address");
            mw_ui_message_timeout(T(STR_SUCCESS), TX(XSTR_REQ_SENT), 2000);
        } else {
            ui_err(pe);
        }
    } else {
        ui_err(e);
    }
    mw_memzero(json, sizeof(json));
    link_state(MW_LINK_STATE_WALLET);
}

// ===========================================================================
//  SD card files (wallet menu)
// ===========================================================================
// The card root is scanned for the Feather files the device can process
// (outputs exports, unsigned transaction sets), newest first by the FAT date
// the PC set, or by the time in the name when the card has no date. The
// result is written next to its source with the source's date; a source that
// already has its result on the card is marked as processed.
#define MW_SD_LIST_MAX 64

typedef struct {
    const mw_sd_entry_t* in;
    mw_sdf_kind_t        kind;
    char                 name[MW_SD_ENTRY_NAME];
} sd_job_t;

static mw_err_t sd_sink_put(result_sink_t* s, int kind, const uint8_t* data, size_t len) {
    MW_UNUSED(kind);
    sd_job_t* j = (sd_job_t*)s->ctx;
    mw_err_t e = mw_sd_write_file(j->name, data, len);
    if (e != MW_OK) return e;
    // The device has no clock: the result gets the date of its source.
    const int64_t t = mw_sdf_sort_time(j->in);
    if (t > 0 && mw_sd_set_mtime(j->name, t) != MW_OK)
        MW_LOGI("sd", "could not set the date of the result");
    // Everything cached goes to the card now: it may be pulled out right after.
    mw_sd_release();
    s->saved_as = j->name;
    MW_LOGI("sd", "result written to the card (%u bytes)", (unsigned)len);
    return MW_OK;
}

// The help file in the card root, written once per card.
static void sd_readme_ensure(void) {
    if (mw_sd_exists(mw_sdf_readme_name)) return;
    const mw_err_t e = mw_sd_write_file(mw_sdf_readme_name,
                                        (const uint8_t*)mw_sdf_readme_text,
                                        strlen(mw_sdf_readme_text));
    mw_sd_release();                      // flush at once; the caller remounts
    MW_LOGI("sd", "%s written to the card: %s", mw_sdf_readme_name, mw_err_str(e));
}

static void sd_process(const mw_account_keys_t* keys, const mw_sd_entry_t* in,
                       mw_sdf_kind_t kind) {
    sd_job_t job;
    memset(&job, 0, sizeof(job));
    job.in = in;
    job.kind = kind;
    mw_err_t e = mw_sdf_result_name(kind, in->name, job.name, sizeof(job.name));
    if (e != MW_OK) { ui_err(e); return; }

    uint8_t* file = (uint8_t*)big_alloc(MW_FLOW_FILE_CAP);
    uint8_t* out  = (uint8_t*)big_alloc(MW_FLOW_FILE_CAP);
    if (!file || !out) {
        big_free(file, MW_FLOW_FILE_CAP);
        big_free(out, MW_FLOW_FILE_CAP);
        ui_err(MW_ERR_MEMORY);
        return;
    }
    size_t len = 0;
    link_state(MW_LINK_STATE_BUSY);        // the PC must not push files meanwhile
    mw_ui_progress(TX(XSTR_PROCESSING), 0, NULL);
    e = mw_sd_read_file(in->name, file, MW_FLOW_FILE_CAP, &len);
    mw_ui_progress_close();
    if (e != MW_OK) {
        ui_err(e);
    } else {
        result_sink_t sink = { sd_sink_put, &job, NULL };
        MW_LOGI("sd", "%s from the card (%u bytes)",
                kind == MW_SDF_OUTPUTS ? "outputs export" : "unsigned transaction",
                (unsigned)len);
        mw_hal_crumb_set(kind == MW_SDF_UNSIGNED ? MW_CRUMB_OP_SIGN : MW_CRUMB_OP_KEYIMAGES,
                         MW_CRUMB_STAGE_LOAD);
        if (kind == MW_SDF_OUTPUTS) handle_outputs(keys, file, len, out, &sink);
        else                        handle_unsigned(keys, file, len, out, &sink);
        mw_hal_crumb_clear();
    }
    mw_memzero(file, len);
    big_free(file, MW_FLOW_FILE_CAP);
    big_free(out, MW_FLOW_FILE_CAP);
    mw_link_bump_seq();
    link_state(MW_LINK_STATE_WALLET);
}

static void sd_format_date(int64_t t, char* out, size_t cap) {
    if (t <= 0) { snprintf(out, cap, "-"); return; }
    time_t tt = (time_t)t;
    struct tm tm;
    gmtime_r(&tt, &tm);          // the FAT date is the PC's local time, shown as is
    snprintf(out, cap, "%04d-%02d-%02d %02d:%02d", tm.tm_year + 1900, tm.tm_mon + 1,
             tm.tm_mday, tm.tm_hour, tm.tm_min);
}

static void sd_files_menu(const mw_account_keys_t* keys) {
    if (mw_sd_ensure() != MW_OK) {
        MW_LOGI("sd", "no card");
        mw_ui_message(TX(XSTR_SD_TITLE), TX(XSTR_SD_NO_CARD));
        return;
    }
    sd_readme_ensure();

    mw_sd_entry_t* all  = (mw_sd_entry_t*)big_alloc(sizeof(mw_sd_entry_t) * MW_SD_LIST_MAX);
    mw_sd_row_t*   rows = (mw_sd_row_t*)big_alloc(sizeof(mw_sd_row_t) * MW_SD_LIST_MAX);
    mw_sdf_kind_t* kind = (mw_sdf_kind_t*)big_alloc(sizeof(mw_sdf_kind_t) * MW_SD_LIST_MAX);
    char (*detail)[96]  = (char (*)[96])big_alloc(96u * MW_SD_LIST_MAX);
    if (!all || !rows || !kind || !detail) {
        ui_err(MW_ERR_MEMORY);
        goto out;
    }

    {
        int focus = 0;
        for (;;) {
            if (mw_sd_ensure() != MW_OK) {
                mw_ui_message(TX(XSTR_SD_TITLE), TX(XSTR_SD_NO_CARD));
                break;
            }
            int found = 0;
            if (mw_sd_list_files("/", all, MW_SD_LIST_MAX, &found) != MW_OK) {
                ui_err(MW_ERR_IO);
                break;
            }
            // Keep only what the device can process.
            int n = 0;
            for (int i = 0; i < found; i++) {
                if (all[i].size == 0 || all[i].size > MW_TRANSFER_MAX_FILE) continue;
                uint8_t head[MW_SDF_HEAD_LEN];
                size_t  hl = 0;
                if (mw_sd_read_head(all[i].name, head, sizeof(head), &hl) != MW_OK) continue;
                if (mw_sdf_kind(head, hl) == MW_SDF_NONE) continue;
                if (n != i) all[n] = all[i];
                n++;
            }
            mw_sdf_sort(all, n);
            MW_LOGI("sd", "%d of %d files in the card root can be processed", n, found);
            if (n == 0) {
                mw_ui_message(TX(XSTR_SD_TITLE), TX(XSTR_SD_EMPTY));
                break;
            }
            for (int i = 0; i < n; i++) {
                uint8_t head[MW_SDF_HEAD_LEN];
                size_t  hl = 0;
                (void)mw_sd_read_head(all[i].name, head, sizeof(head), &hl);
                kind[i] = mw_sdf_kind(head, hl);
                char res[MW_SD_ENTRY_NAME];
                const bool done = mw_sdf_result_name(kind[i], all[i].name, res, sizeof(res)) == MW_OK &&
                                  mw_sd_exists(res);
                char date[24];
                sd_format_date(mw_sdf_sort_time(&all[i]), date, sizeof(date));
                const uint32_t kb = (all[i].size + 1023u) / 1024u;
                snprintf(detail[i], 96, "%s | %u KB | %s%s%s",
                         kind[i] == MW_SDF_OUTPUTS ? TX(XSTR_SD_OUTPUTS) : TX(XSTR_SD_UNSIGNED),
                         (unsigned)kb, date, done ? " | " : "", done ? TX(XSTR_SD_DONE) : "");
                rows[i].icon   = kind[i] == MW_SDF_OUTPUTS ? LV_SYMBOL_REFRESH : LV_SYMBOL_EDIT;
                rows[i].name   = all[i].name;
                rows[i].detail = detail[i];
                rows[i].done   = done;
            }
            if (focus >= n) focus = n - 1;
            const int r = mw_screen_sd_files_run(TX(XSTR_SD_TITLE), rows, n, focus);
            if (r < 0 || lock_requested()) break;
            focus = r;
            sd_process(keys, &all[r], kind[r]);
            if (lock_requested()) break;
        }
    }

out:
    mw_sd_release();                      // nothing stays mounted outside this menu
    big_free(all, sizeof(mw_sd_entry_t) * MW_SD_LIST_MAX);
    big_free(rows, sizeof(mw_sd_row_t) * MW_SD_LIST_MAX);
    big_free(kind, sizeof(mw_sdf_kind_t) * MW_SD_LIST_MAX);
    big_free(detail, 96u * MW_SD_LIST_MAX);
}

// Anything the PC queued since the last look. true when something was done.
static bool handle_pending(const mw_account_keys_t* keys) {
    const uint8_t req = mw_link_request_take();
    if (req) { handle_request(keys, req); return true; }
    size_t len = 0;
    const int kind = mw_link_inbox_any(&len);
    if (kind >= 0) { handle_file(keys, kind); return true; }
    return false;
}

// ===========================================================================
//  Wallet menu (task 3 item 1)
// ===========================================================================
// task2 item 6 / task 3: deleting needs the typed number, not a tap.
static bool delete_wallet(uint32_t id) {
    const wallet_entry_t* w = mw_wallet_get(id);
    char msg[WALLET_NAME_LEN + 96];
    snprintf(msg, sizeof(msg), TX(XSTR_WALLET_DELETE_Q), (w && w->name[0]) ? w->name : "");
    if (!mw_ui_confirm_code(T(STR_WALLET_DELETE), msg)) return false;
    mw_ki_cache_close();
    const mw_err_t e = mw_wallet_delete(id);
    if (e == MW_OK) {
        MW_LOGI("wallet", "wallet deleted");
        mw_ui_message(T(STR_SUCCESS), TX(XSTR_WALLET_DELETED));
        return true;
    }
    ui_err(e);
    return false;
}

static void rename_wallet(uint32_t id) {
    char name[WALLET_NAME_LEN];
    memset(name, 0, sizeof(name));
    if (ask_text(TX(XSTR_WALLET_NAME), name, sizeof(name)) != MW_OK || !name[0]) return;
    const mw_err_t e = mw_wallet_rename(id, name);
    if (e == MW_OK) {
        snprintf(s_open.name, sizeof(s_open.name), "%s", name);
        MW_LOGI("wallet", "wallet renamed");
        mw_ui_message_timeout(T(STR_SUCCESS), TX(XSTR_WL_RENAMED), 1500);
    } else {
        mw_ui_message(T(STR_ERR_GENERIC), mw_err_str(e));
    }
}

static void wallet_home(uint32_t id, mw_account_keys_t* keys, uint8_t variant) {
    const wallet_entry_t* w = mw_wallet_get(id);
    memset(&s_open, 0, sizeof(s_open));
    s_open.open = true;
    s_open.id = id;
    s_open.variant = variant;
    s_open.restore_height = w ? w->restore_height : 0;
    snprintf(s_open.name, sizeof(s_open.name), "%s", w ? w->name : "");

    if (mw_ki_cache_open(id, variant, keys) != MW_OK) {
        MW_LOGE("wallet", "key image cache unavailable");
    } else if (mw_ki_cache_rolled_back()) {
        mw_ui_message(T(STR_ERR_GENERIC), TX(XSTR_KI_ROLLBACK));
    }
    // Leftovers from before the wallet was open are not for this wallet.
    for (int k = 0; k < MW_FILE_KIND_COUNT; ++k) mw_link_inbox_clear((mw_file_kind_id_t)k);
    (void)mw_link_request_take();
    link_state(MW_LINK_STATE_WALLET);
    MW_LOGI("wallet", "wallet '%s' open (%s), %u known key images: ready for files",
            s_open.name, variant ? "with passphrase" : "no passphrase",
            (unsigned)mw_ki_cache_count());

    enum { WA_ADDR = 0, WA_ADDR_QR, WA_VK, WA_VK_QR, WA_SD, WA_RENAME, WA_DELETE, WA_COUNT };
    // SD card files only on boards with a card slot.
    const bool with_sd = mw_hal_caps()->has_sd;
    int focus = 0;
    for (;;) {
        if (lock_requested()) break;
        const uint32_t seq = mw_ui_wake_seq();
        if (handle_pending(keys)) continue;
        if (lock_requested()) break;

        const char* all_items[WA_COUNT] = {
            TX(XSTR_WL_ADDR_TEXT), TX(XSTR_WL_ADDR_QR), TX(XSTR_WL_VK_TEXT),
            TX(XSTR_WL_VK_QR), TX(XSTR_WL_SD), TX(XSTR_WL_RENAME), T(STR_WALLET_DELETE)
        };
        const char* all_icons[WA_COUNT] = {
            LV_SYMBOL_HOME, LV_SYMBOL_IMAGE, LV_SYMBOL_EYE_OPEN, LV_SYMBOL_IMAGE,
            LV_SYMBOL_SD_CARD, LV_SYMBOL_EDIT, LV_SYMBOL_TRASH
        };
        // Menu position -> action, skipping what this board does not have.
        const char* items[WA_COUNT];
        const char* icons[WA_COUNT];
        bool        danger[WA_COUNT];
        int         action[WA_COUNT];
        int         shown = 0;
        for (int a = 0; a < WA_COUNT; a++) {
            if (a == WA_SD && !with_sd) continue;
            items[shown]  = all_items[a];
            icons[shown]  = all_icons[a];
            danger[shown] = (a == WA_DELETE);
            action[shown] = a;
            shown++;
        }
        char sub[96];
        snprintf(sub, sizeof(sub), "%s%s\n%s",
                 variant ? TX(XSTR_WL_VARIANT_PP) : TX(XSTR_WL_VARIANT_BASE),
                 keys->view_only ? " / view-only" : "",
                 mw_link_is_up() ? TX(XSTR_WL_READY) : TX(XSTR_WL_NO_LINK));

        mw_menu_t m;
        memset(&m, 0, sizeof(m));
        m.title = s_open.name;
        m.subtitle = sub;
        m.items = items;
        m.icons = icons;
        m.danger = danger;
        m.count = shown;
        m.initial = focus;
        m.back = true;
        m.back_label = TX(XSTR_WL_CLOSE);
        m.wake = true;
        m.wake_seq = seq;
        m.with_status = true;
        const int r = mw_ui_menu_run(&m);
        if (r == MW_MENU_WAKE) continue;
        if (r == MW_MENU_BACK) break;
        focus = r;
        switch ((r >= 0 && r < shown) ? action[r] : -1) {
        case WA_ADDR:    show_address_text(keys); break;
        case WA_ADDR_QR: show_address_qr(keys); break;
        case WA_VK:      show_view_key(keys, false); break;
        case WA_VK_QR:   show_view_key(keys, true); break;
        case WA_SD:      sd_files_menu(keys); break;
        case WA_RENAME:  rename_wallet(id); break;
        case WA_DELETE:
            if (delete_wallet(id)) goto closed;
            break;
        default: break;
        }
    }
    (void)mw_ki_cache_save();
closed:
    mw_ki_cache_close();
    memset(&s_open, 0, sizeof(s_open));
    link_state(lock_requested() ? MW_LINK_STATE_LOCKED : MW_LINK_STATE_MENU);
    MW_LOGI("wallet", "wallet closed");
}

// True for a polyseed stored in the Cake Wallet / Cupcake form (the phrase
// itself is encrypted with the passphrase, polyseed feature bit 16). Packed
// context: birthday(2) || features(1) || secret.
static bool wallet_is_cake(uint32_t id) {
    const wallet_entry_t* w = mw_wallet_get(id);
    if (!w || w->wallet_type != MW_SEED_POLYSEED) return false;
    uint8_t blob[64];
    size_t  len = 0;
    bool    cake = false;
    if (mw_wallet_unseal_seed(id, blob, sizeof(blob), &len) == MW_OK && len >= 3) {
        mw_polyseed_t ps;
        if (mw_polyseed_unpack(blob, len, &ps) == MW_OK) cake = mw_polyseed_is_encrypted(&ps) != 0;
        mw_memzero(&ps, sizeof(ps));
    }
    mw_memzero(blob, sizeof(blob));
    return cake;
}

// Asks for the passphrase when the wallet has one (task 3 item 5) and opens
// the base or the passphrase variant.
static bool open_wallet(uint32_t id, mw_account_keys_t* keys, uint8_t* variant) {
    const wallet_entry_t* w = mw_wallet_get(id);
    char name[WALLET_NAME_LEN];
    char pass[MW_PASSPHRASE_MAX];
    snprintf(name, sizeof(name), "%s", w ? w->name : "");
    memset(pass, 0, sizeof(pass));

    const uint8_t state = mw_wallet_pp_state(id);
    const bool    cake  = state != MW_PP_NONE && wallet_is_cake(id);
    for (;;) {
        if (state != MW_PP_NONE) {
            if (cake)                    mw_ui_message_timeout(name, TX(XSTR_PP_OPEN_CAKE), 2500);
            else if (state == MW_PP_SET) mw_ui_message_timeout(name, TX(XSTR_PP_OPEN_HINT), 2500);
            if (mw_screen_passphrase_open_run(name, pass, sizeof(pass)) != MW_OK) {
                mw_memzero(pass, sizeof(pass));
                return false;
            }
            if (cake && !pass[0]) {
                mw_ui_message(name, TX(XSTR_PP_REQUIRED));
                continue;
            }
        }
        bool verified = false;
        mw_ui_progress(TX(XSTR_WALLET_UNLOCK), 0, NULL);
        const mw_err_t e = mw_wallet_open(id, pass, keys, &verified);
        mw_ui_progress_close();
        if (e == MW_ERR_DECRYPT) {
            MW_LOGE("wallet", "wrong passphrase");
            mw_ui_message(T(STR_ERR_GENERIC), TX(XSTR_PP_WRONG));
            mw_memzero(pass, sizeof(pass));
            continue;
        }
        if (e != MW_OK) {
            mw_memzero(pass, sizeof(pass));
            ui_err(e);
            return false;
        }
        if (pass[0] && !verified) mw_ui_message(name, TX(XSTR_PP_UNVERIFIED));
        *variant = pass[0] ? 1 : 0;
        mw_memzero(pass, sizeof(pass));
        mw_session_wipe_input();
        return true;
    }
}

// ===========================================================================
//  Wallet list
// ===========================================================================
static void wallets_menu(void) {
    int focus = 0;
    for (;;) {
        if (lock_requested()) return;
        static wallet_store_t store;
        uint32_t ids[MAX_WALLETS];
        char     labels[MAX_WALLETS][WALLET_NAME_LEN + 8];
        const char* items[MAX_WALLETS + 2];
        const char* icons[MAX_WALLETS + 2];
        int n = 0;

        if (mw_wallet_store_load(&store) == MW_OK) {
            for (uint32_t i = 0; i < store.count && n < MAX_WALLETS; i++) {
                const wallet_entry_t* w = &store.wallets[i];
                if (w->is_hidden) continue;
                snprintf(labels[n], sizeof(labels[n]), "%s%s", w->name,
                         (mw_wallet_pp_state(w->id) != MW_PP_NONE) ? "  *" : "");
                ids[n] = w->id;
                items[n] = labels[n];
                icons[n] = LV_SYMBOL_DIRECTORY;
                n++;
            }
        }
        mw_memzero(&store, sizeof(store));
        const int n_wallets = n;
        items[n] = T(STR_WALLET_CREATE); icons[n] = LV_SYMBOL_PLUS;     n++;
        items[n] = T(STR_WALLET_IMPORT); icons[n] = LV_SYMBOL_DOWNLOAD; n++;

        mw_menu_t m;
        memset(&m, 0, sizeof(m));
        m.title = T(STR_MAIN_WALLETS);
        m.subtitle = n_wallets ? NULL : TX(XSTR_WALLET_EMPTY);
        m.footnote = n_wallets ? TX(XSTR_WL_PP_MARK) : NULL;
        m.items = items;
        m.icons = icons;
        m.count = n;
        m.initial = focus;
        m.back = true;
        m.with_status = true;
        const int r = mw_ui_menu_run(&m);
        if (r < 0) return;
        focus = r;

        if (r < n_wallets) {
            mw_account_keys_t keys;
            uint8_t variant = 0;
            memset(&keys, 0, sizeof(keys));
            if (open_wallet(ids[r], &keys, &variant)) {
                mw_wallet_set_active(ids[r]);
                wallet_home(ids[r], &keys, variant);
                focus = 0;
            }
            mw_memzero(&keys, sizeof(keys));
        } else if (r == n_wallets) {
            (void)flow_create_wallet();
        } else {
            (void)flow_import_wallet();
        }
    }
}

// ===========================================================================
//  Main menu (task 3 item 1): Wallets, Settings, Lock
// ===========================================================================
static void main_menu(void) {
    int focus = 0;
    for (;;) {
        if (lock_requested()) return;
        const char* items[3] = { T(STR_MAIN_WALLETS), T(STR_MAIN_SETTINGS), TX(XSTR_MAIN_LOCK) };
        const char* icons[3] = { LV_SYMBOL_LIST, LV_SYMBOL_SETTINGS, LV_SYMBOL_POWER };
        mw_menu_t m;
        memset(&m, 0, sizeof(m));
        m.title = TX(XSTR_APP_NAME);
        m.items = items;
        m.icons = icons;
        m.count = 3;
        m.initial = focus;
        m.back = false;
        m.with_status = true;
        const int r = mw_ui_menu_run(&m);
        if (r < 0) {
            if (lock_requested()) return;
            continue;
        }
        focus = r;
        MW_LOGI("menu", "main menu: %s", r == 0 ? "wallets" : r == 1 ? "settings" : "lock");
        if (r == 0)      wallets_menu();
        else if (r == 1) mw_screen_settings_run();
        else             return;
    }
}

// ===========================================================================
//  USB link glue
// ===========================================================================
// PUT auto: files are recognised by their content (task 3 item 6).
static int classify_file(const uint8_t* data, size_t len, char* why, size_t cap) {
    const mw_file_format_t f = mw_file_detect(data, len);
    switch (f) {
    case MW_FMT_OUTPUTS:     return MW_FILE_KIND_OUTPUTS;
    case MW_FMT_UNSIGNED_TX: return MW_FILE_KIND_UNSIGNED_TX;
    case MW_FMT_KEYIMAGES:
        snprintf(why, cap, "this is a key image export (made by the device): import it in Feather");
        return -1;
    case MW_FMT_SIGNED_TX:
        snprintf(why, cap, "this is a signed transaction (made by the device): load it in Feather");
        return -1;
    case MW_FMT_MULTISIG:
        snprintf(why, cap, "multisig transaction sets are not supported");
        return -1;
    case MW_FMT_UNSUPPORTED_VERSION:
        snprintf(why, cap, "unsupported version of a Monero file - update the wallet software");
        return -1;
    default:
        snprintf(why, cap, "not a Monero outputs export or unsigned transaction file");
        return -1;
    }
}

static void link_event(void* ctx) {
    MW_UNUSED(ctx);
    mw_ui_wake();
}

extern "C" void mw_shell_link_install(void) {
    mw_link_set_classifier(classify_file);
    mw_link_set_event_hook(link_event, NULL);
    link_state(MW_LINK_STATE_LOCKED);
}

// ===========================================================================
//  The shell
// ===========================================================================
static void* ops_alloc(size_t n)         { return big_alloc(n); }
static void  ops_free(void* p, size_t n) { big_free(p, n); }

static void lock_device(void) {
    mw_ui_autolock_arm(false);
    mw_ki_cache_close();
    memset(&s_open, 0, sizeof(s_open));
    mw_session_lock();
    mw_device_auth_forget();
    for (int k = 0; k < MW_FILE_KIND_COUNT; ++k) {
        mw_link_inbox_clear((mw_file_kind_id_t)k);
        mw_link_outbox_clear((mw_file_kind_id_t)k);
    }
    link_state(MW_LINK_STATE_LOCKED);
    MW_LOGI("shell", "device locked");
}

// USB comes up only after the first correct device password (user request:
// no USB link while the device is locked at power-on). Started once; a later
// lock keeps the transport but the link state refuses every file/request.
extern "C" mw_err_t mw_usb_link_init(void);
extern "C" bool     mw_usb_link_running(void);
static void ensure_usb_link(void) {
#if defined(ARDUINO) && !defined(MW_HOST_BUILD)
    if (mw_usb_link_running()) return;
    const mw_err_t e = mw_usb_link_init();
    MW_LOGI("shell", "usb link started after unlock -> %s", mw_err_str(e));
#endif
}

extern "C" void mw_shell_run(void) {
    const mw_ops_alloc_t a = { ops_alloc, ops_free };
    mw_ops_set_allocator(&a);
    (void)mw_fstore_init();

    for (;;) {
        link_state(MW_LINK_STATE_LOCKED);
        mw_ui_show(MW_SCREEN_MAIN_MENU);          // neutral background
        mw_screen_game_run();
        if (!device_auth()) continue;
        ensure_usb_link();

        {   // A crash crumb from the previous run (enums only, no secrets).
            uint8_t op = 0, st = 0;
            if (mw_hal_last_crash(&op, &st)) {
                MW_LOGE("boot", "previous run crashed during op %u stage %u, "
                        "crypto stack min free %u B", (unsigned)op, (unsigned)st,
                        (unsigned)mw_hal_last_crash_stack_free());
                char note[160];
                snprintf(note, sizeof(note), TX(XSTR_LAST_CRASH), (unsigned)op, (unsigned)st);
                mw_ui_message(T(STR_ERR_GENERIC), note);
                mw_hal_last_crash_forget();
            }
        }

        mw_ui_autolock_arm(true);
        link_state(MW_LINK_STATE_MENU);
        main_menu();
        lock_device();
    }
}
