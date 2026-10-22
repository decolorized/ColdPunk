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
//  The Minesweeper box exists only with Settings -> "Minesweeper at start"
//  on; off (the default) the loop goes straight to the password screen.
//
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
#include "../crypto/chacha.h"
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

#include <stdarg.h>
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

static mw_network_t active_network(void);   // the open wallet's (below)

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

// Optional passphrase hint (v9.2): out = "" for none. false on cancel.
static bool ask_pp_hint(char* out, size_t cap) {
    mw_ui_message(TX(XSTR_PP_HINT), TX(XSTR_PP_HINT_WARN));
    for (;;) {
        memset(out, 0, cap);
        if (ask_text(TX(XSTR_PP_HINT_ASK), out, cap) != MW_OK) { out[0] = 0; return false; }
        if (strlen(out) < MW_PP_HINT_LEN) return true;
        mw_ui_message(T(STR_ERR_GENERIC), TX(XSTR_PP_HINT_RULES));
    }
}

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
    char msg[160];
    if (e == MW_ERR_DECRYPT) {
        snprintf(msg, sizeof(msg), TX(XSTR_PW_WRONG), (int)mw_device_auth_failed_attempts());
        if (mw_device_auth_child_pin_due()) {
            size_t n = strlen(msg);
            snprintf(msg + n, sizeof(msg) - n, "\n");
            n = strlen(msg);
            snprintf(msg + n, sizeof(msg) - n, TX(XSTR_PW_LEFT), mw_device_auth_attempts_left());
        }
        mw_ui_message(T(STR_ERR_GENERIC), msg);
    } else if (e == MW_ERR_ABORTED) {
        const uint32_t ms = mw_device_auth_lockout_ms();
        mw_ui_lockout_text(ms, msg, sizeof(msg));
        mw_ui_message_timeout(T(STR_ERR_GENERIC), msg, ms ? ms : 1000u);
    } else {
        ui_err(e);
    }
}

// NVS mark of a wipe in progress: a power cut before the NVS erase (which
// removes the mark) repeats the wipe at the next start.
#define WIPE_MARK "fswipe"
extern "C" mw_err_t mw_store_blob_write(const char* key, const void* data, size_t len);
extern "C" int      mw_store_blob_exists(const char* key);

extern "C" void mw_shell_wipe_device(void) {
    MW_LOGE("auth", "erasing the device");
    mw_ui_progress(TX(XSTR_WIPING), 0, NULL);
    const uint8_t one = 1;
    (void)mw_store_blob_write(WIPE_MARK, &one, 1);
    mw_secure_user_key_clear();
    (void)mw_fstore_wipe_all();
    mw_ui_progress(TX(XSTR_WIPING), 900, NULL);
    mw_factory_reset();                       // NVS (password record last); restarts
}

// The reset phrase typed into the password field (MW_RESET_PHRASE).
static void reset_phrase_typed(void) {
    MW_LOGE("auth", "reset phrase typed");
    if (mw_ui_confirm_code(T(STR_SETTINGS_RESET), TX(XSTR_RESET_PHRASE_Q)))
        mw_shell_wipe_device();               // never returns
}

// From MW_PW_CHILD_AT wrong passwords on: a random number to type before the
// password (a child pressing keys does not burn the last attempts). A wrong
// or cancelled number is not an attempt.
static bool child_pin_gate(void) {
    if (!mw_device_auth_child_pin_due()) return true;
    char body[160];
    snprintf(body, sizeof(body), "%s\n", TX(XSTR_CHILD_PIN));
    const size_t n = strlen(body);
    snprintf(body + n, sizeof(body) - n, TX(XSTR_PW_LEFT), mw_device_auth_attempts_left());
    return mw_ui_confirm_code(TX(XSTR_PW_TITLE), body);
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
    case MW_AUTH_STAGE_OPEN:    what = TX(XSTR_PW_STAGE_OPEN);    break;
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
            mw_shell_wipe_device();             // never returns
        }
        return false;
    }

    if (!mw_device_auth_is_set()) {
        // First start: a password has to be created before anything else.
        MW_LOGI("auth", "no device password yet: asking the user to set one");
        mw_ui_message(TX(XSTR_PW_TITLE), TX(XSTR_PW_SET_HINT));
        for (;;) {
            if (ask_text(TX(XSTR_PW_ENTER), pw, sizeof(pw)) != MW_OK) break;
            if (strlen(pw) < MW_DEVICE_PW_MIN_NEW || strlen(pw) > MW_DEVICE_PW_MAX) {
                mw_ui_message(T(STR_ERR_GENERIC), TX(XSTR_PW_RULES));
                continue;
            }
            if (mw_device_pw_weak(pw) &&
                !mw_ui_confirm(TX(XSTR_PW_TITLE), TX(XSTR_PW_WEAK), TX(XSTR_YES), TX(XSTR_NO))) {
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
            // A running delay is shown (until it ends or a tap); the field
            // still opens afterwards, for the reset phrase - a password
            // typed meanwhile is not checked and not counted.
            if (mw_device_auth_lockout_ms()) {
                auth_report(MW_ERR_ABORTED);
                if (mw_ui_lock_requested()) break;
            }
            if (!child_pin_gate()) break;           // back to the game
            // Cancel or the input timeout: back to the game. A factory reset
            // from here is only the reset phrase (MW_RESET_PHRASE) - the way
            // out when no password opens anything any more.
            if (ask_text(TX(XSTR_PW_ENTER), pw, sizeof(pw)) != MW_OK) break;
            if (mw_device_pw_is_reset_phrase(pw)) {
                mw_memzero(pw, sizeof(pw));
                reset_phrase_typed();
                continue;
            }
            if (mw_device_auth_lockout_ms()) {
                mw_memzero(pw, sizeof(pw));
                continue;
            }
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

// Progress of the CryptoNight slow hash (wallet passphrase, file encryption
// key): a few seconds on the S3, so the bar moves instead of sitting at 0.
typedef struct { const char* title; int last; } slow_progress_t;

static void slow_progress_cb(int permille, void* u) {
    slow_progress_t* p = (slow_progress_t*)u;
    if (p->last >= 0 && permille >= p->last && permille - p->last < 20 &&
        permille < 1000) return;
    p->last = permille;
    mw_ui_progress(p->title, permille, NULL);
}

// Opens the progress page and routes the slow hash into it until
// slow_progress_end().
static void slow_progress_begin(slow_progress_t* p, const char* title) {
    p->title = title;
    p->last  = -1;
    mw_ui_progress(title, 0, NULL);
    mw_cn_slow_hash_set_progress(slow_progress_cb, p);
}
static void slow_progress_end(void) {
    mw_cn_slow_hash_set_progress(NULL, NULL);
    mw_wallet_pp_set_progress(NULL, NULL);
    mw_ui_progress_close();
}
// The same page for the passphrase record's derivation (0.3.5, ~1 s or
// more: MW_PP_KDF_ROUNDS) - and for the CryptoNight of an older record.
static void slow_progress_begin_pp(slow_progress_t* p, const char* title) {
    slow_progress_begin(p, title);
    mw_wallet_pp_set_progress(slow_progress_cb, p);
}

// Stores a seed wallet, recording its passphrase variant (task 3 item 5):
// with a passphrase the record opens two wallets - "" gives the plain one.
// 0.3.5: the passphrase wallet is reached only through "Open passphrase" in
// the wallet's menu, which every wallet has.
static mw_err_t store_seed_wallet(const char* name, mw_seed_type_t type,
                                  const uint8_t* material, size_t material_len,
                                  uint32_t restore_height, const char* pass,
                                  uint32_t* id, mw_account_keys_t* shown) {
    mw_account_keys_t pp;
    mw_err_t e;
    memset(&pp, 0, sizeof(pp));
    const bool with_pp = pass && pass[0];
    slow_progress_t sp;
    slow_progress_begin_pp(&sp, TX(XSTR_WALLET_UNLOCK));
    e = mw_seed_to_keys(type, material, material_len, with_pp ? pass : "", &pp);
    if (e == MW_OK) {
        e = mw_wallet_create_pp(name, type, material, material_len, restore_height,
                                with_pp ? pass : "", with_pp ? &pp : NULL, id);
    }
    slow_progress_end();
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
    {
        char hint[MW_PP_HINT_LEN + 8];
        hint[0] = 0;
        if (pass[0]) (void)ask_pp_hint(hint, sizeof(hint));
        e = store_seed_wallet(name, type, material, material_len, restore_height, pass,
                              &id, &keys);
        if (e == MW_OK && hint[0]) (void)mw_wallet_set_pp_hint(id, hint);
        mw_memzero(hint, sizeof(hint));
    }
    if (e != MW_OK) { ui_err(e); goto fail; }
    mw_wallet_set_active(id);
    MW_LOGI("wallet", "wallet created (%s)",
            type == MW_SEED_POLYSEED ? "polyseed" : "legacy 25 words");

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

// Typing a phrase word by word: words start..n-1 into indices (the word
// `suspect` highlighted); Back goes one word back, Restart from the first.
static mw_err_t ask_seed_words(mw_seed_type_t type, const char* title, uint16_t* indices,
                               int start, int suspect) {
    char word[MW_FLOW_WORD_CAP];
    const int n_words = (type == MW_SEED_POLYSEED) ? MW_POLYSEED_WORDS : MW_LEGACY_SEED_WORDS;
    const mw_wordlist_t* wl = wl_for(type);
    mw_err_t e = MW_OK;
    memset(word, 0, sizeof(word));
    for (int i = start; i < n_words; ) {
        mw_kb_ctx_t kc;
        memset(&kc, 0, sizeof(kc));
        kc.mode       = kb_mode_for(type);
        kc.type       = mw_ui_settings()->keyboard;
        kc.title      = title;
        kc.word_index = i + 1;
        kc.word_total = n_words;
        kc.allow_back = (i > 0);
        kc.highlight  = (i == suspect);

        const mw_err_t r = mw_kb_run(&kc, word, sizeof(word));
        if (r == MW_KB_BACK)    { if (i > 0) i--; continue; }
        if (r == MW_KB_RESTART) {
            i = 0; suspect = -1;
            memset(indices, 0, sizeof(uint16_t) * MW_MAX_SEED_WORDS);
            continue;
        }
        if (r != MW_OK)         { e = MW_ERR_ABORTED; break; }

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
    return e;
}

// ===========================================================================
//  Import wallet (TZ 4.2, 5.7, 5.8)
// ===========================================================================
static mw_err_t flow_import_wallet(void) {
    char     name[WALLET_NAME_LEN];
    char     pass[MW_PASSPHRASE_MAX];
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
        if (ask_seed_words(type, TX(XSTR_IMPORT_TITLE), indices, start, suspect) != MW_OK) {
            e = MW_ERR_ABORTED;
            goto fail;
        }

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

    {
        char hint[MW_PP_HINT_LEN + 8];
        hint[0] = 0;
        if (pass[0]) (void)ask_pp_hint(hint, sizeof(hint));
        e = store_seed_wallet(name, type, material, material_len, restore_height, pass,
                              &id, &keys);
        if (e == MW_OK && hint[0]) (void)mw_wallet_set_pp_hint(id, hint);
        mw_memzero(hint, sizeof(hint));
    }
    if (e != MW_OK) { ui_err(e); goto fail; }
    mw_wallet_set_active(id);
    MW_LOGI("wallet", "wallet imported (%s)",
            type == MW_SEED_POLYSEED ? "polyseed" : "legacy 25 words");

    show_address_text(&keys);
    mw_ui_message(T(STR_SUCCESS), TX(XSTR_WALLET_CREATED));
    e = MW_OK;

fail:
    mw_memzero(&keys, sizeof(keys));
    mw_memzero(&ps, sizeof(ps));
    mw_memzero(material, sizeof(material));
    mw_memzero(indices, sizeof(indices));
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

// The open wallet's network (v0.3: kept per wallet); the device setting
// when no wallet is open (a wallet being created takes that one).
static mw_network_t active_network(void) {
    if (s_open.open) return (mw_network_t)mw_wallet_network(s_open.id);
    return mw_ui_settings()->network;
}

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

// The result is in the outbox (or on the card): the PC may fetch it and send
// the next file at once, without waiting for the success message to go.
static void result_ready(void) {
    mw_link_bump_seq();
    link_state(MW_LINK_STATE_WALLET);
}

// How long a success message stays up. It closes itself (or on a tap / key)
// so the device is back in the wallet screen without an extra OK.
#define MW_SUCCESS_MS 2500
#define MW_NOTE_MS    8000       // the success message with notes (0.3.6)

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
// The account's key image container crossed another 64 KiB step (v0.3):
// its size now tells a memory dump that this slot is a real account. Shown
// once per step.
static void ki_growth_warning(void) {
    const size_t sz = mw_ki_store_size();
    const uint32_t steps = (uint32_t)(sz / MW_KI_STORE_STEP);
    const uint32_t warned = mw_wallet_store_ki_warned();
    if (steps < warned) { (void)mw_wallet_store_set_ki_warned(steps); return; }
    if (steps <= 1 || steps <= warned) return;
    MW_LOGI("kicache", "container grew to %u KiB: warning shown", (unsigned)(sz / 1024u));
    char msg[256];
    snprintf(msg, sizeof(msg), TX(XSTR_KI_GROWN), (unsigned)(sz / 1024u));
    mw_ui_message(T(STR_KI_SYNC), msg);
    (void)mw_wallet_store_set_ki_warned(steps);
}

static void cache_full_warning(void) {
    ki_growth_warning();
    if (mw_ops_cache_save_error() != MW_OK) {
        mw_ui_message(T(STR_ERR_GENERIC), TX(mw_ops_cache_save_error() == MW_ERR_TOO_MANY
                                                 ? XSTR_KI_STORAGE_FULL : XSTR_KI_SAVE_FAIL));
    }
    const uint32_t lost = mw_ops_cache_overflow();
    if (!lost) return;
    char msg[200];
    snprintf(msg, sizeof(msg), TX(XSTR_KI_CACHE_FULL), (unsigned)mw_ki_cache_count(),
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
    slow_progress_t sp;
    slow_progress_begin(&sp, TX(XSTR_PROCESSING));
    mw_err_t e = mw_ops_outputs_inspect(keys, file, len, &plain_len, &info, &er);
    slow_progress_end();
    if (e != MW_OK) { show_refusal(TX(XSTR_KI_REFUSED), &er); return; }

    MW_LOGI("file", "outputs: %u records, offset %u, %u already known",
            (unsigned)info.count, (unsigned)info.offset, (unsigned)info.known);
    char body[192];
    snprintf(body, sizeof(body), TX(XSTR_KI_CONFIRM), (unsigned)info.count,
             (unsigned)info.known);
    // 0.3.5: the checkbox is always there: the cache may hold some of the
    // earlier transfers and not others; what it adds is reported afterwards.
    bool all_saved = false;
    if (!mw_ui_confirm_check(T(STR_KI_SYNC), body, TX(XSTR_YES), TX(XSTR_NO),
                             TX(XSTR_KI_ALL_SAVED), &all_saved)) {
        MW_LOGI("file", "key image export declined on the device");
        return;
    }

    op_progress_t p = { T(STR_KI_SYNC), -1, MW_CRUMB_OP_KEYIMAGES, "" };
    mw_ops_cb_t cb = { ops_progress, &p };
    size_t out_len = 0;
    mw_ui_progress(T(STR_KI_SYNC), 0, NULL);
    mw_ki_saved_info_t saved;
    e = mw_ops_outputs_to_keyimages_x(keys, file, plain_len, all_saved, out,
                                      MW_FLOW_FILE_CAP, &out_len, &saved, &cb, &er);
    mw_ui_progress_close();
    if (e != MW_OK) { show_refusal(TX(XSTR_KI_REFUSED), &er); return; }

    e = sink->put(sink, MW_FILE_KIND_KEYIMAGES, out, out_len);
    mw_memzero(out, out_len);
    if (e != MW_OK) { ui_err(e); return; }
    MW_LOGI("file", "key images ready: %u records + %u saved, %u bytes (cache: %u)",
            (unsigned)info.count, (unsigned)saved.saved, (unsigned)out_len,
            (unsigned)mw_ki_cache_count());
    // A typed-in balance holds until the next sync.
    if (s_open.open) (void)mw_wallet_set_manual_balance(s_open.id, false, 0);
    result_ready();
    // 0.3.6: ONE message that closes itself. The notes that used to follow
    // it in windows of their own (what "All saved key images" added, the
    // "export ALL outputs" hint after every partial export) wait for a tap
    // and kept the result screen up; they are part of it now, shown a
    // little longer.
    static char msg[640];
    size_t ml = 0;
    if (sink->saved_as) ml = (size_t)snprintf(msg, sizeof(msg), TX(XSTR_SD_SAVED), sink->saved_as);
    else                ml = (size_t)snprintf(msg, sizeof(msg), TX(XSTR_KI_DONE),
                                              (unsigned)(info.count + saved.saved));
    bool notes = false;
    auto add_note = [&](const char* fmt, ...) {
        if (ml + 2 >= sizeof(msg)) return;
        ml += (size_t)snprintf(msg + ml, sizeof(msg) - ml, "\n\n");
        if (ml >= sizeof(msg)) { ml = sizeof(msg) - 1; return; }
        va_list ap;
        va_start(ap, fmt);
        const int n = vsnprintf(msg + ml, sizeof(msg) - ml, fmt, ap);
        va_end(ap);
        if (n > 0) ml += (size_t)n;
        if (ml >= sizeof(msg)) ml = sizeof(msg) - 1;
        notes = true;
    };
    if (all_saved) {
        // What the cache added: from which transfer, or why nothing.
        if (info.offset == 0)
            add_note("%s", TX(XSTR_KI_SAVED_FULL));
        else if (saved.saved == 0)
            add_note(TX(XSTR_KI_SAVED_NONE), (unsigned)info.offset);
        else
            add_note(TX(XSTR_KI_SAVED_ADDED), (unsigned)saved.saved, (unsigned)saved.start,
                     (unsigned)(info.offset - 1), (unsigned)saved.start);
    }
    // 0.3.5: an incremental export (not from the first transfer) cannot tell
    // the amounts the device is still missing; a full one can.
    if (info.offset != 0 && !(mw_wallet_store_opts() & MW_ACC_OPT_NO_BALANCE)) {
        uint32_t unknown = 0;
        if (mw_ki_cache_balance(NULL, NULL, &unknown) == MW_OK && unknown)
            add_note("%s", TX(XSTR_TXL_HINT_FULL));
    }
    mw_ui_message_timeout(T(STR_SUCCESS), msg, notes ? MW_NOTE_MS : MW_SUCCESS_MS);
    mw_memzero(msg, sizeof(msg));
    cache_full_warning();
}

// The signed transactions go to the wallet's list (v0.3; nothing is kept
// with balance tracking off).
static void record_signed(const mw_tx_review_t* rv) {
    for (uint32_t i = 0; i < rv->n_txes; ++i) {
        const mw_tx_summary_t* sm = &rv->sum[i];
        mw_ki_tx_t t;
        memset(&t, 0, sizeof(t));
        t.fee = sm->fee;
        t.change = sm->change;
        t.n_recipients = sm->n_recipients;
        t.own_only = 1;
        for (uint8_t j = 0; j < sm->n_recipients && j < MW_MAX_DESTINATIONS; ++j) {
            if (sm->recipient_own[j]) continue;
            t.sent += sm->amounts[j];
            if (t.own_only) snprintf(t.addr, sizeof(t.addr), "%.*s", MW_KI_TX_ADDR,
                                     sm->recipients[j]);
            t.own_only = 0;
        }
        (void)mw_ki_cache_tx_add(&t);
    }
    (void)mw_ki_cache_save();
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
    slow_progress_t sp;
    slow_progress_begin(&sp, TX(XSTR_PROCESSING));
    mw_err_t e = mw_ops_unsigned_inspect(keys, active_network(), file, len, s, true, rv, &er);
    slow_progress_end();
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
        if (!(mw_wallet_store_opts() & MW_ACC_OPT_NO_BALANCE)) {
            mw_ui_progress(T(STR_SIGNING), 1000, TX(XSTR_SAVING));
            record_signed(rv);
            mw_ui_progress_close();
        }
        result_ready();
        if (sink->saved_as) {
            char body[160];
            snprintf(body, sizeof(body), TX(XSTR_SD_SAVED), sink->saved_as);
            mw_ui_message_timeout(T(STR_SUCCESS), body, MW_SUCCESS_MS);
        } else {
            mw_ui_message_timeout(T(STR_SUCCESS), TX(XSTR_TX_DONE), MW_SUCCESS_MS);
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

// Lists what the device can process in the card root into the caller's
// arrays: the row count, or -1 when the card could not be read.
static int sd_scan(mw_sd_entry_t* all, mw_sd_row_t* rows, mw_sdf_kind_t* kind,
                   char (*detail)[96]) {
    int found = 0;
    if (mw_sd_list_files("/", all, MW_SD_LIST_MAX, &found) != MW_OK) return -1;
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
    return n;
}

static bool sd_list_changed(void) { return mw_sd_watch_changed(); }

// The list stays open while cards come and go: a background watch notices a
// card pulled out (the list empties and asks for a card) or put in (the list
// is read at once), see mw_sd_watch_start().
static void sd_files_menu(const mw_account_keys_t* keys) {
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
            int n = 0;
            const char* empty = TX(XSTR_SD_INSERT);
            if (mw_sd_ensure() == MW_OK) {
                sd_readme_ensure();               // unmounts after a write
                if (mw_sd_mounted() || mw_sd_ensure() == MW_OK) {
                    n = sd_scan(all, rows, kind, detail);
                    if (n < 0) {                  // pulled out while reading
                        MW_LOGI("sd", "card read failed");
                        mw_sd_release();
                        n = 0;
                    } else if (n == 0) {
                        empty = TX(XSTR_SD_EMPTY);
                    }
                }
            } else {
                MW_LOGI("sd", "no card");
            }
            if (focus >= n) focus = n > 0 ? n - 1 : 0;

            mw_sd_watch_start();
            const int r = mw_screen_sd_files_run(TX(XSTR_SD_TITLE), rows, n, focus,
                                                 empty, sd_list_changed);
            mw_sd_watch_stop();
            if (lock_requested()) break;
            if (r == MW_SD_LIST_CHANGED) {
                MW_LOGI("sd", "card %s", mw_sd_mounted() ? "inserted" : "removed");
                focus = 0;
                continue;
            }
            if (r < 0 || r >= n) break;
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

// Writes the address and the private view key of the open wallet to
// "<wallet>_viewonly.txt" in the card root (a free "_2", "_3"... name when
// that one is taken - two wallets may map to the same file name), after the
// same kind of warning as showing the key on the screen.
static void sd_export_view_key(const mw_account_keys_t* keys) {
    if (mw_sc_is_zero(&keys->sec.view)) {
        mw_ui_message(TX(XSTR_VIEWKEY_TITLE), TX(XSTR_SD_VK_NONE));
        return;
    }
    if (!mw_ui_confirm(TX(XSTR_VIEWKEY_TITLE), TX(XSTR_SD_VK_WARN),
                       TX(XSTR_YES), TX(XSTR_NO))) {
        return;
    }
    if (mw_sd_ensure() != MW_OK) {
        mw_ui_message(TX(XSTR_SD_TITLE), TX(XSTR_SD_NO_CARD));
        return;
    }
    char name[MW_SD_ENTRY_NAME];
    mw_err_t e = MW_ERR_TOO_MANY;
    for (int i = 1; i <= 99; ++i) {
        e = mw_sdf_viewonly_name(s_open.name, i, name, sizeof(name));
        if (e != MW_OK) break;
        if (!mw_sd_exists(name)) break;
        e = MW_ERR_TOO_MANY;
    }
    static char text[1024];               // off the flow stack; wiped below
    size_t len = 0;
    if (e == MW_OK) {
        e = mw_ops_viewonly_text(keys, active_network(), s_open.name,
                                 s_open.restore_height, text, sizeof(text), &len);
    }
    if (e == MW_OK) e = mw_sd_write_file(name, (const uint8_t*)text, len);
    mw_memzero(text, sizeof(text));
    mw_sd_release();                      // flush now: the card may go right away
    if (e != MW_OK) { ui_err(e); return; }
    MW_LOGI("sd", "view-only wallet data written to the card");
    char body[160];
    snprintf(body, sizeof(body), TX(XSTR_SD_SAVED), name);
    mw_ui_message(T(STR_SUCCESS), body);
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

// ---- v0.3: network, seed check, balance -----------------------------------
static const char* net_label(mw_network_t n) {
    switch (n) {
    case MW_NET_TESTNET:  return TX(XSTR_NET_TEST);
    case MW_NET_STAGENET: return TX(XSTR_NET_STAGE);
    default:              return TX(XSTR_NET_MAIN);
    }
}

static void change_network(uint32_t id) {
    const char* items[] = { TX(XSTR_NET_MAIN), TX(XSTR_NET_TEST), TX(XSTR_NET_STAGE) };
    const int cur = mw_wallet_network(id);
    const int i = mw_ui_choose(s_open.name, items, 3, cur);
    if (i < 0 || i == cur) return;
    static const uint8_t wnet[3] = { MW_WNET_MAINNET, MW_WNET_TESTNET, MW_WNET_STAGENET };
    const mw_err_t e = mw_wallet_set_network(id, wnet[i]);
    if (e != MW_OK) { ui_err(e); return; }
    MW_LOGI("wallet", "wallet network set to %s", net_label((mw_network_t)i));
    char msg[128];
    snprintf(msg, sizeof(msg), TX(XSTR_WL_NET_SET), net_label((mw_network_t)i));
    mw_ui_message(T(STR_SUCCESS), msg);
}

// The user types the phrase; the device says whether it is this wallet's.
// Constant-time comparison, nothing but match / no match is shown.
static void check_seed(uint32_t id) {
    const wallet_entry_t* w = mw_wallet_get(id);
    if (!w || (w->wallet_type != MW_SEED_MONERO_LEGACY && w->wallet_type != MW_SEED_POLYSEED))
        return;
    const mw_seed_type_t type = (mw_seed_type_t)w->wallet_type;
    const mw_wordlist_t* wl = wl_for(type);
    uint16_t indices[MW_MAX_SEED_WORDS];
    uint8_t  typed[MW_POLYSEED_BLOB_MAX + 32], stored[64];
    size_t   typed_len = 0, stored_len = 0;
    mw_polyseed_t ps;
    memset(indices, 0, sizeof(indices));
    memset(typed, 0, sizeof(typed));
    memset(stored, 0, sizeof(stored));
    memset(&ps, 0, sizeof(ps));

    mw_ui_message(TX(XSTR_CHECK_SEED), TX(XSTR_CHECK_SEED_HINT));
    if (ask_seed_words(type, TX(XSTR_CHECK_SEED), indices, 0, -1) == MW_OK) {
        mw_err_t e;
        if (type == MW_SEED_MONERO_LEGACY) {
            e = mw_legacy_seed_decode(indices, wl, typed);
            typed_len = 32;
        } else {
            e = mw_polyseed_decode(indices, wl, &ps);
            if (e == MW_OK) e = mw_polyseed_pack(&ps, typed, sizeof(typed), &typed_len);
        }
        if (e != MW_OK) {
            mw_ui_message(TX(XSTR_CHECK_SEED), TX(XSTR_CHECK_SEED_INVALID));
        } else if ((e = mw_wallet_unseal_seed(id, stored, sizeof(stored), &stored_len)) != MW_OK) {
            ui_err(e);
        } else {
            if (type == MW_SEED_MONERO_LEGACY && stored_len == 32) {
                // The same key whether the phrase encodes it reduced or not.
                mw_scalar_t a, b;
                memcpy(a.b, typed, 32);
                memcpy(b.b, stored, 32);
                mw_sc_reduce32(&a);
                mw_sc_reduce32(&b);
                memcpy(typed, a.b, 32);
                memcpy(stored, b.b, 32);
                mw_memzero(&a, sizeof(a));
                mw_memzero(&b, sizeof(b));
            }
            const bool same = typed_len == stored_len && stored_len <= sizeof(stored) &&
                              mw_ct_equal(typed, stored, stored_len) != 0;
            MW_LOGI("wallet", "seed check: %s", same ? "match" : "no match");
            mw_ui_message(TX(XSTR_CHECK_SEED),
                          same ? TX(XSTR_CHECK_SEED_OK) : TX(XSTR_CHECK_SEED_BAD));
        }
    }
    mw_memzero(indices, sizeof(indices));
    mw_memzero(typed, sizeof(typed));
    mw_memzero(stored, sizeof(stored));
    mw_memzero(&ps, sizeof(ps));
    mw_session_wipe_input();
}

// "1", "1.25", "0.000000000001" -> piconero. false when not an amount.
static bool parse_xmr(const char* in, uint64_t* out) {
    uint64_t whole = 0, frac = 0;
    int digits = 0, fd = 0;
    bool dot = false;
    for (const char* p = in; *p; ++p) {
        if (*p == '.' || *p == ',') {
            if (dot) return false;
            dot = true;
            continue;
        }
        if (*p < '0' || *p > '9') return false;
        digits++;
        if (!dot) {
            if (whole > 18000000ull) return false;          // > the supply
            whole = whole * 10u + (uint64_t)(*p - '0');
        } else {
            if (++fd > 12) return false;
            frac = frac * 10u + (uint64_t)(*p - '0');
        }
    }
    if (!digits) return false;
    for (; fd < 12; ++fd) frac *= 10u;
    *out = whole * 1000000000000ull + frac;
    return true;
}

// 0.3.5: every transaction the device knows of, from the key image cache:
//   received - the outputs of the outputs exports, grouped by the
//              transaction they came in (its public key), newest first by
//              the outputs' global index; change of a transaction signed
//              here is marked "*", an output without a known transaction "?"
//   signed   - the transactions signed on this device ("*")
//   ?        - outputs spent by transactions not signed here (only their sum
//              is known) and outputs whose amount is not known
typedef struct {
    mw_pubkey_t tx;
    uint64_t    amount, gidx;
    uint16_t    outs, spent;
    bool        change, notx;
} txl_group_t;

static int txl_cmp(const void* a, const void* b) {
    const txl_group_t* x = (const txl_group_t*)a;
    const txl_group_t* y = (const txl_group_t*)b;
    return x->gidx < y->gidx ? 1 : x->gidx > y->gidx ? -1 : 0;     // newest first
}

static int txl_cmp_tx(const void* a, const void* b) {
    const txl_group_t* x = (const txl_group_t*)a;
    const txl_group_t* y = (const txl_group_t*)b;
    if (x->notx != y->notx) return x->notx ? 1 : -1;
    return memcmp(x->tx.b, y->tx.b, 32);
}

static void show_signed_txs(void) {
    const uint32_t ne = mw_ki_cache_count();
    const uint32_t nt = mw_ki_cache_tx_count();
    uint64_t total = 0;
    uint32_t outs = 0, unknown = 0;
    (void)mw_ki_cache_balance(&total, &outs, &unknown);

    txl_group_t* g = ne ? (txl_group_t*)big_alloc((size_t)ne * sizeof(txl_group_t)) : NULL;
    if (ne && !g) { ui_err(MW_ERR_MEMORY); return; }
    uint32_t ng = 0, else_n = 0;
    uint64_t else_amt = 0;
    // One group per output first, then sorted by transaction key and merged
    // (n log n: a cache holds thousands of outputs).
    for (uint32_t i = 0; i < ne; i++) {
        mw_ki_entry_t e;
        if (!mw_ki_cache_get(i, &e)) continue;
        if (!(e.bal & MW_KI_B_AMOUNT)) continue;              // counted as unknown
        const bool spent_here = (e.flags & MW_KI_F_SPENT) != 0;
        const bool spent = spent_here || (e.bal & MW_KI_B_SPENT);
        if (spent && !spent_here) { else_amt += e.amount; else_n++; }
        txl_group_t* x = &g[ng++];
        memset(x, 0, sizeof *x);
        x->tx = e.tx_pub;
        x->notx = mw_ct_is_zero(e.tx_pub.b, 32) != 0;
        x->gidx = e.gidx;
        x->amount = e.amount;
        x->outs = 1;
        x->spent = spent ? 1 : 0;
        x->change = (e.flags & MW_KI_F_CHANGE) != 0;
        mw_memzero(&e, sizeof e);
    }
    qsort(g, ng, sizeof(txl_group_t), txl_cmp_tx);
    {
        uint32_t m = 0;
        for (uint32_t k = 0; k < ng; k++) {
            if (m && !g[k].notx && !g[m - 1].notx &&
                memcmp(g[m - 1].tx.b, g[k].tx.b, 32) == 0) {
                txl_group_t* y = &g[m - 1];
                y->amount += g[k].amount;
                if (y->outs < 0xFFFF) y->outs++;
                if (g[k].spent && y->spent < 0xFFFF) y->spent++;
                y->change = y->change || g[k].change;
                if (g[k].gidx > y->gidx) y->gidx = g[k].gidx;
            } else {
                g[m++] = g[k];
            }
        }
        ng = m;
    }
    if (!ng && !nt && !unknown) {
        big_free(g, (size_t)ne * sizeof(txl_group_t));
        mw_ui_message(TX(XSTR_BAL_TXS), TX(XSTR_BAL_TX_NONE));
        return;
    }
    qsort(g, ng, sizeof(txl_group_t), txl_cmp);

    const size_t cap = (size_t)ng * 72u + (size_t)nt * 96u + 512u;
    char* text = (char*)big_alloc(cap);
    if (!text) { big_free(g, (size_t)ne * sizeof(txl_group_t)); ui_err(MW_ERR_MEMORY); return; }
    size_t used = 0;
    text[0] = 0;
#define TXL_ADD(...) do { if (used < cap) { snprintf(text + used, cap - used, __VA_ARGS__); \
                                            used = strlen(text); } } while (0)
    char amt[32], fee[32], n[24];
    TXL_ADD("%s\n\n", TX(XSTR_TXL_LEGEND));
    if (ng) TXL_ADD("%s\n", TX(XSTR_TXL_RECEIVED));
    for (uint32_t k = 0; k < ng; k++) {
        mw_format_amount(g[k].amount, amt, sizeof(amt));
        snprintf(n, sizeof(n), TX(XSTR_TXL_OUTS), (unsigned)g[k].outs);
        TXL_ADD("%s+%s\n  %s%s%s%s%s\n", g[k].change ? "*" : g[k].notx ? "?" : " ", amt, n,
                g[k].spent ? ", " : "", g[k].spent ? TX(XSTR_TXL_SPENT) : "",
                g[k].change ? ", " : g[k].notx ? ", " : "",
                g[k].change ? TX(XSTR_TXL_CHANGE) : g[k].notx ? TX(XSTR_TXL_NOTX) : "");
    }
    if (nt) TXL_ADD("\n%s\n", TX(XSTR_TXL_SENT));
    for (uint32_t k = nt; k-- > 0; ) {                                 // newest first
        mw_ki_tx_t t;
        if (!mw_ki_cache_tx_get(k, &t)) continue;
        mw_format_amount(t.fee, fee, sizeof(fee));
        TXL_ADD("*");
        if (t.own_only) {
            TXL_ADD(TX(XSTR_BAL_TX_OWN), (unsigned)t.seq, fee);
        } else {
            mw_format_amount(t.sent, amt, sizeof(amt));
            TXL_ADD(TX(XSTR_BAL_TX_LINE), (unsigned)t.seq, amt, t.addr, fee);
        }
        TXL_ADD("\n");
    }
    if (else_n) {
        mw_format_amount(else_amt, amt, sizeof(amt));
        snprintf(n, sizeof(n), TX(XSTR_TXL_OUTS), (unsigned)else_n);
        TXL_ADD("\n%s\n?-%s\n  %s\n", TX(XSTR_TXL_ELSEWHERE), amt, n);
    }
    if (unknown) {
        TXL_ADD("\n");
        TXL_ADD(TX(XSTR_TXL_UNKNOWN), (unsigned)unknown);
        TXL_ADD("\n");
    }
#undef TXL_ADD
    big_free(g, (size_t)ne * sizeof(txl_group_t));
    mw_ui_text_view(TX(XSTR_BAL_TXS), text);
    big_free(text, cap);
}

// The balance of the open wallet: the estimate from the key image cache, or
// what the user typed in; the list of signed transactions.
static void wallet_balance(uint32_t id) {
    int focus = 0;
    for (;;) {
        if (lock_requested()) return;
        const wallet_entry_t* w = mw_wallet_get(id);
        const bool manual = w && (w->bal_flags & MW_BAL_MANUAL);
        char amt[32], sub[256];
        uint64_t total = 0;
        uint32_t outs = 0, unknown = 0;
        (void)mw_ki_cache_balance(&total, &outs, &unknown);
        if (manual) {
            mw_format_amount(w->bal_manual, amt, sizeof(amt));
            snprintf(sub, sizeof(sub), TX(XSTR_BAL_MANUAL), amt);
        } else if (!outs && !unknown) {
            snprintf(sub, sizeof(sub), "%s", TX(XSTR_BAL_NONE));
        } else {
            mw_format_amount(total, amt, sizeof(amt));
            snprintf(sub, sizeof(sub), TX(XSTR_BAL_EST), amt, (unsigned)outs);
            if (unknown) {
                const size_t u = strlen(sub);
                snprintf(sub + u, sizeof(sub) - u, "\n");
                snprintf(sub + u + 1, sizeof(sub) - u - 1, TX(XSTR_BAL_UNKNOWN), (unsigned)unknown);
            }
        }
        const char* items[3] = { TX(XSTR_BAL_TXS), TX(XSTR_BAL_SET), TX(XSTR_BAL_CLEAR) };
        const char* icons[3] = { LV_SYMBOL_LIST, LV_SYMBOL_EDIT, LV_SYMBOL_REFRESH };
        mw_menu_t m;
        memset(&m, 0, sizeof(m));
        m.title = TX(XSTR_WL_BALANCE);
        m.subtitle = sub;
        m.items = items;
        m.icons = icons;
        m.count = manual ? 3 : 2;
        m.initial = focus;
        m.back = true;
        m.with_status = true;
        const int r = mw_ui_menu_run(&m);
        if (r < 0) return;
        focus = r;
        if (r == 0) {
            show_signed_txs();
        } else if (r == 1) {
            char in[32];
            memset(in, 0, sizeof(in));
            if (ask_text(TX(XSTR_BAL_ENTER), in, sizeof(in)) != MW_OK || !in[0]) continue;
            uint64_t v = 0;
            if (!parse_xmr(in, &v)) { mw_ui_message(T(STR_ERR_GENERIC), TX(XSTR_BAL_BAD)); continue; }
            const mw_err_t e = mw_wallet_set_manual_balance(id, true, v);
            if (e != MW_OK) ui_err(e);
        } else {
            const mw_err_t e = mw_wallet_set_manual_balance(id, false, 0);
            if (e != MW_OK) ui_err(e);
        }
    }
}

// Shows the hint (if any) and asks for a new one; empty clears it.
static void edit_pp_hint(uint32_t id) {
    char cur[MW_PP_HINT_LEN], hint[MW_PP_HINT_LEN + 8];
    if (mw_wallet_pp_hint(id, cur, sizeof(cur)) != MW_OK) cur[0] = 0;
    if (cur[0]) {
        char msg[MW_PP_HINT_LEN + 96];
        snprintf(msg, sizeof(msg), "%s:\n%s", TX(XSTR_PP_HINT), cur);
        mw_ui_message(TX(XSTR_PP_HINT), msg);
        mw_memzero(msg, sizeof(msg));
    }
    if (ask_pp_hint(hint, sizeof(hint))) {          // cancel keeps the old one
        const mw_err_t e = mw_wallet_set_pp_hint(id, hint);
        if (e == MW_OK) mw_ui_message_timeout(T(STR_SUCCESS), TX(XSTR_SETTINGS_SAVED), 1500);
        else            mw_ui_message(T(STR_ERR_GENERIC), mw_err_str(e));
    }
    mw_memzero(cur, sizeof(cur));
    mw_memzero(hint, sizeof(hint));
}

static bool open_wallet_pp(uint32_t id, mw_account_keys_t* keys);

// The open wallet. Returns true when the user opened its passphrase wallet
// ("Open passphrase"): `keys` then holds that wallet and the caller opens it
// as variant 1; false when the wallet was closed.
static bool wallet_home(uint32_t id, mw_account_keys_t* keys, uint8_t variant) {
    bool reopen_pp = false;
    const wallet_entry_t* w = mw_wallet_get(id);
    memset(&s_open, 0, sizeof(s_open));
    s_open.open = true;
    s_open.id = id;
    s_open.variant = variant;
    s_open.restore_height = w ? w->restore_height : 0;
    snprintf(s_open.name, sizeof(s_open.name), "%s", w ? w->name : "");

    // Reading and opening the account's container (64 KiB and up).
    mw_ui_progress(s_open.name, 500, TX(XSTR_KI_LOADING));
    const uint32_t t0 = mw_millis();
    const mw_err_t ke = mw_ki_cache_open(id, variant, keys);
    MW_LOGD("wallet", "key image cache loaded in %u ms", (unsigned)(mw_millis() - t0));
    mw_ui_progress_close();
    if (ke != MW_OK) {
        MW_LOGE("wallet", "key image cache unavailable");
    } else if (mw_ki_cache_rolled_back()) {
        mw_ui_message(T(STR_ERR_GENERIC), TX(XSTR_KI_ROLLBACK));
    }
    // Leftovers from before the wallet was open are not for this wallet.
    for (int k = 0; k < MW_FILE_KIND_COUNT; ++k) mw_link_inbox_clear((mw_file_kind_id_t)k);
    (void)mw_link_request_take();
    link_state(MW_LINK_STATE_WALLET);
    MW_LOGI("wallet", "wallet '%s' open, %u known key images: ready for files",
            s_open.name, (unsigned)mw_ki_cache_count());

    enum { WA_ADDR = 0, WA_ADDR_QR, WA_BALANCE, WA_VK, WA_VK_QR, WA_SD, WA_SD_VK,
           WA_OPEN_PP, WA_RENAME, WA_PP_HINT, WA_NETWORK, WA_CHECK_SEED, WA_DELETE, WA_COUNT };
    // SD card files only on boards with a card slot.
    const bool with_sd = mw_hal_caps()->has_sd;
    int focus = 0;
    for (;;) {
        if (lock_requested()) break;
        const uint32_t seq = mw_ui_wake_seq();
        if (handle_pending(keys)) continue;
        if (lock_requested()) break;

        char net_item[48];
        snprintf(net_item, sizeof(net_item), TX(XSTR_WL_NETWORK), net_label(active_network()));
        const char* all_items[WA_COUNT] = {
            TX(XSTR_WL_ADDR_TEXT), TX(XSTR_WL_ADDR_QR), TX(XSTR_WL_BALANCE), TX(XSTR_WL_VK_TEXT),
            TX(XSTR_WL_VK_QR), TX(XSTR_WL_SD), TX(XSTR_WL_SD_VK), TX(XSTR_WL_OPEN_PP),
            TX(XSTR_WL_RENAME), TX(XSTR_PP_HINT), net_item, TX(XSTR_CHECK_SEED),
            T(STR_WALLET_DELETE)
        };
        const char* all_icons[WA_COUNT] = {
            LV_SYMBOL_HOME, LV_SYMBOL_IMAGE, LV_SYMBOL_LIST, LV_SYMBOL_EYE_OPEN, LV_SYMBOL_IMAGE,
            LV_SYMBOL_SD_CARD, LV_SYMBOL_SAVE, LV_SYMBOL_KEYBOARD, LV_SYMBOL_EDIT,
            LV_SYMBOL_KEYBOARD, LV_SYMBOL_SHUFFLE, LV_SYMBOL_OK, LV_SYMBOL_TRASH
        };
        const wallet_entry_t* we = mw_wallet_get(id);
        const bool has_seed = we && (we->wallet_type == MW_SEED_MONERO_LEGACY ||
                                     we->wallet_type == MW_SEED_POLYSEED);
        const bool balance_on = !(mw_wallet_store_opts() & MW_ACC_OPT_NO_BALANCE);
        // Menu position -> action, skipping what this board does not have.
        const char* items[WA_COUNT];
        const char* icons[WA_COUNT];
        bool        danger[WA_COUNT];
        int         action[WA_COUNT];
        int         shown = 0;
        for (int a = 0; a < WA_COUNT; a++) {
            if ((a == WA_SD || a == WA_SD_VK) && !with_sd) continue;
            // A view-only record without the key has nothing to export.
            if (a == WA_SD_VK && mw_sc_is_zero(&keys->sec.view)) continue;
            // 0.3.5: "Open passphrase" in EVERY wallet (nothing shows whether
            // one exists), only from the session without a passphrase; the
            // hint can be set on every wallet too.
            if (a == WA_OPEN_PP && variant != 0) continue;
            if (a == WA_CHECK_SEED && !has_seed) continue;
            if (a == WA_BALANCE && !balance_on) continue;
            items[shown]  = all_items[a];
            icons[shown]  = all_icons[a];
            danger[shown] = (a == WA_DELETE);
            action[shown] = a;
            shown++;
        }
        // The passphrase mark only inside a passphrase session.
        char sub[96];
        snprintf(sub, sizeof(sub), "%s%s%s%s",
                 variant ? TX(XSTR_WL_VARIANT_PP) : "",
                 keys->view_only ? (variant ? " / view-only" : "view-only") : "",
                 (variant || keys->view_only) ? "\n" : "",
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
        case WA_SD_VK:   sd_export_view_key(keys); break;
        case WA_OPEN_PP: {
            mw_account_keys_t pk;
            memset(&pk, 0, sizeof(pk));
            if (open_wallet_pp(id, &pk)) {
                *keys = pk;
                reopen_pp = true;
            }
            mw_memzero(&pk, sizeof(pk));
            break;
        }
        case WA_RENAME:  rename_wallet(id); break;
        case WA_PP_HINT: edit_pp_hint(id); break;
        case WA_BALANCE: wallet_balance(id); break;
        case WA_NETWORK: change_network(id); break;
        case WA_CHECK_SEED: check_seed(id); break;
        case WA_DELETE:
            if (delete_wallet(id)) goto closed;
            break;
        default: break;
        }
        if (reopen_pp) break;
    }
    if (mw_ki_cache_dirty()) {
        mw_ui_progress(s_open.name, 1000, TX(XSTR_SAVING));
        (void)mw_ki_cache_save();
        mw_ui_progress_close();
    }
closed:
    mw_ki_cache_close();
    memset(&s_open, 0, sizeof(s_open));
    link_state(lock_requested() ? MW_LINK_STATE_LOCKED : MW_LINK_STATE_MENU);
    MW_LOGI("wallet", "wallet closed");
    return reopen_pp && !lock_requested();
}

// Opens a wallet: always the wallet without a passphrase (0.3.5) - nothing
// is asked and nothing shows whether the record has a passphrase wallet.
static bool open_wallet(uint32_t id, mw_account_keys_t* keys, uint8_t* variant) {
    bool verified = false;
    const mw_err_t e = mw_wallet_open(id, "", keys, &verified);
    if (e != MW_OK) {
        ui_err(e);
        return false;
    }
    *variant = 0;
    return true;
}

// "Open passphrase" (0.3.5): the same screen, the same work (~1 s and more,
// MW_PP_KDF_ROUNDS) and the same "wrong passphrase" for every wallet; only
// the right passphrase of a wallet that has one opens its passphrase wallet.
static bool open_wallet_pp(uint32_t id, mw_account_keys_t* keys) {
    const wallet_entry_t* w = mw_wallet_get(id);
    char name[WALLET_NAME_LEN];
    char pass[MW_PASSPHRASE_MAX];
    snprintf(name, sizeof(name), "%s", w ? w->name : "");
    memset(pass, 0, sizeof(pass));
    {
        char hint[MW_PP_HINT_LEN];
        if (mw_wallet_pp_hint(id, hint, sizeof(hint)) != MW_OK) hint[0] = 0;
        if (hint[0]) {
            char msg[MW_PP_HINT_LEN + 96];
            snprintf(msg, sizeof(msg), TX(XSTR_PP_HINT_SHOW), hint);
            mw_ui_message(name, msg);                 // stays until tapped
            mw_memzero(msg, sizeof(msg));
        }
        mw_memzero(hint, sizeof(hint));
    }
    if (mw_screen_passphrase_open_run(name, pass, sizeof(pass)) != MW_OK) {
        mw_memzero(pass, sizeof(pass));
        return false;
    }
    slow_progress_t sp;
    slow_progress_begin_pp(&sp, TX(XSTR_WALLET_UNLOCK));
    const mw_err_t e = mw_wallet_open_pp(id, pass, keys);
    slow_progress_end();
    mw_memzero(pass, sizeof(pass));
    mw_session_wipe_input();
    if (e == MW_ERR_DECRYPT) {
        mw_ui_message(T(STR_ERR_GENERIC), TX(XSTR_PP_WRONG));
        return false;
    }
    if (e != MW_OK) {
        ui_err(e);
        return false;
    }
    return true;
}

// ===========================================================================
//  Wallet list
// ===========================================================================
static void wallets_menu(void) {
    int focus = 0;
    for (;;) {
        if (lock_requested()) return;
        // Off the crypto task stack: up to 64 wallets (the directory copy in
        // PSRAM, the short lists static).
        static uint32_t ids[MAX_WALLETS];
        static char     labels[MAX_WALLETS][WALLET_NAME_LEN + 8];
        static const char* items[MAX_WALLETS + 2];
        static const char* icons[MAX_WALLETS + 2];
        int n = 0;

        wallet_store_t* store = (wallet_store_t*)big_alloc(sizeof(wallet_store_t));
        if (store && mw_wallet_store_load(store) == MW_OK) {
            for (uint32_t i = 0; i < store->count && n < MAX_WALLETS; i++) {
                const wallet_entry_t* w = &store->wallets[i];
                if (w->is_hidden) continue;
                snprintf(labels[n], sizeof(labels[n]), "%s", w->name);
                ids[n] = w->id;
                items[n] = labels[n];
                icons[n] = LV_SYMBOL_DIRECTORY;
                n++;
            }
        }
        big_free(store, sizeof(wallet_store_t));
        const int n_wallets = n;
        items[n] = T(STR_WALLET_CREATE); icons[n] = LV_SYMBOL_PLUS;     n++;
        items[n] = T(STR_WALLET_IMPORT); icons[n] = LV_SYMBOL_DOWNLOAD; n++;

        mw_menu_t m;
        memset(&m, 0, sizeof(m));
        m.title = T(STR_MAIN_WALLETS);
        m.subtitle = n_wallets ? NULL : TX(XSTR_WALLET_EMPTY);
        m.items = items;
        m.icons = icons;
        m.count = n;
        m.initial = focus;
        m.back = true;
        m.with_status = true;
        const int r = mw_ui_menu_run(&m);
        // The names stay in RAM no longer than the list is on screen.
        mw_memzero(labels, sizeof(labels));
        if (r < 0) return;
        focus = r;

        if (r < n_wallets) {
            mw_account_keys_t keys;
            uint8_t variant = 0;
            memset(&keys, 0, sizeof(keys));
            if (open_wallet(ids[r], &keys, &variant)) {
                mw_wallet_set_active(ids[r]);
                // "Open passphrase" closes the session and opens the
                // passphrase wallet of the same record.
                while (wallet_home(ids[r], &keys, variant)) variant = 1;
                // 0.3.6: back on the wallet just closed (the menu clamps
                // the row when it was deleted).
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
        // The account's name under the title (only this account's own).
        static char account[MW_ACCOUNT_NAME_LEN];
        if (mw_wallet_store_account_name(account, sizeof(account)) != MW_OK) account[0] = 0;
        mw_menu_t m;
        memset(&m, 0, sizeof(m));
        m.title = TX(XSTR_APP_NAME);
        m.subtitle = account[0] ? account : NULL;
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

extern "C" mw_err_t mw_usb_link_init(void);
extern "C" bool     mw_usb_link_running(void);
extern "C" void     mw_usb_link_bus(bool on);
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
#if defined(ARDUINO) && !defined(MW_HOST_BUILD)
    // 0.3.6: off the USB bus while locked. A moment first, so the program on
    // the PC still gets the "locked" state.
    mw_delay_ms(150);
    mw_usb_link_bus(false);
#endif
}

// USB comes up only after a correct device password (user request: no USB
// link while the device is locked). Started at the first unlock; a lock
// takes the device off the bus (lock_device) and the next unlock puts it back.
static void ensure_usb_link(void) {
#if defined(ARDUINO) && !defined(MW_HOST_BUILD)
    if (mw_usb_link_running()) {
        mw_usb_link_bus(true);
        return;
    }
    const mw_err_t e = mw_usb_link_init();
    MW_LOGI("shell", "usb link started after unlock -> %s", mw_err_str(e));
#endif
}

// The very first step after the game, before the device password: the device
// does not work without its eFuse key (nothing is sealed without it). The key
// goes into the highest free key block; declining returns to the game.
static bool efuse_gate(void) {
    if (mw_secure_key_status() == MW_OK) return true;
    MW_LOGI("boot", "no eFuse key: offering to provision it");
    if (mw_secure_key_target_block() >= 0)
        mw_ui_message(TX(XSTR_EFUSE_PROVISION), TX(XSTR_EFUSE_FIRST));
    return mw_screen_efuse_provision_run();
}

// Progress of the one-off storage conversion (FAT -> LittleFS, v0.3).
static void fs_progress(int permille) {
    mw_ui_progress(TX(XSTR_FS_CONVERT), permille, TX(XSTR_FS_CONVERT_NOTE));
}

// Firmware before 0.3 left the storage as FAT: the slots beyond the current
// count go first (less to copy), the files are read into PSRAM and checked,
// and after the user's confirmation the partition becomes LittleFS.
static void convert_storage(void) {
    MW_LOGI("boot", "converting the storage to LittleFS");
    fs_progress(0);
    (void)mw_wallet_store_decoys_ensure();
    mw_fstore_mig_info_t info;
    mw_err_t e = mw_fstore_migrate_prepare(&info);
    mw_ui_progress_close();
    char msg[256];
    if (e != MW_OK) {
        MW_LOGE("boot", "storage conversion not possible: %s", mw_err_str(e));
        snprintf(msg, sizeof(msg), TX(XSTR_FS_CONVERT_FAIL), mw_err_str(e),
                 (unsigned)info.files, (unsigned)((info.bytes + 1023u) / 1024u));
        mw_ui_message(T(STR_ERR_GENERIC), msg);
        return;
    }
    snprintf(msg, sizeof(msg), TX(XSTR_FS_CONVERT_Q), (unsigned)info.files,
             (unsigned)((info.bytes + 1023u) / 1024u));
    if (!mw_ui_confirm_code(TX(XSTR_FS_CONVERT), msg)) {
        mw_fstore_migrate_abort();
        mw_ui_message(TX(XSTR_FS_CONVERT), TX(XSTR_FS_LATER));
        return;
    }
    fs_progress(450);
    e = mw_fstore_migrate_commit();
    mw_ui_progress_close();
    if (e != MW_OK) {
        MW_LOGE("boot", "storage conversion failed after the erase: %s", mw_err_str(e));
        mw_ui_message(T(STR_ERR_GENERIC), TX(XSTR_FS_LOST));
    }
}

extern "C" void mw_shell_run(void) {
    const mw_ops_alloc_t a = { ops_alloc, ops_free };
    mw_ops_set_allocator(&a);
    mw_fstore_set_progress(fs_progress);
    (void)mw_fstore_init();                   // may finish an interrupted conversion
    // A factory reset or wipe cut short by a power loss: finished first.
    if (mw_store_blob_exists(WIPE_MARK) == 1) mw_shell_wipe_device();
    // The wipe after MW_PW_WIPE_AT wrong passwords; also finishes one a
    // power cut interrupted.
    mw_device_auth_set_wipe_hook(mw_shell_wipe_device);
    mw_device_auth_wipe_check();
    if (mw_fstore_migration_lost()) mw_ui_message(T(STR_ERR_GENERIC), TX(XSTR_FS_LOST));
    if (mw_fstore_on_fat()) convert_storage();
    mw_fstore_set_progress(NULL);

    for (;;) {
        link_state(MW_LINK_STATE_LOCKED);
        mw_ui_show(MW_SCREEN_MAIN_MENU);          // neutral background
        // Settings -> Minesweeper: the game as a disguise, left only by the
        // gesture. Off (the default): straight to the password screen.
        if (mw_ui_settings()->game) mw_screen_game_run();
        if (!efuse_gate()) continue;
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
