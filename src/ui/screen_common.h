// ---------------------------------------------------------------------------
//  Shared UI internals: cross-task plumbing, the page frame, the status bar,
//  the message/progress/list helpers and every screen entry point.
//
//  THREADING (see the header comment of lvgl_port.cpp for the full rule):
//    * Everything named mw_screen_*_build / mw_ui_page_* / any lv_* call runs
//      ONLY on the LVGL task.
//    * Everything named mw_screen_*_run and every mw_ui_* helper below is safe
//      to call from the crypto task; it marshals the work onto the LVGL task.
//
//  i18n.c includes this header with MW_UI_STRINGS_ONLY defined so it can see
//  the extended string table without pulling LVGL in.
// ---------------------------------------------------------------------------
#ifndef MW_UI_SCREEN_COMMON_H
#define MW_UI_SCREEN_COMMON_H

#include <stdint.h>
#include <stdbool.h>
#include <stddef.h>

#ifndef MW_UI_STRINGS_ONLY
#include "theme.h"
#include "ui.h"
#include "i18n.h"
#include "../hal/hal.h"
#include "../wallet/secure_storage.h"
#include "../monero/monero_types.h"
#include "../monero/tx.h"
#include "../config/app_config.h"
#endif

#ifdef __cplusplus
extern "C" {
#endif

// ===========================================================================
//  Extended string table
//
//  i18n.h is a frozen contract and its mw_str_id_t cannot grow, but the
//  screens need far more strings than it carries. They live in the same
//  RU/EN table in i18n.c and are reached with TX(...) instead of T(...).
//  No screen is allowed to hardcode a user-visible string.
// ===========================================================================
typedef enum {
    XSTR_APP_NAME = 0, XSTR_VERSION, XSTR_BOOT, XSTR_LOCKED,
    XSTR_YES, XSTR_NO, XSTR_OK, XSTR_CLOSE, XSTR_MENU, XSTR_PROCESSING,
    XSTR_ABORTED, XSTR_UNSUPPORTED,

    XSTR_WALLET_ACTIVE, XSTR_WALLET_NONE, XSTR_WALLET_EMPTY, XSTR_WALLET_NAME,
    XSTR_WALLET_DELETE_Q, XSTR_WALLET_DELETED, XSTR_WALLET_CREATED,
    XSTR_WALLET_FULL, XSTR_WALLET_UNLOCK, XSTR_WALLET_SELECTED,

    XSTR_CREATE_TITLE, XSTR_IMPORT_TITLE, XSTR_SEED_SOURCE_TITLE,
    XSTR_ENTROPY_SOURCE, XSTR_DICE_ROLLS, XSTR_DICE_UNDO, XSTR_DICE_BITS,
    XSTR_DICE_NEED_MORE,

    XSTR_SEED_WRITE_DOWN, XSTR_SEED_WRITTEN_Q, XSTR_SEED_PAGE,
    XSTR_VERIFY_PROMPT, XSTR_VERIFY_FAIL, XSTR_VERIFY_OK, XSTR_SEED_WORD_BAD,

    XSTR_PASSPHRASE_ENTER, XSTR_PASSPHRASE_HINT, XSTR_PASSPHRASE_EMPTY_Q,
    XSTR_PASSPHRASE_OK,

    XSTR_ADDRESS, XSTR_SHOW_QR, XSTR_RESTORE_HEIGHT_HINT,

    XSTR_CHANNEL, XSTR_CHANNEL_SD, XSTR_CHANNEL_QR,
    XSTR_WAITING_FILE,

    XSTR_TX_CHANGE, XSTR_TX_TOTAL, XSTR_TX_FULL_ADDR, XSTR_TX_UNLOCK_TIME,
    XSTR_TX_SIGNED, XSTR_TX_BALANCE_FAIL, XSTR_TX_RECIPIENT,

    XSTR_KI_PROCESSED, XSTR_KI_ERRORS,

    XSTR_QR_PART, XSTR_QR_PAUSE, XSTR_QR_RESUME, XSTR_SCAN_TITLE,
    XSTR_SCAN_HINT, XSTR_NO_CAMERA, XSTR_NO_QRCODE,

    XSTR_KB_FULL, XSTR_KB_SCROLL, XSTR_LETTERS, XSTR_SHIFT, XSTR_DIGITS,
    XSTR_SYMBOLS, XSTR_SPACE,

    XSTR_SETTINGS_LANG, XSTR_SETTINGS_NETWORK, XSTR_SETTINGS_ABOUT,
    XSTR_SETTINGS_SAVED, XSTR_FORMAT_SD_Q, XSTR_CALIB_PROMPT, XSTR_CALIB_DONE,
    XSTR_MINUTES, XSTR_NET_MAIN, XSTR_NET_TEST, XSTR_NET_STAGE,
    XSTR_LANG_RU, XSTR_LANG_EN, XSTR_EFUSE_MISSING,

    // eFuse provisioning (TZ 8.1) - the one-shot, irreversible key burn.
    XSTR_EFUSE_PROVISION, XSTR_EFUSE_WARN1, XSTR_EFUSE_WARN2,
    XSTR_EFUSE_DONE, XSTR_EFUSE_NEEDED,

    // TZ 12.4: the unsigned set carries more than one transaction.
    XSTR_TX_MULTI,
    // TZ 11.3: one line per failed key-image record.
    XSTR_KI_FAIL_ITEM,
    // TZ 5.9: the input buffer is full and the key was refused.
    XSTR_INPUT_LIMIT,
    // TZ 5.8: the phrase failed its checksum; this word is the suspect.
    XSTR_SEED_FIX_WORD,
    // TZ 4.2: import from raw spend/view keys.
    XSTR_IMPORT_KEYS, XSTR_KEY_SPEND_SEC, XSTR_KEY_VIEW_SEC,
    XSTR_KEY_SPEND_PUB, XSTR_KEY_HEX_BAD, XSTR_KEY_VIEW_ONLY,

    // TZ 2.0 stage 1: the CDC/HID link driven by the host program.
    XSTR_CHANNEL_LINK, XSTR_LINK_WAIT_HINT, XSTR_LINK_READY,

    // task2 item 4 / 7: keyboard layout and the input line captions.
    XSTR_KB_LAYOUT, XSTR_KB_QWERTY, XSTR_KB_ABC, XSTR_WORD_START, XSTR_INPUT,
    // task2 item 3: debug log toggle.
    XSTR_DEBUG_LOG, XSTR_ON, XSTR_OFF,
    // task2 item 6: typed-number confirmation of critical actions.
    XSTR_CODE_TITLE, XSTR_CODE_PROMPT, XSTR_CODE_ENTER, XSTR_CODE_WRONG,
    // task2 item 1: device password.
    XSTR_PW_TITLE, XSTR_PW_SET_HINT, XSTR_PW_ENTER, XSTR_PW_REPEAT,
    XSTR_PW_MISMATCH, XSTR_PW_WRONG, XSTR_PW_LOCKED, XSTR_PW_RULES,
    XSTR_PW_CHANGE, XSTR_PW_OLD, XSTR_PW_NEW, XSTR_PW_CHANGED, XSTR_PW_REQUIRED,
    // task2 item 5: per-wallet actions.
    XSTR_WL_SET_ACTIVE, XSTR_WL_SHOW_ADDR, XSTR_WL_SHOW_VIEWKEY,
    XSTR_VIEWKEY_TITLE, XSTR_VIEWKEY_WARN,

    // task 3: game, shell, wallet menu, files and requests from the PC.
    XSTR_GAME_TITLE, XSTR_GAME_WON, XSTR_GAME_LOST, XSTR_GAME_MINES,
    XSTR_MAIN_LOCK,
    XSTR_WL_ADDR_TEXT, XSTR_WL_ADDR_QR, XSTR_WL_VK_TEXT, XSTR_WL_VK_QR,
    XSTR_WL_RENAME, XSTR_WL_RENAMED, XSTR_WL_CLOSE, XSTR_WL_VARIANT_BASE,
    XSTR_WL_VARIANT_PP, XSTR_WL_READY, XSTR_WL_NO_LINK, XSTR_WL_PP_MARK,
    XSTR_PP_OPEN_HINT, XSTR_PP_WRONG, XSTR_PP_UNVERIFIED,
    XSTR_FILE_ERROR, XSTR_KI_REFUSED, XSTR_KI_CONFIRM, XSTR_KI_DONE,
    XSTR_TX_REFUSED, XSTR_TX_SPENT_WARN, XSTR_TX_OF, XSTR_TX_DONE,
    XSTR_REQ_ADDR_Q, XSTR_REQ_VK_Q, XSTR_REQ_SENT, XSTR_REQ_DENIED,

    // v5:change (ids of the change package; keep inside this block)
    XSTR_TX_CHANGE_ROW, XSTR_TX_CHANGE_NONE, XSTR_TX_CHANGE_ADDR, XSTR_TX_OWNED_BY,
    XSTR_TX_OWN_MARK, XSTR_TX_DUMMY, XSTR_TX_IN_OUT, XSTR_TX_HIGH_FEE_TITLE,
    XSTR_TX_HIGH_FEE_BODY,
    // end v5:change

    // v5:auth (ids of the auth package; keep inside this block)
    XSTR_PW_FAILED_SINCE, XSTR_PW_CHECKING, XSTR_PW_EMPTY,
    // end v5:auth

    // v5:touch (ids of the touch package; keep inside this block)
    XSTR_TOUCH_TEST, XSTR_TOUCH_TEST_HINT, XSTR_TOUCH_TEST_WAIT, XSTR_CALIB_FAILED,
    // end v5:touch

    // v5:ui (ids of the ui package; keep inside this block)
    // end v5:ui

    // v5:game (ids of the game package; keep inside this block)
    // end v5:game

    // v5:crash (ids of the crash package; keep inside this block)
    XSTR_LAST_CRASH,
    // end v5:crash

    // v6 (ColdPunk audit fixes; keep inside this block)
    XSTR_PW_CORRUPT,
    XSTR_DICE_MIXED,
    XSTR_BIRTH_MONTH,
    XSTR_BIRTH_MONTH_BAD,
    XSTR_KI_CACHE_FULL,
    XSTR_KI_ROLLBACK,
    XSTR_PW_STAGE_CHECK,
    XSTR_PW_STAGE_UPGRADE,
    XSTR_PW_STAGE_NEW,
    XSTR_PW_STAGE_REKEY,
    // end v6

    XSTR_COUNT
} mw_xstr_id_t;

const char* mw_strx(mw_xstr_id_t id);
#define TX(id) mw_strx(id)

#ifndef MW_UI_STRINGS_ONLY

// ===========================================================================
//  Cross-task plumbing (lvgl_port.cpp)
// ===========================================================================
typedef void (*mw_ui_job_fn)(void* arg);

// True when the caller is the task that owns LVGL.
bool mw_ui_is_ui_task(void);

// Runs fn(arg) on the LVGL task and returns once it has returned.
void mw_ui_sync_call(mw_ui_job_fn fn, void* arg);

// Runs fn(arg) on the LVGL task and returns immediately. `arg` must stay
// valid until the job has run (use a static buffer).
void mw_ui_async_call(mw_ui_job_fn fn, void* arg);

// Runs fn(arg) on the LVGL task and blocks until something on that task calls
// mw_ui_modal_done(). Returns the value passed to mw_ui_modal_done().
int32_t mw_ui_modal_call(mw_ui_job_fn fn, void* arg);
void    mw_ui_modal_done(int32_t result);

// Recursive LVGL lock. The LVGL task holds it while pumping timers; anything
// that has to touch LVGL outside a job must take it.
void mw_ui_lock(void);
void mw_ui_unlock(void);

// Starts the LVGL task itself. The reference firmware creates its own task and
// calls mw_ui_tick() instead, so this is only for host/bring-up sketches.
void mw_ui_task_start(void);

// ===========================================================================
//  Physical buttons (TZ 2.5 / 5.6)
//
//  By default lvgl_port feeds the keypad indev so lv_group navigation works on
//  every screen. A screen that needs raw 2-D navigation (both keyboards)
//  installs a hook; while a hook is installed the indev is fed nothing and the
//  hook sees every edge, including the long-press timings of TZ 5.6.
// ===========================================================================
typedef bool (*mw_ui_btn_hook_t)(mw_button_t btn, uint32_t hold_ms,
                                 bool released, void* user);
void mw_ui_set_button_hook(mw_ui_btn_hook_t hook, void* user);

// Long-press thresholds of TZ 5.6.
#define MW_BACK_LONG_MS      600
#define MW_BACK_VERY_LONG_MS 2000

// Binds `g` to the keypad indev (no-op on touch-only boards).
void        mw_ui_group_activate(lv_group_t* g);
lv_group_t* mw_ui_group_current(void);

// ===========================================================================
//  Settings cache
// ===========================================================================
const mw_settings_t* mw_ui_settings(void);
void                 mw_ui_settings_reload(void);
mw_err_t             mw_ui_settings_store(const mw_settings_t* s);

// ===========================================================================
//  Per-screen focus memory
//
//  Every list screen remembers the row the user was on when they left it, so
//  Back returns the cursor there instead of the first row. The builder calls
//  mw_ui_focus_restore(slot) before laying out its rows, and the click handler
//  calls mw_ui_focus_remember(slot, index) before it hands control back.
// ===========================================================================
typedef enum {
    MW_FOCUS_MAIN = 0,   // main menu
    MW_FOCUS_WALLETS,    // wallet list
    MW_FOCUS_SETTINGS,   // settings list
    MW_FOCUS_TX,         // tx review: recipient rows
    MW_FOCUS_KI,         // key-image screen (reserved)
    MW_FOCUS_CHOOSE,     // generic chooser
    MW_FOCUS_COUNT
} mw_focus_slot_t;

void mw_ui_focus_remember(mw_focus_slot_t slot, int index);
int  mw_ui_focus_restore (mw_focus_slot_t slot);

// ===========================================================================
//  Page frame (LVGL task only)
//
//  TZ memory rule: at most two LVGL screens exist at any moment - the root
//  screen loaded by mw_ui_show() and at most one page on top of it. Every
//  mw_screen_*_run() creates its page, waits, and destroys it before
//  returning, so pages never nest.
// ===========================================================================
typedef struct mw_page mw_page_t;
struct mw_page {
    lv_obj_t*   scr;        // the screen (page) or the overlay root
    lv_obj_t*   prev;       // screen to restore; NULL for an overlay
    lv_obj_t*   status;     // NULL when the tier is compact or with_status=false
    lv_obj_t*   title;
    lv_obj_t*   body;       // put content here
    lv_obj_t*   footer;     // created lazily by mw_ui_page_footer()
    lv_group_t* group;      // focus group for button boards
    lv_group_t* prev_group; // group to restore on destroy
    bool        overlay;
    void      (*on_escape)(void* user);   // hardware Back / LV_KEY_ESC
    void*       escape_user;
};

// A full new screen. At most one page may be alive on top of the root screen.
void      mw_ui_page_create(mw_page_t* p, const char* title, bool with_status);
// A full-screen container on top of whatever is already displayed. Overlays
// nest safely and do not count as a second screen.
void      mw_ui_overlay_create(mw_page_t* p, const char* title);
void      mw_ui_page_destroy(mw_page_t* p);      // idempotent
lv_obj_t* mw_ui_page_footer(mw_page_t* p);       // bottom row, horizontal
void      mw_ui_focus_add(mw_page_t* p, lv_obj_t* obj);
void      mw_ui_page_set_escape(mw_page_t* p, void (*cb)(void*), void* user);
// Tears down the page currently on top of the root screen, if any, and
// releases the crypto task that was waiting on it with a "cancelled" result.
void      mw_ui_page_cancel_active(void);

// ===========================================================================
//  Widget helpers (LVGL task only)
// ===========================================================================
lv_obj_t* mw_ui_label(lv_obj_t* parent, const char* text, lv_style_t* style);
lv_obj_t* mw_ui_button(lv_obj_t* parent, const char* text,
                       lv_event_cb_t cb, void* user);
lv_obj_t* mw_ui_list(lv_obj_t* parent);
lv_obj_t* mw_ui_list_row(lv_obj_t* list, const char* icon, const char* text,
                         lv_event_cb_t cb, void* user);
lv_obj_t* mw_ui_bar(lv_obj_t* parent);
// Height a flex-grow child of the flex COLUMN `column` would get right now:
// lays the screen out with a temporary probe and deletes it again. Lets a
// page size fixed content from the room the rest of the page leaves.
lv_coord_t mw_ui_free_height(lv_obj_t* column);

// Status bar (TZ 4.2): battery / SD / USB. Created by the page frame.
lv_obj_t* mw_ui_status_bar(lv_obj_t* parent);
void      mw_ui_status_apply(void);   // repaints every live status bar
// Latest values published by mw_ui_set_status() (lvgl_port.cpp).
void      mw_ui_status_values(int* battery_percent, bool* sd, bool* usb);

// ===========================================================================
//  Blocking modals - safe from any task
// ===========================================================================
// Simple single-choice list. Returns the index, or -1 when cancelled.
int  mw_ui_choose(const char* title, const char* const* items, int count,
                  int initial);
// Full-screen scrollable read-only text (used for the full address, TZ 12.3).
void mw_ui_text_view(const char* title, const char* text);
// Closes the progress page opened by mw_ui_progress().
void mw_ui_progress_close(void);
// Optional Cancel on the progress page. Call mw_ui_progress_cancellable(true)
// BEFORE mw_ui_progress() opens the page: it adds a Cancel button and binds
// hardware Back to it, and resets the cancelled flag. Long waits (a file
// over the USB link) poll mw_ui_progress_cancelled() and give up when it is
// set. The flag is cleared again by mw_ui_progress_cancellable(false) or by
// the next mw_ui_progress_cancellable(true).
void mw_ui_progress_cancellable(bool on);
bool mw_ui_progress_cancelled(void);

// Message dialog. mw_ui_message() blocks until the user dismisses it.
// mw_ui_message_timeout() dismisses itself after timeout_ms milliseconds
// (timeout_ms = 0 falls back to the blocking form).
void mw_ui_message(const char* title, const char* body);
void mw_ui_message_timeout(const char* title, const char* body,
                           uint32_t timeout_ms);

// ---- modal cancellation (task 3: autolock) ---------------------------------
// A modal builder (LVGL task) registers how to close itself as "cancelled";
// mw_ui_modal_done() clears the registration. mw_ui_cancel_modal() (LVGL
// task) closes whatever modal is open, falling back to the active page.
typedef void (*mw_ui_cancel_fn)(void);
void mw_ui_modal_set_cancel(mw_ui_cancel_fn fn);
void mw_ui_modal_clear_cancel(void);
void mw_ui_cancel_modal(void);

// ---- wake signal (task 3: files from the PC while a menu is open) ----------
// Any task may call mw_ui_wake(); a menu run with `wake` set returns
// MW_MENU_WAKE once the sequence number differs from `wake_seq`.
void     mw_ui_wake(void);
uint32_t mw_ui_wake_seq(void);

// ---- generic menu page (screen_menu.cpp) -----------------------------------
#define MW_MENU_BACK  (-1)
#define MW_MENU_WAKE  (-2)
#define MW_MENU_MAX   12

typedef struct {
    const char*        title;
    const char*        subtitle;       // dim text above the list, may be NULL
    const char*        footnote;       // dim text below the list, may be NULL
    const char* const* items;
    const char* const* icons;          // LV_SYMBOL_*, may be NULL
    const bool*        danger;         // per item, may be NULL
    int                count;
    int                initial;        // focused row
    bool               back;           // Back button + hardware Back
    const char*        back_label;     // default: "Back"
    bool               wake;           // return MW_MENU_WAKE on mw_ui_wake()
    uint32_t           wake_seq;       // mw_ui_wake_seq() read BEFORE the
                                       // caller looked for pending events
    bool               with_status;
} mw_menu_t;

// Blocking: index of the chosen row, MW_MENU_BACK or MW_MENU_WAKE.
int mw_ui_menu_run(const mw_menu_t* m);

// ===========================================================================
//  Screen entry points
// ===========================================================================
// --- screen_main.cpp (LVGL task) ---
void mw_screen_main_build(lv_obj_t* scr);
void mw_screen_boot_build(lv_obj_t* scr);

// --- screen_seed.cpp ---
#define MW_DICE_TARGET_ROLLS MW_DICE_ROLLS_REQUIRED   // TZ 6.4: 100 d6 ~ 258 bits
#define MW_DICE_MAX_ROLLS    160
bool mw_screen_seed_display_run(const char* const* words, int n);
bool mw_screen_seed_verify_run(const char* const* words, int n,
                               mw_kb_mode_t mode);
bool mw_screen_dice_run(uint8_t* rolls, int max_rolls, int* n_out);

// --- screen_game.cpp (task 3 item 7) ---
// Minesweeper shown at power-on and after every lock. Returns only when the
// user taps the exploded mine three times in a row (within 2 seconds).
void mw_screen_game_run(void);

// --- screen_passphrase.cpp (task 3 item 5) ---
// Opening a wallet: ONE entry of the passphrase; an empty entry is allowed
// and opens the wallet without a passphrase. MW_ERR_ABORTED on cancel.
mw_err_t mw_screen_passphrase_open_run(const char* wallet_name, char* out,
                                       size_t out_cap);

// --- screen_passphrase.cpp ---
// TZ 5.9: "произвольная длина". The ceiling is the session scratch buffer
// (MW_SESSION_INPUT_CAP in session.c); the keyboard buffer MW_KB_TEXT_MAX
// matches it, so nothing on the way from the key cap to mw_seed_to_keys()
// truncates a long passphrase behind the user's back.
#define MW_PASSPHRASE_MAX 256
// The complete TZ 5.2 flow: mandatory prompt, explicit "no passphrase" with a
// second confirmation, double entry with comparison, buffers wiped on every
// exit path.
mw_err_t mw_screen_passphrase_run(char* out, size_t out_cap);

// --- screen_tx.cpp ---
bool mw_screen_tx_run(const mw_tx_summary_t* s, uint64_t unlock_time);

// --- screen_qr.cpp ---
bool mw_screen_qr_show_run(const char* title, const char* ur_type,
                           const uint8_t* data, size_t len);
// task2 item 5: ONE static QR code of `text` (a wallet address), no UR
// animation. The text is also shown under the code so it can be compared.
bool mw_screen_qr_static_run(const char* title, const char* text);

// --- screen_pin.cpp (task2 item 6) ---
// Numeric keypad. Returns MW_OK with the digits in `out`, MW_ERR_ABORTED on
// cancel. `hint` is shown above the digits.
mw_err_t mw_screen_pin_run(const char* title, const char* hint, char* out,
                           size_t out_cap, bool mask);
// The critical-action gate: shows `body`, then a random 4-digit number the
// user has to type back on the keypad. true only when the number matched.
bool     mw_ui_confirm_code(const char* title, const char* body);
// Viewfinder + UR assembly progress. Returns true when the sequence completed.
bool mw_screen_qr_scan_run(const char* title, uint8_t* buf, size_t cap,
                           size_t* len_out);

// --- screen_settings.cpp ---
void mw_screen_settings_run(void);
// TZ 8.1: the one-shot, IRREVERSIBLE eFuse HMAC key burn, behind a double
// confirmation that spells out what is burned and that it can never be
// changed without replacing the chip. Returns true when the key is
// provisioned by the time it returns (including "it already was").
bool mw_screen_efuse_provision_run(void);

#endif /* MW_UI_STRINGS_ONLY */

#ifdef __cplusplus
}
#endif
#endif