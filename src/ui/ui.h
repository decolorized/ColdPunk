// LVGL UI layer (TZ 4). Screens are created lazily and destroyed on exit so a
// 240x320 board never holds more than two screens' worth of objects.
#ifndef MW_UI_H
#define MW_UI_H

#include "../monero/monero_types.h"
#include "../monero/tx.h"
#include "../wallet/secure_storage.h"

#ifdef __cplusplus
extern "C" {
#endif

typedef enum {
    MW_SCREEN_BOOT = 0,
    MW_SCREEN_MAIN_MENU,
    MW_SCREEN_WALLET_LIST,
    MW_SCREEN_WALLET_CREATE,
    MW_SCREEN_WALLET_IMPORT,
    MW_SCREEN_SEED_DISPLAY,
    MW_SCREEN_SEED_INPUT,
    MW_SCREEN_SEED_VERIFY,
    MW_SCREEN_PASSPHRASE,
    MW_SCREEN_DICE,
    MW_SCREEN_TX_REVIEW,
    MW_SCREEN_KEYIMAGE_SYNC,
    MW_SCREEN_QR_DISPLAY,
    MW_SCREEN_QR_SCAN,
    MW_SCREEN_SETTINGS,
    MW_SCREEN_PROGRESS,
    MW_SCREEN_MESSAGE
} mw_screen_id_t;

mw_err_t mw_ui_init(void);
void     mw_ui_tick(void);                 // call from the LVGL task loop
void     mw_ui_show(mw_screen_id_t id);
mw_screen_id_t mw_ui_current(void);

// Status bar indicators (TZ 4.2).
void mw_ui_set_status(int battery_percent, bool sd, bool usb);

// Blocking helpers driven from the crypto task via a queue.
bool mw_ui_confirm(const char* title, const char* body,
                   const char* ok, const char* cancel);
void mw_ui_message(const char* title, const char* body);
void mw_ui_progress(const char* title, int permille, const char* detail);

// ---------------- keyboard (TZ 5.4) ----------------------------------------
typedef enum {
    MW_KB_MODE_SEED_LEGACY = 0,   // constrained to the 1626-word list
    MW_KB_MODE_SEED_POLYSEED,     // constrained to the 2048-word list
    MW_KB_MODE_FREE_TEXT          // passphrase / wallet name
} mw_kb_mode_t;

typedef struct {
    mw_kb_mode_t    mode;
    keyboard_type_t type;         // FULL or SCROLL
    const char*     title;
    int             word_index;   // 1-based, for "Слово 5 из 25"
    int             word_total;
    bool            allow_back;   // step back to the previous word
    // TZ 5.8: this word is the one a failed checksum / RS code points at, so
    // the keyboard marks it in the danger colour instead of the plain counter.
    bool            highlight;
} mw_kb_ctx_t;

// Runs one word / one string of input. Returns MW_OK and fills `out`, or
// MW_ERR_ABORTED when the user cancels.
mw_err_t mw_kb_run(const mw_kb_ctx_t* ctx, char* out, size_t out_cap);

// ---------------- the device shell (flows.cpp, task 3) ---------------------
// The crypto task's whole life: Minesweeper -> device password -> main menu
// (Wallets / Settings / Lock) -> wallet menu, and back to the game on lock or
// autolock. Never returns.
void mw_shell_run(void);
// Installs the USB link hooks (file classifier, wake on PC events).
void mw_shell_link_install(void);
// The open wallet, for the link's INFO answer. Empty name when none.
void mw_shell_info(char* name, size_t cap, uint8_t* variant, uint8_t* network);

// TZ 5.2: asked at wallet creation / import, with an explicit "no
// passphrase" confirmation and a double entry.
mw_err_t mw_flow_passphrase(char* out, size_t out_cap);

// ---------------- LVGL task plumbing (lvgl_port.cpp) ------------------------
// The LVGL task calls mw_ui_task_register() before its first tick; setup()
// calls mw_ui_task_expect() before creating it, so no other task drives LVGL
// in the meantime.
void mw_ui_task_expect(void);
void mw_ui_task_register(void);

// Autolock: armed by the shell while the device is unlocked; the LVGL task
// calls mw_ui_autolock_tick() once a second.
void mw_ui_autolock_arm(bool on);
void mw_ui_autolock_tick(void);
bool mw_ui_lock_requested(void);
void mw_ui_lock_request(void);

#ifdef __cplusplus
}
#endif
#endif
