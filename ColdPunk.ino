// ============================================================================
//  Monero Cold Wallet - firmware entry point
//  ESP32-S3 + LVGL, air-gapped hardware wallet. MIT licence.
//
//  Boot order matters and is fixed by the specification:
//    1. bootloader_random_enable() + TRNG self-test   (TZ 8.2)
//    2. PSRAM check and the 2 MiB cn_slow_hash arena  (TZ 1.4)
//    3. display, input devices, SD                    (TZ 2)
//    4. settings, wallet store, device password record (TZ 8.1, task2 item 1)
//    5. the USB link (CDC serial + vendor HID, task2 item 2)
//    6. FreeRTOS tasks: LVGL on core 0, crypto on core 1
//    7. the crypto task runs the shell (src/ui/flows.cpp): the Minesweeper
//       start screen, the device password (set on first start), the menus
//
//  Nothing in this firmware opens a network socket. Wi-Fi and Bluetooth are
//  never initialised and the build fails if their headers are pulled in
//  (see src/config/app_config.h, TZ 8.4).
//
//  Logging: everything goes through src/hal/log.h (task2 items 3 and 10).
//  hal_esp32.cpp installs the UART console when the USB CDC port carries the
//  host protocol; the USB link forwards every line to the host program.
// ============================================================================

#include <Arduino.h>

#include "board_config.h"

#include "src/config/app_config.h"
#include "src/hal/hal.h"
#include "src/hal/log.h"
#include "src/crypto/random.h"
#include "src/crypto/chacha.h"
#include "src/monero/bulletproof_plus.h"
#include "src/wallet/secure_storage.h"
#include "src/wallet/session.h"
#include "src/wallet/wallet_store.h"
#include "src/wallet/device_auth.h"
#include "src/transfer/transfer.h"
#include "src/transfer/link.h"
#include "src/ui/ui.h"
#include "src/ui/i18n.h"

#include <freertos/FreeRTOS.h>
#include <freertos/task.h>
#include <esp_heap_caps.h>

// USB link entry point (src/transfer/usb_link_arduino.cpp). The core owns
// TinyUSB; the link has its own small task for the byte pumps.
extern "C" mw_err_t mw_usb_link_init(void);

static mw_settings_t g_settings;

// ---------------------------------------------------------------------------
// Fatal error handler
// ---------------------------------------------------------------------------
static void fatal(const char* what, mw_err_t err) {
    MW_LOGE("boot", "FATAL: %s (%s)", what, mw_err_str(err));
    mw_ui_message("FATAL", what);
    for (;;) {
        mw_ui_tick();
        delay(50);
    }
}

// ---------------------------------------------------------------------------
// INFO for the host program (link.h). Nothing secret: version, board, how
// many wallets exist and whether a session is open.
// ---------------------------------------------------------------------------
static void link_info_provider(mw_link_info_t* out, void* ctx) {
    (void)ctx;
    snprintf(out->fw_version, sizeof(out->fw_version), "%s", MW_FIRMWARE_VERSION);
    snprintf(out->board, sizeof(out->board), "%s", BOARD_NAME);
    const uint8_t state = mw_link_state();
    out->unlocked = (state != MW_LINK_STATE_LOCKED) ? 1 : 0;
    // The reset reason is generic; link.c drops the crash fields while the
    // device is locked.
    out->reset_reason = mw_hal_reset_reason();
    uint8_t op = 0, stage = 0;
    if (out->unlocked && mw_hal_last_crash(&op, &stage)) {
        const uint32_t sf = mw_hal_last_crash_stack_free();
        out->crash_op = op;
        out->crash_stage = stage;
        out->crash_flags = MW_LINK_CRASH_VALID | (sf ? MW_LINK_CRASH_STACK : 0);
        out->crash_stack_free = (uint16_t)(sf > 0xFFFFu ? 0xFFFFu : sf);
    }
    // Wallet names and counts are only reported once the device is unlocked:
    // the locked device is "just a game".
    if (out->unlocked) {
        static wallet_store_t store;    // ~1.5 KB, keep off the link task stack
        if (mw_wallet_store_load(&store) == MW_OK) {
            out->wallet_count = (uint8_t)(store.count > 255 ? 255 : store.count);
        }
        memset(&store, 0, sizeof(store));
        mw_shell_info(out->wallet_name, sizeof(out->wallet_name), &out->pp_variant,
                      &out->network);
    }
}

// ---------------------------------------------------------------------------
// Boot diagnostics: why the previous run ended, and the internal heap. The
// crash breadcrumb holds only an operation and a stage (no wallet data); its
// details are reported to the host only once the device is unlocked.
// ---------------------------------------------------------------------------
static const char* reset_reason_name(uint8_t r) {
    switch (r) {
    case MW_RESET_POWERON:   return "power-on";
    case MW_RESET_EXTERNAL:  return "reset pin";
    case MW_RESET_SOFTWARE:  return "software restart";
    case MW_RESET_PANIC:     return "crash (panic)";
    case MW_RESET_INT_WDT:   return "interrupt watchdog";
    case MW_RESET_TASK_WDT:  return "task watchdog";
    case MW_RESET_WDT:       return "watchdog";
    case MW_RESET_DEEPSLEEP: return "deep sleep wake";
    case MW_RESET_BROWNOUT:  return "brownout";
    case MW_RESET_USB:       return "USB/JTAG reset";
    case MW_RESET_OTHER:     return "other";
    default:                 return "unknown";
    }
}

static void log_boot_diagnostics(void) {
    MW_LOGI("boot", "reset reason: %s", reset_reason_name(mw_hal_reset_reason()));
    MW_LOGI("boot", "internal heap: %u B free, largest block %u B",
            (unsigned)heap_caps_get_free_size(MALLOC_CAP_INTERNAL),
            (unsigned)heap_caps_get_largest_free_block(MALLOC_CAP_INTERNAL));
    if (mw_hal_last_crash(nullptr, nullptr)) {
        // Details (operation, stage) only after unlock: flows.cpp reports them.
        MW_LOGE("boot", "the previous run crashed; details after unlock");
    }
}

// ---------------------------------------------------------------------------
// UI task - owns every LVGL object. Pinned to core 0 (TZ 4.1).
// ---------------------------------------------------------------------------
static void ui_task(void* arg) {
    (void)arg;
    // First thing: tell the UI layer which task owns LVGL (task 3 item 0).
    mw_ui_task_register();
    uint32_t last_status = 0;
    for (;;) {
        mw_ui_tick();

        uint32_t now = mw_millis();
        if (now - last_status > 1000) {
            last_status = now;
            mw_ui_set_status(mw_battery_percent(), mw_sd_present(), mw_usb_connected());
            // The autolock closes the open dialog; the shell then locks the
            // device and returns to the game. (It used to wipe the typed
            // passphrase every second here, which made a double entry never
            // match.)
            mw_ui_autolock_tick();
        }
        vTaskDelay(pdMS_TO_TICKS(5));
    }
}

// ---------------------------------------------------------------------------
// Crypto task - owns every secret. Pinned to core 1 (TZ 4.1).
// The device password comes first (task2 item 1): nothing else runs until
// the user key is installed.
// ---------------------------------------------------------------------------
static void crypto_task(void* arg) {
    (void)arg;
    MW_LOGI("boot", "crypto task running");
    mw_shell_run();                       // never returns
}

void setup() {
    // ---- 1. entropy first, before anything can consume randomness --------
    mw_rng_status_t rng = mw_random_init();

    // ---- 2. hardware (also brings the log up) -----------------------------
    mw_err_t err = mw_hal_init();
    if (err != MW_OK) {
        MW_LOGE("boot", "HAL init failed: %s", mw_err_str(err));
    }
    log_boot_diagnostics();

    if (mw_ui_init() != MW_OK) {
        MW_LOGE("boot", "UI init failed");
    }

    if (rng != MW_RNG_OK) {
        fatal("TRNG self-test failed", MW_ERR_IO);
    }

    // ---- 3. memory arenas -----------------------------------------------
    if (mw_cn_slow_hash_init() != 0) {
        fatal("cn_slow_hash scratchpad (2 MiB PSRAM) unavailable", MW_ERR_MEMORY);
    }
    if (mw_bpp_init() != MW_OK) {
        fatal("Bulletproofs+ generator table allocation failed", MW_ERR_MEMORY);
    }

    // ---- 4. persistent state --------------------------------------------
    if (mw_settings_load(&g_settings) != MW_OK) {
        g_settings.keyboard      = mw_settings_default_keyboard();
        g_settings.kb_layout     = KB_LAYOUT_QWERTY;
        g_settings.brightness    = 80;
        g_settings.autolock_min  = MW_AUTOLOCK_DEFAULT_MIN;
        g_settings.network       = MW_DEFAULT_NETWORK;
        g_settings.debug_log     = false;
        mw_settings_save(&g_settings);
    }
    mw_log_set_debug(g_settings.debug_log);
    mw_display_backlight(g_settings.brightness);

    mw_i18n_set(MW_UI_DEFAULT_LANG);

    if (mw_secure_key_status() != MW_OK) {
        MW_LOGE("boot", "eFuse HMAC key not provisioned; "
                        "wallet seeds are protected by the password only");
    }

    if (mw_wallet_store_init() != MW_OK) {
        MW_LOGE("boot", "wallet store unavailable");
    }
    if (mw_device_auth_init() != MW_OK) {
        MW_LOGE("boot", "device password record unreadable");
    }

    // ---- 5. exchange channels -------------------------------------------
    mw_transfer_init();
    mw_link_set_info_provider(link_info_provider, nullptr);
    // The USB link (CDC + HID) is NOT started here: the shell starts it after
    // the first correct device password (flows.cpp, ensure_usb_link). Until
    // then the device answers nothing on USB. With Tools > "USB CDC On Boot:
    // Enabled" the core itself enumerates the CDC port before setup(); set it
    // to Disabled for no USB device at all before the password.
    mw_shell_link_install();          // file classifier + wake on PC events

    // ---- 6. tasks --------------------------------------------------------
    // From here on only the UI task drives LVGL; the crypto task waits for it
    // instead of running its first dialog itself (task 3 item 0).
    mw_ui_task_expect();
    BaseType_t ok = xTaskCreatePinnedToCore(ui_task, "ui", MW_UI_TASK_STACK, nullptr,
                                            MW_UI_TASK_PRIO, nullptr, MW_UI_TASK_CORE);
    if (ok != pdPASS) {
        MW_LOGE("boot", "UI task creation failed (%u bytes internal RAM free)",
                (unsigned)heap_caps_get_free_size(MALLOC_CAP_INTERNAL));
    }
    ok = xTaskCreatePinnedToCore(crypto_task, "crypto", MW_CRYPTO_TASK_STACK, nullptr,
                                 MW_CRYPTO_TASK_PRIO, nullptr, MW_CRYPTO_TASK_CORE);
    if (ok != pdPASS) {
        // Without the crypto task nothing on the screen would ever react.
        MW_LOGE("boot", "crypto task creation failed (%u bytes internal RAM free)",
                (unsigned)heap_caps_get_free_size(MALLOC_CAP_INTERNAL));
    }
    MW_LOGI("boot", "%s %s on %s ready", MW_FIRMWARE_NAME, MW_FIRMWARE_VERSION, BOARD_NAME);
}

void loop() {
    // Everything runs in the two pinned tasks above.  Keep the Arduino loop
    // idle so it cannot interfere with LVGL's timing.
    vTaskDelay(pdMS_TO_TICKS(1000));
}
