// Hardware abstraction layer. Every board-specific detail is reached through
// this header; board_config.h only supplies pin numbers and feature flags
// (TZ 2.1 - no auto-detection).
#ifndef MW_HAL_H
#define MW_HAL_H

#include <stdint.h>
#include <stdbool.h>
#include <stddef.h>
#include "../monero/monero_types.h"

#ifdef __cplusplus
extern "C" {
#endif

// ---------------- display --------------------------------------------------
#define DISPLAY_ILI9341 1
#define DISPLAY_ST7789  2
#define DISPLAY_ST7701S 3
#define DISPLAY_GC9A01  4
#define DISPLAY_ILI9488 5
#define DISPLAY_SSD1306 6
#define DISPLAY_SH1106  7

// ---------------- touch ----------------------------------------------------
#define TOUCH_NONE    0
#define TOUCH_FT6336G 1
#define TOUCH_FT6236  2
#define TOUCH_CST816S 3
#define TOUCH_GT911   4
#define TOUCH_XPT2046 5
// CST816D / CST816T use the CST816S register map (0x15, regs 0x01..0x06).
#define TOUCH_CST816D TOUCH_CST816S
#define TOUCH_CST816T TOUCH_CST816S

typedef struct {
    uint16_t width, height;
    uint8_t  rotation;
    bool     monochrome;
    bool     has_touch;
    bool     has_buttons;
    bool     has_encoder;
    bool     has_sd;
    bool     has_camera;
    bool     has_usb;
    bool     has_psram;
    uint32_t psram_size_mb;
    const char* board_name;
} mw_hal_caps_t;

const mw_hal_caps_t* mw_hal_caps(void);

mw_err_t mw_hal_init(void);          // clocks, PSRAM, TRNG, display, inputs
void     mw_hal_deinit(void);

// ---------------- display --------------------------------------------------
mw_err_t mw_display_init(void);
void     mw_display_backlight(uint8_t percent);   // 0..100
// LVGL flush callback plumbing lives in ui/lvgl_port.cpp; the HAL only exposes
// the raw blit so the port stays driver-agnostic.
void     mw_display_blit(int16_t x, int16_t y, int16_t w, int16_t h,
                         const uint16_t* pixels);
void     mw_display_wait_dma(void);

// ---------------- input ----------------------------------------------------
typedef enum {
    MW_BTN_NONE = 0, MW_BTN_UP, MW_BTN_DOWN, MW_BTN_LEFT, MW_BTN_RIGHT,
    MW_BTN_SELECT, MW_BTN_BACK
} mw_button_t;

typedef struct {
    bool     pressed;
    uint16_t x, y;
} mw_touch_state_t;

mw_err_t mw_touch_init(void);
bool     mw_touch_read(mw_touch_state_t* out);
mw_err_t mw_touch_calibrate(int32_t coeffs[6]);   // persisted in NVS

mw_err_t mw_buttons_init(void);
// Bitmask of currently pressed buttons, bit index = mw_button_t value.
uint32_t mw_buttons_read(void);
// Bitmask of the buttons the board actually has wired (same bit layout).
// A board without LEFT/RIGHT (4-button boards) gets the linear keyboard
// navigation of src/ui/keyboard_nav.h.
uint32_t mw_buttons_present(void);
// Encoder delta since the last call (0 when no encoder).
int32_t  mw_encoder_read(void);

// ---------------- storage --------------------------------------------------
mw_err_t mw_sd_init(void);
bool     mw_sd_present(void);
mw_err_t mw_sd_read_file(const char* path, uint8_t* buf, size_t cap, size_t* len);
mw_err_t mw_sd_write_file(const char* path, const uint8_t* buf, size_t len);
mw_err_t mw_sd_list(const char* dir, char (*names)[64], int max, int* count);
mw_err_t mw_sd_format(void);
mw_err_t mw_sd_unlink(const char* path);
// (The block-level API that USB mass storage used to need is gone: the card
// is only ever a file courier now - task2 item 2.)

// ---------------- camera (TZ 3.7 QR scanning) ------------------------------
// Grayscale frames are enough for QR decoding and a quarter of the RAM of
// RGB565. The frame buffer is owned by the driver and stays valid until the
// next mw_camera_capture() call.
typedef struct {
    const uint8_t* data;     // 8-bit grayscale, row-major
    uint16_t       width;
    uint16_t       height;
} mw_camera_frame_t;

mw_err_t mw_camera_init(void);
void     mw_camera_deinit(void);
// Returns MW_ERR_NOT_SUPPORTED when HAS_CAMERA is 0.
mw_err_t mw_camera_capture(mw_camera_frame_t* out);
// Downscaled preview for the viewfinder, as RGB565 for direct blitting.
mw_err_t mw_camera_preview(uint16_t* out, uint16_t w, uint16_t h);

// ---------------- power ----------------------------------------------------
int  mw_battery_percent(void);   // -1 when the board has no fuel gauge
bool mw_usb_connected(void);

// ---------------- misc -----------------------------------------------------
uint32_t mw_millis(void);
void     mw_delay_ms(uint32_t ms);
void     mw_reboot(void);
// Factory reset: wipes NVS (including all wallets) and reboots (TZ 4.2).
void     mw_factory_reset(void);

// ---------------- crash diagnostics ----------------------------------------
// Why this boot happened (esp_reset_reason() folded into a small enum that
// the USB link reports in INFO byte 92 and mwlink.py names).
enum {
    MW_RESET_UNKNOWN   = 0,
    MW_RESET_POWERON   = 1,
    MW_RESET_EXTERNAL  = 2,    // reset pin
    MW_RESET_SOFTWARE  = 3,    // esp_restart(): reboot, factory reset, OTA
    MW_RESET_PANIC     = 4,    // exception / abort (stack overflow included)
    MW_RESET_INT_WDT   = 5,
    MW_RESET_TASK_WDT  = 6,
    MW_RESET_WDT       = 7,    // other watchdogs
    MW_RESET_DEEPSLEEP = 8,
    MW_RESET_BROWNOUT  = 9,
    MW_RESET_USB       = 10,   // USB peripheral / JTAG reset
    MW_RESET_OTHER     = 11
};
uint8_t  mw_hal_reset_reason(void);

// Breadcrumb: what the crypto task is doing right now. Kept in RTC memory
// that survives a panic or watchdog reset (not a power cycle). Only these
// enums and a stack figure are stored, never data.
enum {
    MW_CRUMB_OP_NONE       = 0,
    MW_CRUMB_OP_SIGN       = 1,    // unsigned tx -> signed tx
    MW_CRUMB_OP_KEYIMAGES  = 2,    // outputs -> key images
    MW_CRUMB_OP_WALLET     = 3,    // opening / creating a wallet
    MW_CRUMB_OP_EXPORT     = 4     // address / view-only export
};
enum {
    MW_CRUMB_STAGE_NONE    = 0,
    MW_CRUMB_STAGE_LOAD    = 1,    // decrypting / parsing the input
    MW_CRUMB_STAGE_INSPECT = 2,    // review before the user confirms
    MW_CRUMB_STAGE_KEYS    = 3,    // key derivation / key images
    MW_CRUMB_STAGE_CLSAG   = 4,
    MW_CRUMB_STAGE_BPP     = 5,    // Bulletproofs+
    MW_CRUMB_STAGE_SEAL    = 6,    // encrypting the result
    MW_CRUMB_STAGE_OUTPUT  = 7     // handing the result to the PC / QR
};
// Records op/stage and the calling task's minimum free stack.
void     mw_hal_crumb_set(uint8_t op, uint8_t stage);
void     mw_hal_crumb_clear(void);
// The crumb that was set when the previous run crashed (panic, watchdog or
// brownout), captured in mw_hal_init(). False when the last reset was not a
// crash or nothing was recorded.
bool     mw_hal_last_crash(uint8_t* op, uint8_t* stage);
// Minimum free stack of the crashed task at its last crumb, bytes (0 = not
// known). Valid only when mw_hal_last_crash() returns true.
uint32_t mw_hal_last_crash_stack_free(void);
// Forgets the last crash once it has been reported to the user.
void     mw_hal_last_crash_forget(void);
// Minimum free stack of the calling task so far, bytes (UINT32_MAX on host).
uint32_t mw_stack_free_min(void);
#ifdef MW_HOST_BUILD
// Host tests: acts like a boot after a reset of kind `reason` (MW_RESET_*).
void     mw_host_simulate_reset(uint8_t reason);
#endif

#ifdef __cplusplus
}
#endif
#endif
