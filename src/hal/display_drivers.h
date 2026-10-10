// Board-config resolution, HAL-wide defaults and the small set of HAL
// extensions that do not fit in the frozen hal.h.
//
// Every HAL translation unit includes this header FIRST (after Arduino.h on
// the device build).  It is deliberately host-safe: when MW_HOST_BUILD is set
// nothing board- or Arduino-specific is pulled in.
//
// Naming note: the file is called display_drivers.h because the display
// dispatch table is its main content, but it is also the single place where
// board_config.h is located and where the optional board defines get their
// fallback values.  Keeping that in one header is what lets boards/*.h stay
// as small as the TZ 2.2 template.
#ifndef MW_DISPLAY_DRIVERS_H
#define MW_DISPLAY_DRIVERS_H

#include <stdint.h>
#include <stdbool.h>
#include <stddef.h>

#include "hal.h"
#include "../config/app_config.h"     // MW_USE_SERIAL / MW_USE_HID / MW_USE_SD

// ===========================================================================
// 1. board_config.h resolution (TZ 2.1 - manual selection, no auto-detect)
// ===========================================================================
// The sketch folder owns board_config.h; it does nothing but #include one of
// boards/*.h.  Three ways to reach it, tried in order:
//
//   a) -DMW_BOARD_CONFIG_HEADER="\"../../boards/es3c28p.h\""  (CI / host)
//   b) "board_config.h" on the include path (Arduino IDE: the sketch folder
//      is always on the include path, so this is the normal device case)
//   c) the in-repo relative path, for editors and non-Arduino builds
//
// See boards/README.md for the exact contract.
#if !defined(MW_HOST_BUILD)
#  if defined(MW_BOARD_CONFIG_HEADER)
#    include MW_BOARD_CONFIG_HEADER
#  elif defined(__has_include)
#    if __has_include("board_config.h")
#      include "board_config.h"
#    elif __has_include("../../MoneroColdWallet/board_config.h")
#      include "../../MoneroColdWallet/board_config.h"
#    else
#      error "board_config.h not found - see boards/README.md (TZ 2.1)"
#    endif
#  else
#    include "board_config.h"
#  endif
#  if !defined(BOARD_NAME)
#    error "board_config.h did not define BOARD_NAME - wrong header included?"
#  endif
#endif  // !MW_HOST_BUILD

// ===========================================================================
// 2. Fallbacks for optional board defines
// ===========================================================================
// boards/es3c28p.h is the frozen TZ 2.2 template and does not carry the
// extra defines the later boards need, so every one of them is optional.
#if !defined(MW_HOST_BUILD)

#ifndef DISPLAY_ROTATION
#define DISPLAY_ROTATION 0
#endif

// Display geometry contract (v6):
//   DISPLAY_WIDTH x DISPLAY_HEIGHT is the PHYSICAL panel, i.e. its size at
//   rotation 0 - the numbers from the panel datasheet (240x320 for a 2.8"
//   ILI9341 or a 2" ST7789T3, whatever DISPLAY_ROTATION says).
//   The LOGICAL size the UI works in is NOT a compile-time constant: it is
//   read from the driver after begin() (mw_display_width/height() below) and
//   reaches LVGL and the theme metrics through mw_hal_caps().  A controller
//   whose driver swaps the axes for an odd rotation and one whose driver does
//   not both end up with LVGL and the driver agreeing on the frame size.
// MW_DISPLAY_EXPECT_W/H is only the usual answer (axes swapped for an odd
// rotation): the value before the driver is up and the reference the init
// log compares the driver against.
#if (DISPLAY_ROTATION & 1)
#  define MW_DISPLAY_EXPECT_W DISPLAY_HEIGHT
#  define MW_DISPLAY_EXPECT_H DISPLAY_WIDTH
#else
#  define MW_DISPLAY_EXPECT_W DISPLAY_WIDTH
#  define MW_DISPLAY_EXPECT_H DISPLAY_HEIGHT
#endif
#ifndef TFT_CS
#define TFT_CS -1
#endif
#ifndef TFT_DC
#define TFT_DC -1
#endif
#ifndef TFT_RST
#define TFT_RST -1
#endif
#ifndef TFT_MOSI
#define TFT_MOSI -1
#endif
#ifndef TFT_SCK
#define TFT_SCK -1
#endif
#ifndef TFT_MISO
#define TFT_MISO -1
#endif
#ifndef TFT_BL
#define TFT_BL -1
#endif
#ifndef TFT_BL_ACTIVE_HIGH
#define TFT_BL_ACTIVE_HIGH 1
#endif
#ifndef DISPLAY_SPI_HZ
#define DISPLAY_SPI_HZ 40000000UL      // conservative for 10 cm ribbon cables
#endif
#ifndef DISPLAY_IPS
#define DISPLAY_IPS 1
#endif

// Touch extras (XPT2046 is on SPI, the I2C parts have an address).
#ifndef HAS_TOUCH
#define HAS_TOUCH 0
#endif
#ifndef TOUCH_DRIVER
#define TOUCH_DRIVER TOUCH_NONE
#endif
#ifndef TOUCH_SDA
#define TOUCH_SDA -1
#endif
#ifndef TOUCH_SCL
#define TOUCH_SCL -1
#endif
#ifndef TOUCH_INT
#define TOUCH_INT -1
#endif
#ifndef TOUCH_RST
#define TOUCH_RST -1
#endif
#ifndef TOUCH_CS
#define TOUCH_CS -1                    // XPT2046 only
#endif
#ifndef TOUCH_I2C_HZ
#define TOUCH_I2C_HZ 400000UL
#endif
// Capacitive glass fix-ups, applied in the unrotated panel space before the
// DISPLAY_ROTATION map (src/hal/touch_map.h).  XPT2046 uses TOUCH_SWAP_XY
// only for its uncalibrated default.
#ifndef TOUCH_SWAP_XY
#define TOUCH_SWAP_XY 0
#endif
#ifndef TOUCH_MIRROR_X
#define TOUCH_MIRROR_X 0
#endif
#ifndef TOUCH_MIRROR_Y
#define TOUCH_MIRROR_Y 0
#endif
// Native (rotation 0) size of the touch glass; by default the panel's own
// physical size, DISPLAY_WIDTH x DISPLAY_HEIGHT.
#ifndef TOUCH_NATIVE_W
#  define TOUCH_NATIVE_W DISPLAY_WIDTH
#endif
#ifndef TOUCH_NATIVE_H
#  define TOUCH_NATIVE_H DISPLAY_HEIGHT
#endif

// Buttons / encoder.
#ifndef HAS_BUTTONS
#define HAS_BUTTONS 0
#endif
#ifndef BUTTON_UP
#define BUTTON_UP -1
#endif
#ifndef BUTTON_DOWN
#define BUTTON_DOWN -1
#endif
#ifndef BUTTON_LEFT
#define BUTTON_LEFT -1
#endif
#ifndef BUTTON_RIGHT
#define BUTTON_RIGHT -1
#endif
#ifndef BUTTON_SELECT
#define BUTTON_SELECT -1
#endif
#ifndef BUTTON_BACK
#define BUTTON_BACK -1
#endif
#ifndef BUTTON_ENCODER_A
#define BUTTON_ENCODER_A -1
#endif
#ifndef BUTTON_ENCODER_B
#define BUTTON_ENCODER_B -1
#endif
#ifndef BUTTON_ACTIVE_LOW
#define BUTTON_ACTIVE_LOW 1            // internal pull-up, switch to GND
#endif

// Storage / power / misc.
#ifndef HAS_SD
#define HAS_SD 0
#endif
// The slot is used only when the build wants it (app_config.h MW_USE_SD).
#if !MW_USE_SD
#undef  HAS_SD
#define HAS_SD 0
#endif
// A wallet that cannot exchange files with the PC is of no use.
#if !MW_USE_SERIAL && !MW_USE_HID && !HAS_SD
#error "No exchange interface: enable MW_USE_SERIAL, MW_USE_HID or MW_USE_SD (on a board with HAS_SD)"
#endif
#ifndef SD_CS
#define SD_CS -1
#endif
#ifndef SD_MISO
#define SD_MISO -1
#endif
#ifndef SD_MOSI
#define SD_MOSI -1
#endif
#ifndef SD_SCK
#define SD_SCK -1
#endif
#ifndef SD_DETECT
#define SD_DETECT -1                   // card-detect switch, active low
#endif
#ifndef HAS_CAMERA
#define HAS_CAMERA 0
#endif
// OV2640 pins (TZ 3.7).  Only meaningful when HAS_CAMERA is 1; the fallbacks
// exist so a board header written before the camera API landed still builds.
#ifndef CAM_PIN_PWDN
#define CAM_PIN_PWDN  -1
#endif
#ifndef CAM_PIN_RESET
#define CAM_PIN_RESET -1
#endif
#ifndef CAM_PIN_XCLK
#define CAM_PIN_XCLK  -1
#endif
#ifndef CAM_PIN_SIOD
#define CAM_PIN_SIOD  -1
#endif
#ifndef CAM_PIN_SIOC
#define CAM_PIN_SIOC  -1
#endif
#ifndef CAM_PIN_D0
#define CAM_PIN_D0    -1
#endif
#ifndef CAM_PIN_D1
#define CAM_PIN_D1    -1
#endif
#ifndef CAM_PIN_D2
#define CAM_PIN_D2    -1
#endif
#ifndef CAM_PIN_D3
#define CAM_PIN_D3    -1
#endif
#ifndef CAM_PIN_D4
#define CAM_PIN_D4    -1
#endif
#ifndef CAM_PIN_D5
#define CAM_PIN_D5    -1
#endif
#ifndef CAM_PIN_D6
#define CAM_PIN_D6    -1
#endif
#ifndef CAM_PIN_D7
#define CAM_PIN_D7    -1
#endif
#ifndef CAM_PIN_VSYNC
#define CAM_PIN_VSYNC -1
#endif
#ifndef CAM_PIN_HREF
#define CAM_PIN_HREF  -1
#endif
#ifndef CAM_PIN_PCLK
#define CAM_PIN_PCLK  -1
#endif
#ifndef HAS_PSRAM
#define HAS_PSRAM 0
#endif
#ifndef PSRAM_SIZE_MB
#define PSRAM_SIZE_MB 0
#endif
#ifndef HAS_USB_OTG
#define HAS_USB_OTG 0
#endif
#ifndef BATTERY_ADC_PIN
#define BATTERY_ADC_PIN -1             // -1 -> mw_battery_percent() == -1
#endif
#ifndef BATTERY_DIV_NUM
#define BATTERY_DIV_NUM 2              // Vbat = Vadc * NUM / DEN
#endif
#ifndef BATTERY_DIV_DEN
#define BATTERY_DIV_DEN 1
#endif
#ifndef BATTERY_MV_EMPTY
#define BATTERY_MV_EMPTY 3300
#endif
#ifndef BATTERY_MV_FULL
#define BATTERY_MV_FULL 4180
#endif
#ifndef USB_VBUS_DET_PIN
#define USB_VBUS_DET_PIN -1
#endif

// True when the panel is a 1 bpp OLED (SSD1306 / SH1106).
#if (DISPLAY_DRIVER == DISPLAY_SSD1306) || (DISPLAY_DRIVER == DISPLAY_SH1106)
#define MW_DISPLAY_MONO 1
#else
#define MW_DISPLAY_MONO 0
#endif

// True when the display is an ST7701S RGB panel driven by the LCD_CAM
// peripheral rather than by a plain SPI bus.
#if (DISPLAY_DRIVER == DISPLAY_ST7701S)
#define MW_DISPLAY_RGB_PANEL 1
#else
#define MW_DISPLAY_RGB_PANEL 0
#endif

// The SD card shares the display SPI bus whenever the clock pin matches.
// When it does, the GFX backend must be the SPIClass-based Arduino_HWSPI so
// both users arbitrate through beginTransaction()/endTransaction().
#if HAS_SD && !MW_DISPLAY_MONO && !MW_DISPLAY_RGB_PANEL && (SD_SCK == TFT_SCK)
#define MW_SPI_BUS_SHARED 1
#else
#define MW_SPI_BUS_SHARED 0
#endif

// Mono OLED I2C parameters.
#ifndef OLED_I2C_SDA
#define OLED_I2C_SDA -1
#endif
#ifndef OLED_I2C_SCL
#define OLED_I2C_SCL -1
#endif
#ifndef OLED_I2C_ADDR
#define OLED_I2C_ADDR 0x3C
#endif
#ifndef OLED_I2C_HZ
#define OLED_I2C_HZ 400000UL
#endif

// ST7789 RAM offsets.  The 240x320 modules are flush with the controller RAM;
// the 240x240 ones start at row 80 in some rotations.  Boards override this.
#ifndef ST7789_COL_OFFSET
#define ST7789_COL_OFFSET 0
#endif
#ifndef ST7789_ROW_OFFSET
#define ST7789_ROW_OFFSET 0
#endif

// ST7735S RAM offsets.  Panels vary: some map the 128x160 visible area at
// column 0 / row 0, others at 0/32 or 2/1 depending on the module.  Boards
// override this in board_config.h when the image comes out shifted.
#ifndef ST7735S_COL_OFFSET
#define ST7735S_COL_OFFSET 0
#endif
#ifndef ST7735S_ROW_OFFSET
#define ST7735S_ROW_OFFSET 0
#endif


// ---- ST7701S RGB panel timings -------------------------------------------
// Only meaningful on an RGB-panel board, which supplies the 20 data/sync pins
// itself; the porches below are the common 480x480 "type1" values.
#if MW_DISPLAY_RGB_PANEL
#ifndef LCD_HSYNC_POLARITY
#define LCD_HSYNC_POLARITY     1
#endif
#ifndef LCD_HSYNC_FRONT_PORCH
#define LCD_HSYNC_FRONT_PORCH  10
#endif
#ifndef LCD_HSYNC_PULSE_WIDTH
#define LCD_HSYNC_PULSE_WIDTH  8
#endif
#ifndef LCD_HSYNC_BACK_PORCH
#define LCD_HSYNC_BACK_PORCH   50
#endif
#ifndef LCD_VSYNC_POLARITY
#define LCD_VSYNC_POLARITY     1
#endif
#ifndef LCD_VSYNC_FRONT_PORCH
#define LCD_VSYNC_FRONT_PORCH  10
#endif
#ifndef LCD_VSYNC_PULSE_WIDTH
#define LCD_VSYNC_PULSE_WIDTH  8
#endif
#ifndef LCD_VSYNC_BACK_PORCH
#define LCD_VSYNC_BACK_PORCH   20
#endif
#ifndef LCD_PCLK_ACTIVE_NEG
#define LCD_PCLK_ACTIVE_NEG    1
#endif
#ifndef LCD_PREFER_SPEED
#define LCD_PREFER_SPEED       16000000L
#endif
// Panel register set shipped by Arduino_GFX (st7701_type1..type9).  Which one
// is right depends on the glass, not on the controller - check the vendor
// init list before trusting the default.
#ifndef LCD_ST7701_INIT_OPS
#define LCD_ST7701_INIT_OPS     st7701_type1_init_operations
#define LCD_ST7701_INIT_OPS_LEN sizeof(st7701_type1_init_operations)
#endif
#endif  // MW_DISPLAY_RGB_PANEL

#endif  // !MW_HOST_BUILD

#ifdef __cplusplus
extern "C" {
#endif

// ===========================================================================
// 3. HAL extensions (NOT part of the frozen hal.h)
// ===========================================================================

// --- button press duration (TZ 5.6) ---------------------------------------
// mw_buttons_read() returns the currently pressed buttons, one bit per
// mw_button_t value:
//
//   bits 0..7   currently pressed          (bit index == mw_button_t)
//
// The HAL reports raw hold time and nothing else.  It used to also latch
// "long" and "very long" flags into bits 8..15 / 16..23 against thresholds of
// its own (800 ms / 2500 ms); nothing ever read them, and the UI - which owns
// the interaction semantics of TZ 5.6 - times presses itself against
// MW_BACK_LONG_MS / MW_BACK_VERY_LONG_MS in src/ui/screen_common.h.  Two sets
// of thresholds that disagree is one set too many, so the HAL side is gone and
// mw_buttons_press_ms() is the single source of hold time.
#define MW_BTN_MASK(btn)    (1u << (btn))
#define MW_BTN_DEBOUNCE_MS  20u

// Milliseconds the button has been continuously held, 0 when released.
uint32_t mw_buttons_press_ms(mw_button_t btn);
// Drains the debouncer without consuming events; safe to call from the LVGL
// tick when mw_buttons_read() is not being polled.
void     mw_buttons_poll(void);

// --- display extras --------------------------------------------------------
// Logical (after DISPLAY_ROTATION) size of the frame the driver accepts.
// After mw_display_init() this is what the driver itself reports; before it
// (or if the driver reports nonsense) MW_DISPLAY_EXPECT_W/H.  Every layer
// above the HAL takes the size from mw_hal_caps(), which is filled from here.
uint16_t mw_display_width(void);
uint16_t mw_display_height(void);
// Fills the whole panel with one RGB565 colour without allocating a frame.
void     mw_display_fill(uint16_t rgb565);
// 1 when the panel is monochrome and mw_display_blit() thresholds to 1 bpp.
bool     mw_display_is_mono(void);
// Pushes the shadow framebuffer of a monochrome panel to the glass.  No-op on
// colour panels, which are written through directly.
void     mw_display_flush(void);

// --- SD extras -------------------------------------------------------------
// FAT32, LFN, files up to 256 KB.  Every path handed to the SD API is
// bounded by these two limits.
#define MW_SD_PATH_MAX   128
#define MW_SD_NAME_MAX   64
// Same ceiling as the USB link (MW_TRANSFER_MAX_FILE): a large Feather outputs
// export must fit either way.
#define MW_SD_FILE_MAX   (256u * 1024u)

// One regular file of a directory, for the SD file browser.
#define MW_SD_ENTRY_NAME 96              // longer names are skipped, not cut
typedef struct {
    char     name[MW_SD_ENTRY_NAME];
    uint32_t size;
    int64_t  mtime;                      // unix seconds as the FAT entry says; 0 = none
} mw_sd_entry_t;

// Regular files of `dir` (no directories, no hidden names). Names that do
// not fit MW_SD_ENTRY_NAME are skipped, so every returned name opens.
mw_err_t mw_sd_list_files(const char* dir, mw_sd_entry_t* out, int max, int* count);
// The first `cap` bytes of a file (fewer for a short file).
mw_err_t mw_sd_read_head(const char* path, uint8_t* buf, size_t cap, size_t* len);
bool     mw_sd_exists(const char* path);
// Sets the FAT modification time (the device has no clock of its own).
mw_err_t mw_sd_set_mtime(const char* path, int64_t unix_time);
// Fresh mount for one piece of work: whatever was mounted before is released
// first, so a card swapped while the device ran is picked up. MW_OK when the
// card can be used.
mw_err_t mw_sd_ensure(void);
// Writes every cached sector (FAT, directory, data) to the card and unmounts
// it. Called right after each write and when the SD screens are left, so the
// card can be pulled out at any time without losing data.
void     mw_sd_release(void);

// Card hot-plug watch, for the SD file screen. A background task probes the
// slot about twice a second: a mounted card with a raw sector read (a pulled
// card fails it; the volume is then released), an empty slot with a mount
// attempt. On the first change it stops and mw_sd_watch_changed() turns
// true; the screen then closes and the caller rebuilds it. Nothing else may
// touch the card between start and stop. mw_sd_watch_stop() waits for the
// task to end. mw_sd_mounted(): the volume is mounted right now.
void     mw_sd_watch_start(void);
void     mw_sd_watch_stop(void);
bool     mw_sd_watch_changed(void);
bool     mw_sd_mounted(void);

// --- host-build extras -----------------------------------------------------
#ifdef MW_HOST_BUILD
// Writes the in-memory framebuffer to a binary PPM so host tests can eyeball
// what the UI drew.  Returns MW_OK on success.
mw_err_t mw_host_dump_ppm(const char* path);
// Points the file-backed "SD card" somewhere other than ./sdcard/.
void     mw_host_set_sd_root(const char* path);
// Injects a synthetic touch for UI tests (the host build reports has_touch
// == false, but mw_touch_read() will hand this back once when armed).
void     mw_host_inject_touch(uint16_t x, uint16_t y, bool pressed);
// Advances the simulated clock; mw_millis() = real elapsed + this offset.
void     mw_host_advance_ms(uint32_t ms);
#endif

#ifdef __cplusplus
}
#endif

// ===========================================================================
// 4. Device-only: the Arduino_GFX object built by display.cpp
// ===========================================================================
#if defined(ARDUINO) && !defined(MW_HOST_BUILD) && defined(__cplusplus) && !MW_DISPLAY_MONO
class Arduino_GFX;
// Valid only after mw_display_init(); NULL before that and on mono panels.
// ui/lvgl_port.cpp may use it for driver-specific tricks, but the normal path
// is mw_display_blit().
Arduino_GFX* mw_display_gfx(void);
#endif

#endif  // MW_DISPLAY_DRIVERS_H
