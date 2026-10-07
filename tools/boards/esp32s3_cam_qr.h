// ESP32-S3 + OV2640 camera + 2.4" ST7789 240x320 + CST816S touch + microSD.
// The QR board: it can both scan and display animated UR codes (TZ 3.7), so
// it talks to Feather, ANON/NERO and Cake Wallet with no cable at all.
//
// Camera pinout is the Freenove ESP32-S3-WROVER one (XCLK 15, SIOD 4,
// SIOC 5, D0..D7 = 11/9/8/10/12/18/17/16, VSYNC 6, HREF 7, PCLK 13), which is
// the most widely cloned S3 camera wiring and leaves the high GPIOs free.
// The display, card and touch panel are the add-on wiring and use what is
// left: GPIO 38-42 and 47/48 for the SPI block, GPIO 1/2/14 for touch.
//
// NOTE ON THE TZ PIN TABLE: section 2.2 lists CAM_PIN_SIOC 39, which collides
// with TOUCH_INT 39 in the same table, and CAM_PIN_XCLK 10, which collides
// with nothing there but does collide with a display CS on any real wiring.
// boards/es3c28p.h already documents that the section 2.2 numbers are
// classic-ESP32 values; this board follows the same precedent and uses an
// S3 pinout that actually exists on shipping hardware.
//
// PIN BUDGET: 25 usable GPIOs, and this board uses all 25.  A camera costs
// 14 pins, so there is nothing left for a battery divider or a VBUS sense -
// the status bar simply hides the battery icon (mw_battery_percent() == -1).
//
// PSRAM is not optional here: an OV2640 frame buffer lives in PSRAM, and so
// does the cn_slow_hash scratchpad.
#ifndef BOARD_CONFIG_H
#define BOARD_CONFIG_H

#include "../src/config/app_config.h"

#define BOARD_NAME "ESP32S3-CAM-QR"

// ===== Display =====
#define DISPLAY_DRIVER   DISPLAY_ST7789
#define DISPLAY_WIDTH    240
#define DISPLAY_HEIGHT   320
#define DISPLAY_ROTATION 0
#define TFT_CS           21
#define TFT_DC           47
#define TFT_RST          48
#define TFT_MOSI         40
#define TFT_MISO         41
#define TFT_SCK          39
#define TFT_BL           42
#define TFT_BL_ACTIVE_HIGH 1
#define ST7789_COL_OFFSET 0
#define ST7789_ROW_OFFSET 0
#define DISPLAY_IPS      1
#define DISPLAY_SPI_HZ   40000000UL

// ===== Touch =====
#define HAS_TOUCH        1
#define TOUCH_DRIVER     TOUCH_CST816S
#define TOUCH_SDA        1
#define TOUCH_SCL        2
#define TOUCH_INT        14
#define TOUCH_RST        -1     // tied to the board reset net

// ===== SD Card (shares the display SPI bus) =====
#define HAS_SD           1
#define SD_CS            38
#define SD_MISO          41
#define SD_MOSI          40
#define SD_SCK           39

// ===== Camera (OV2640, Freenove ESP32-S3-WROVER pinout) =====
#define HAS_CAMERA       1
#define CAM_PIN_PWDN     -1
#define CAM_PIN_RESET    -1
#define CAM_PIN_XCLK     15
#define CAM_PIN_SIOD     4
#define CAM_PIN_SIOC     5
#define CAM_PIN_D7       16
#define CAM_PIN_D6       17
#define CAM_PIN_D5       18
#define CAM_PIN_D4       12
#define CAM_PIN_D3       10
#define CAM_PIN_D2       8
#define CAM_PIN_D1       9
#define CAM_PIN_D0       11
#define CAM_PIN_VSYNC    6
#define CAM_PIN_HREF     7
#define CAM_PIN_PCLK     13

// ===== Buttons =====
#define HAS_BUTTONS      0
#define BUTTON_UP        -1
#define BUTTON_DOWN      -1
#define BUTTON_LEFT      -1
#define BUTTON_RIGHT     -1
#define BUTTON_SELECT    -1
#define BUTTON_BACK      -1
#define BUTTON_ENCODER_A -1
#define BUTTON_ENCODER_B -1

// ===== Power =====
// Every usable GPIO is taken; no battery sense, no VBUS sense.
#define BATTERY_ADC_PIN  -1
#define USB_VBUS_DET_PIN -1

// ===== Feature flags =====
#define HAS_PSRAM        1
#define PSRAM_SIZE_MB    8
#define HAS_HMAC         1
#define HAS_USB_OTG      1

// ===== Default input mode =====
// 240x320 with touch -> full keyboard (TZ 5.5 AUTO rule).
#define DEFAULT_SEED_INPUT_MODE  SEED_INPUT_AUTO

#endif
