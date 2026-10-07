// ESP32-S3 + 128x64 SSD1306 OLED, no touch, 6 buttons + rotary encoder,
// microSD.  This is the TZ 2.5 reference configuration.
//
// Self-built from an ESP32-S3-DevKitC-1, a 0.96" I2C OLED, six tactile
// switches and an EC11 encoder - the cheapest way to a working Monero cold
// wallet, and the configuration that proves the UI really does work without
// an indev (LVGL navigates a lv_group from the button events).
//
// 128x64 is the minimum screen TZ 5.6 allows.  At that size the full
// keyboard cannot be drawn, so the board pins SEED_INPUT_SCROLL_KB; the
// TZ 5.7 flow (type 1-3 letters, pick from the candidate list) is what makes
// a 25-word seed tolerable on six buttons.
//
// Button semantics come from TZ 5.6 and are decoded in src/hal/buttons.cpp:
//   short Back        one character back
//   long Back  >800ms clear the current word prefix
//   very long >2500ms clear the whole phrase
// The encoder replaces Left/Right; Left/Right are still wired so the board
// works if the encoder is not fitted.
//
// Pin policy: see boards/README.md.  14 GPIOs used.
#ifndef BOARD_CONFIG_H
#define BOARD_CONFIG_H

#include "../src/config/app_config.h"

#define BOARD_NAME "ESP32S3-SSD1306-NO_SD"

// ===== Display =====
// Monochrome I2C OLED: there is no SPI panel bus and no backlight, so all of
// TFT_* stays -1.  src/hal/display.cpp keeps a 1024-byte 1 bpp shadow
// framebuffer, thresholds the RGB565 blits into it, and pushes dirty pages
// over I2C.  mw_display_backlight() maps onto the contrast register.
#define DISPLAY_DRIVER   DISPLAY_SSD1306
#define DISPLAY_WIDTH    128
#define DISPLAY_HEIGHT   64
#define DISPLAY_ROTATION 0
#define TFT_CS           -1
#define TFT_DC           -1
#define TFT_RST          -1
#define TFT_MOSI         -1
#define TFT_MISO         -1
#define TFT_SCK          -1
#define TFT_BL           -1
#define TFT_BL_ACTIVE_HIGH 1
#define OLED_I2C_SDA     8
#define OLED_I2C_SCL     9
#define OLED_I2C_ADDR    0x3C   // 0x3D on modules with the ADDR jumper moved
#define OLED_I2C_HZ      400000UL

// ===== Touch =====
#define HAS_TOUCH        0
#define TOUCH_DRIVER     TOUCH_NONE
#define TOUCH_SDA        -1
#define TOUCH_SCL        -1
#define TOUCH_INT        -1
#define TOUCH_RST        -1

// ===== SD Card (its own SPI bus - the OLED is on I2C) =====
#define HAS_SD           0
#define SD_CS            -1
#define SD_MISO          -1
#define SD_MOSI          -1
#define SD_SCK           -1

// ===== Camera =====
#define HAS_CAMERA       0
#define CAM_PIN_PWDN     -1
#define CAM_PIN_RESET    -1
#define CAM_PIN_XCLK     -1
#define CAM_PIN_SIOD     -1
#define CAM_PIN_SIOC     -1
#define CAM_PIN_D7       -1
#define CAM_PIN_D6       -1
#define CAM_PIN_D5       -1
#define CAM_PIN_D4       -1
#define CAM_PIN_D3       -1
#define CAM_PIN_D2       -1
#define CAM_PIN_D1       -1
#define CAM_PIN_D0       -1
#define CAM_PIN_VSYNC    -1
#define CAM_PIN_HREF     -1
#define CAM_PIN_PCLK     -1

// ===== Buttons =====
// Momentary switches to GND, read through the internal pull-ups; 20 ms
// debounce in src/hal/buttons.cpp.
#define HAS_BUTTONS      1
#define BUTTON_ACTIVE_LOW 1
#define BUTTON_UP        4
#define BUTTON_DOWN      5
#define BUTTON_LEFT      6
#define BUTTON_RIGHT     7
#define BUTTON_SELECT    15
#define BUTTON_BACK      16
// EC11 detented encoder; both lines get internal pull-ups and an edge
// interrupt, and four quadrature counts make one detent.
#define BUTTON_ENCODER_A 17
#define BUTTON_ENCODER_B 18
#define ENCODER_COUNTS_PER_DETENT 4

// ===== Power =====
#define BATTERY_ADC_PIN  -1     // USB powered
#define USB_VBUS_DET_PIN -1

// ===== Feature flags =====
#define HAS_PSRAM        1
#define PSRAM_SIZE_MB    8
#define HAS_HMAC         1
#define HAS_USB_OTG      1

// ===== Default input mode =====
// TZ 5.5: HAS_TOUCH = 0 -> scrolling keyboard.  Pinned rather than AUTO
// because nothing else fits on 128x64.
#define DEFAULT_SEED_INPUT_MODE  SEED_INPUT_SCROLL_KB

#endif
