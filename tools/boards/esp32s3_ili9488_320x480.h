// ESP32-S3 + 3.5" ILI9488 320x480 + XPT2046 resistive touch + microSD.
//
// The classic "3.5 inch TFT LCD touch shield" glass (the one shipped with an
// XPT2046 on the same SPI header) driven from an ESP32-S3 devkit.  This is
// the only board in the tree with a resistive panel, which is why it is the
// one that really needs mw_touch_calibrate(): an XPT2046 reports raw 12-bit
// ADC counts, and the 3-point affine map in src/hal/touch.cpp is what turns
// them into pixels.
//
// Bus sharing: panel, touch controller and card all hang off the same
// SCK/MOSI/MISO with three separate chip selects.  src/hal/display.cpp sees
// SD_SCK == TFT_SCK and switches Arduino_GFX to the SPIClass backend so all
// three arbitrate through beginTransaction(); the XPT2046 runs its own 2 MHz
// transaction inside that scheme.
//
// Pin policy: see boards/README.md.  11 GPIOs used.
#ifndef BOARD_CONFIG_H
#define BOARD_CONFIG_H

#include "../src/config/app_config.h"

#define BOARD_NAME "ESP32S3-ILI9488-320x480"

// ===== Display =====
#define DISPLAY_DRIVER   DISPLAY_ILI9488
#define DISPLAY_WIDTH    320
#define DISPLAY_HEIGHT   480
#define DISPLAY_ROTATION 0
#define TFT_CS           10
#define TFT_DC           9
#define TFT_RST          8
#define TFT_MOSI         11
#define TFT_MISO         13
#define TFT_SCK          12
#define TFT_BL           14
#define TFT_BL_ACTIVE_HIGH 1
#define DISPLAY_IPS      0
// The ILI9488 cannot take 16 bpp over SPI, so every pixel goes out as three
// bytes; 27 MHz is what these modules reliably sustain with that overhead.
#define DISPLAY_SPI_HZ   27000000UL

// ===== Touch =====
// XPT2046 is SPI, not I2C: TOUCH_SDA/TOUCH_SCL stay -1 and TOUCH_CS/TOUCH_INT
// carry the chip select and the PENIRQ line.
#define HAS_TOUCH        1
#define TOUCH_DRIVER     TOUCH_XPT2046
#define TOUCH_SDA        -1
#define TOUCH_SCL        -1
#define TOUCH_CS         16
#define TOUCH_INT        15     // PENIRQ, active low
#define TOUCH_RST        -1
#define TOUCH_SPI_HZ     2000000UL
// Resistive panels are usually wired with X and Y the other way round from
// the glass; the calibration absorbs it either way, this only makes the
// uncalibrated first boot land close enough to hit the targets.
#define TOUCH_SWAP_XY    1

// ===== SD Card (shares the display SPI bus) =====
#define HAS_SD           1
#define SD_CS            21
#define SD_MISO          13
#define SD_MOSI          11
#define SD_SCK           12

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
#define BATTERY_ADC_PIN  4      // ADC1_CH3, 2:1 divider
#define BATTERY_DIV_NUM  2
#define BATTERY_DIV_DEN  1
#define BATTERY_MV_EMPTY 3300
#define BATTERY_MV_FULL  4180
#define USB_VBUS_DET_PIN -1

// ===== Feature flags =====
#define HAS_PSRAM        1
#define PSRAM_SIZE_MB    8
#define HAS_HMAC         1
#define HAS_USB_OTG      1

// ===== Default input mode =====
// 320x480 with touch -> full keyboard (TZ 5.5 AUTO rule).
#define DEFAULT_SEED_INPUT_MODE  SEED_INPUT_AUTO

#endif
