// ES3C28P - ESP32-S3 + 2.8" ILI9341V IPS 240x320 + FT6336G touch + microSD.
// Board configuration for ES3C28P (LCDWiki).
// Pinout verified against official LCDWiki specification (CR2025-M16872).
#ifndef BOARD_CONFIG_H
#define BOARD_CONFIG_H

// From the repo (boards/ next to MoneroColdWallet/) or from a copy of this
// file placed in the sketch folder, where src/ is on the include path.
#if defined(__has_include)
#  if __has_include("../MoneroColdWallet/src/config/app_config.h")
#    include "../MoneroColdWallet/src/config/app_config.h"
#  else
#    include "src/config/app_config.h"
#  endif
#else
#  include "../MoneroColdWallet/src/config/app_config.h"
#endif
#define BOARD_NAME "ES3C28P"

// ===== Display =====
// Landscape, USB connector on the left. DISPLAY_WIDTH/HEIGHT are the size
// AFTER rotation (display.cpp refuses an odd rotation with WIDTH < HEIGHT).
//   portrait:              WIDTH 240, HEIGHT 320, ROTATION 0 (or 2)
//   landscape, USB right:  WIDTH 320, HEIGHT 240, ROTATION 3
#define DISPLAY_DRIVER   DISPLAY_ILI9341
#define DISPLAY_WIDTH    320
#define DISPLAY_HEIGHT   240
#define DISPLAY_ROTATION 1
#define DISPLAY_IPS      1                 // ILI9341V on this module is IPS
#define DISPLAY_SPI_HZ   40000000UL
#define TFT_CS           10
#define TFT_DC           46
#define TFT_RST          -1   // RST is tied to CHIP_PU (board reset)
#define TFT_MOSI         11
#define TFT_MISO         13
#define TFT_SCK          12
#define TFT_BL           45   // backlight, BSS138 N-channel
#define TFT_BL_ACTIVE_HIGH 1

// ===== Touch =====
// The FT6336G reports in the glass's own portrait axes (240x320); touch.cpp
// rotates them with DISPLAY_ROTATION (src/hal/touch_map.h), so these flags
// stay 0 for this module in every rotation. They exist for a glass mounted
// differently. Symptoms on Settings -> Touch test, in rotation 1:
//   dot mirrored left-right          -> TOUCH_MIRROR_Y 1
//   dot mirrored up-down             -> TOUCH_MIRROR_X 1
//   finger moves right, dot moves down -> TOUCH_SWAP_XY 1
// (MIRROR_X/Y act on the unrotated panel axes, hence the cross-over.)
#define HAS_TOUCH        1
#define TOUCH_DRIVER     TOUCH_FT6336G
#define TOUCH_SDA        16
#define TOUCH_SCL        15
#define TOUCH_INT        17
#define TOUCH_RST        18
#define TOUCH_SWAP_XY    0
#define TOUCH_MIRROR_X   0
#define TOUCH_MIRROR_Y   0
#define TOUCH_I2C_HZ     400000UL

// ===== SD Card =====
// The card is wired for SDIO, but src/hal/sdcard.cpp drives SD over SPI only
// (SD.begin(SD_CS, SPI, ...)), so the slot cannot be used: HAS_SD 0.
#define HAS_SD           0
#define SD_CS            -1
#define SD_MISO          -1
#define SD_MOSI          -1
#define SD_SCK           -1
#define SD_DETECT        -1
// SDIO pins, for a future SD_MMC driver:
//   SD_CLK 38, SD_CMD 40, SD_D0 39, SD_D1 41, SD_D2 48, SD_D3 47

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

// ===== Feature flags =====
#define HAS_PSRAM        1
#define PSRAM_SIZE_MB    8
#define HAS_HMAC         1
#define HAS_USB_OTG      1

// ===== Battery / USB =====
// TP4054 charger with a 200K/200K divider (R14/R15), but the ADC pin is not
// documented, so battery and VBUS sensing stay off (-1).
#define BATTERY_ADC_PIN  -1
#define BATTERY_DIV_NUM   2
#define BATTERY_DIV_DEN   1
#define USB_VBUS_DET_PIN -1

// ===== Default input mode =====
#define DEFAULT_SEED_INPUT_MODE  SEED_INPUT_AUTO

#endif
