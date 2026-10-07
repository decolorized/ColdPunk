// ESP32-S3 + 2.4" ST7789 240x320 + CST816S capacitive touch + microSD.
//
// Modelled on the widely available "ESP32-S3 2.4/2.8 inch SPI TFT with
// capacitive touch" modules (Waveshare ESP32-S3-Touch-LCD-2.8 and the many
// clones).  As with boards/es3c28p.h, the pin numbers here are the S3-correct
// assignment for a self-wired board rather than a transcription of one
// vendor's schematic - check yours before the first flash.
//
// Pin policy shared by every board in this directory (see boards/README.md):
//   never used: 0, 3      strapping (BOOT, JTAG source select)
//               19, 20    USB OTG D-/D+ - the wallet needs USB MSC/MTP
//               26..32    SPI flash
//               33..37    octal PSRAM on -N8R8/-N16R8 modules
//               43, 44    UART0 console
//               45, 46    strapping (VDD_SPI, boot log)
// That leaves 25 usable GPIOs; this board uses 13 of them.
#ifndef BOARD_CONFIG_H
#define BOARD_CONFIG_H

#include "../src/config/app_config.h"

#define BOARD_NAME "ESP32S3-ST7789-240x320"

// ===== Display =====
#define DISPLAY_DRIVER   DISPLAY_ST7789
#define DISPLAY_WIDTH    240
#define DISPLAY_HEIGHT   240
#define DISPLAY_ROTATION 0
#define TFT_CS           10
#define TFT_DC           9
#define TFT_RST          8
#define TFT_MOSI         11
#define TFT_MISO         13
#define TFT_SCK          12
#define TFT_BL           14
#define TFT_BL_ACTIVE_HIGH 1
// A 240x320 ST7789 is flush with the controller RAM; only the 240x240 panels
// need an offset (row 80 in some rotations).
#define ST7789_COL_OFFSET 0
#define ST7789_ROW_OFFSET 0
#define DISPLAY_IPS      1
#define DISPLAY_SPI_HZ   40000000UL

// ===== Touch =====
#define HAS_TOUCH        0
#define TOUCH_DRIVER     TOUCH_CST816S
#define TOUCH_SDA        -1
#define TOUCH_SCL        -1
#define TOUCH_INT        -1
#define TOUCH_RST        -1

// ===== SD Card (shares the display SPI bus) =====
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
#define HAS_BUTTONS      1
#define BUTTON_UP        -1
#define BUTTON_DOWN      -1
#define BUTTON_LEFT      -1
#define BUTTON_RIGHT     -1
#define BUTTON_SELECT    -1
#define BUTTON_BACK      -1
#define BUTTON_ENCODER_A -1
#define BUTTON_ENCODER_B -1

// ===== Power =====
// Li-ion through a 2:1 divider on an ADC1 channel (GPIO4 = ADC1_CH3).  ADC2
// is unusable whenever the RF block is clocked, and even on an air-gapped
// build ADC1 is the safer habit.
#define BATTERY_ADC_PIN  4
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
// 240x320 with touch -> full keyboard (TZ 5.5 AUTO rule).
#define DEFAULT_SEED_INPUT_MODE  SEED_INPUT_AUTO

#endif
