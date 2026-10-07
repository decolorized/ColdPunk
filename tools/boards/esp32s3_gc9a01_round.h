// ESP32-S3 + 1.28" GC9A01 240x240 round LCD + CST816S touch.
//
// Modelled on the Waveshare ESP32-S3-Touch-LCD-1.28: a round wearable-style
// board with a Li-ion charger and no card slot.  That absence is honest and
// deliberate here - it exercises the HAS_SD = 0 path, and the board still has
// two working couriers for the air gap (TZ 3.1): USB MSC/MTP over the native
// OTG port, and animated UR QR codes on the screen.
//
// Round-display notes:
//   * The usable rectangle inscribed in a 240 px circle is only 170x170, so
//     the UI must keep controls away from the corners.  TZ 5.5 puts anything
//     under 240x240 on the scrolling keyboard; this panel is exactly 240x240,
//     but the round bezel makes the full keyboard unusable in practice, so
//     the board pins SEED_INPUT_SCROLL_KB rather than leaving it to AUTO.
//   * GC9A01 is write-only over SPI: there is no MISO line at all.
//
// Pin policy: see boards/README.md.  11 GPIOs used, none of them strapping,
// flash, PSRAM or USB pins.
#ifndef BOARD_CONFIG_H
#define BOARD_CONFIG_H

#include "../src/config/app_config.h"

#define BOARD_NAME "ESP32S3-GC9A01-ROUND"

// ===== Display =====
#define DISPLAY_DRIVER   DISPLAY_GC9A01
#define DISPLAY_WIDTH    240
#define DISPLAY_HEIGHT   240
#define DISPLAY_ROTATION 0
#define TFT_CS           9
#define TFT_DC           8
#define TFT_RST          14
#define TFT_MOSI         11
#define TFT_MISO         -1     // GC9A01 has no read path
#define TFT_SCK          10
#define TFT_BL           2
#define TFT_BL_ACTIVE_HIGH 1
#define DISPLAY_IPS      1
#define DISPLAY_SPI_HZ   40000000UL

// ===== Touch =====
#define HAS_TOUCH        1
#define TOUCH_DRIVER     TOUCH_CST816S
#define TOUCH_SDA        6
#define TOUCH_SCL        7
#define TOUCH_INT        5
#define TOUCH_RST        13

// ===== SD Card =====
// No slot on this board: data exchange is USB MSC/MTP or QR (TZ 3.1).
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
// On-board Li-ion charger; the cell is divided 2:1 into ADC1_CH0 (GPIO1).
#define BATTERY_ADC_PIN  1
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
#define DEFAULT_SEED_INPUT_MODE  SEED_INPUT_SCROLL_KB

#endif
