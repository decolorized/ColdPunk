// ES3C28P - ESP32-S3 + 2.8" ILI9341 240x320 + FT6336G touch + microSD.
// Board configuration for ES3C28P (LCDWiki).
// Pinout verified against official LCDWiki specification (CR2025-M16872).
#ifndef BOARD_CONFIG_H
#define BOARD_CONFIG_H

// app_config.h лежит в src/config/ Ч путь ќ“ папки скетча.
// (Arduino IDE добавл€ет папку скетча в include path автоматически.)
#include "src/config/app_config.h"

#define BOARD_NAME "ES3C28P"

// ===== Display =====
#define DISPLAY_DRIVER   DISPLAY_ILI9341
#define DISPLAY_WIDTH    240                  // physical panel, rotation 0
#define DISPLAY_HEIGHT   320
#define DISPLAY_ROTATION 1                    // landscape: logical 320x240
#define DISPLAY_IPS      1                    // ILI9341V на этом модуле Ч IPS
#define DISPLAY_SPI_HZ   40000000UL           // 40 ћ√ц, как в рабочем скетче

#define TFT_CS           10
#define TFT_DC           46
#define TFT_RST          -1    // RST подключЄн к CHIP_PU (пин сброса платы)
#define TFT_MOSI         11
#define TFT_MISO         13
#define TFT_SCK          12
#define TFT_BL           45    // ѕодсветка на GPIO45
#define TFT_BL_ACTIVE_HIGH 1   // BSS138 N-channel, активный ¬џ—ќ »…
                               // (в рабочем LovyanGFX-скетче invert = false)

// ===== Touch =====
#define HAS_TOUCH        1
#define TOUCH_DRIVER     TOUCH_FT6336G
#define TOUCH_SDA        16
#define TOUCH_SCL        15
#define TOUCH_INT        17
#define TOUCH_RST        18
#define TOUCH_SWAP_XY    0
#define TOUCH_I2C_HZ     400000UL

// ===== SD Card =====
// The card slot is wired for SDIO (SD_MMC), not SPI. 4-bit bus; the driver
// falls back to 1-bit (CLK, CMD, D0) when the 4-bit mount fails.
#define HAS_SD           1
#define MW_SD_SDMMC      1
#define SD_CLK           38
#define SD_CMD           40
#define SD_D0            39
#define SD_D1            41
#define SD_D2            48
#define SD_D3            47
// SPI-mode pins are not used on this board.
#define SD_CS            -1
#define SD_MISO          -1
#define SD_MOSI          -1
#define SD_SCK           -1
#define SD_DETECT        -1

// ===== Camera =====
#define HAS_CAMERA       0

// ===== Buttons =====
#define HAS_BUTTONS      0
#define BUTTON_ACTIVE_LOW 1

// ===== Feature flags =====
#define HAS_PSRAM        1
#define PSRAM_SIZE_MB    8
#define HAS_USB_OTG      1

// ===== Battery =====
// Ќа модуле есть TP4054 и делитель R14/R15 (200K/200K).
// ѕин ADC не выведен в документации Ч оставл€ем -1.
#define BATTERY_ADC_PIN  -1
#define BATTERY_DIV_NUM   2
#define BATTERY_DIV_DEN   1
#define BATTERY_MV_EMPTY  3300
#define BATTERY_MV_FULL   4180
#define USB_VBUS_DET_PIN  -1

// ===== Default input mode =====
#define DEFAULT_SEED_INPUT_MODE  SEED_INPUT_AUTO

// ===== Diagnostics =====
// Serial0 на UART0 (GPIO43/44), а не на USB.
// #define MW_SERIAL_USE_UART0

#endif