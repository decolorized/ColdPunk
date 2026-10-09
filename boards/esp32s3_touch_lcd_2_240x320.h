// ESP32-S3-Touch-LCD-2 - Waveshare 2" IPS (ST7789T3) + тач CST816D + IMU QMI8658
#ifndef BOARD_CONFIG_H
#define BOARD_CONFIG_H

// app_config.h лежит в src/config/
#include "src/config/app_config.h"

#define BOARD_NAME "ESP32-S3-Touch-LCD-2"

// ===== Дисплей =====
// На этой плате установлена IPS-матрица 2 дюйма с драйвером ST7789T3
#define DISPLAY_DRIVER   DISPLAY_ST7789       // ST7789T3
// DISPLAY_WIDTH/HEIGHT - физический размер панели (при rotation 0).
// Логический размер после поворота прошивка берёт у драйвера в рантайме.
#define DISPLAY_WIDTH    240
#define DISPLAY_HEIGHT   320
#define DISPLAY_ROTATION 1                    // 0/2 = портрет 240x320, 1/3 = альбом 320x240
#define DISPLAY_IPS      1                    // Панель IPS
#define DISPLAY_SPI_HZ   40000000UL           // 40 МГц (подтверждено рабочими проектами)

// Пины SPI для дисплея (согласно MicroPythonOS и CircuitPython)
#define TFT_CS           45
#define TFT_DC           42
#define TFT_RST          -1                   // Аппаратный сброс не подключён отдельно
#define TFT_MOSI         38
#define TFT_MISO         40
#define TFT_SCK          39
#define TFT_BL           1                    // Управление подсветкой
#define TFT_BL_ACTIVE_HIGH 1                  // Требует подтверждения по схеме

// ===== Тачскрин (CST816D) =====
#define HAS_TOUCH        1
#define TOUCH_DRIVER     TOUCH_CST816D        // = драйвер CST816S (та же карта регистров)
#define TOUCH_SDA        48
#define TOUCH_SCL        47
#define TOUCH_INT        -1                   // Прерывание не используется (см. рабочие проекты)
#define TOUCH_RST        -1                   // Аппаратный сброс не используется
#define TOUCH_SWAP_XY    0
#define TOUCH_I2C_HZ     400000UL

// ===== SD-карта =====
// TF-слот в режиме SPI на общей шине с дисплеем (схема Waveshare
// ESP32-S3-Touch-LCD-2: SD_CS IO41, SD_MOSI IO38, SD_SCLK IO39, SD_MISO IO40).
// SD_SCK == TFT_SCK, поэтому display_drivers.h включает MW_SPI_BUS_SHARED:
// дисплей и карта делят SPIClass через beginTransaction()/endTransaction().
#define HAS_SD           1
#define SD_CS            41
#define SD_MISO          40
#define SD_MOSI          38
#define SD_SCK           39
#define SD_DETECT        -1                   // Датчика наличия карты нет

// ===== Камера =====
// На плате есть 24-pin разъём для OV2640 / OV5640.
#define HAS_CAMERA       0                    // Требуется уточнение распиновки по схеме

// ===== Кнопки =====
#define HAS_BUTTONS      0
#define BUTTON_ACTIVE_LOW 1

// ===== Флаги возможностей =====
#define HAS_PSRAM        1
#define PSRAM_SIZE_MB    8
#define HAS_USB_OTG      1

// ===== Батарея =====
// Разъём MX1.25 для Li-Po аккумулятора, контроллер заряда TP4054.
#define BATTERY_ADC_PIN  -1                   // ADC-пин не указан в документации
#define BATTERY_DIV_NUM   2
#define BATTERY_DIV_DEN   1
#define BATTERY_MV_EMPTY  3300
#define BATTERY_MV_FULL   4180
#define USB_VBUS_DET_PIN  -1

// ===== Режим ввода по умолчанию =====
#define DEFAULT_SEED_INPUT_MODE  SEED_INPUT_AUTO

// ===== Диагностика =====
// #define MW_SERIAL_USE_UART0

#endif