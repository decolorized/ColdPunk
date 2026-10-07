// ESP32-S3 + 1.8" 128x160 ST7735S TFT, 6 кнопок + энкодер, microSD.
//
// 1.8" 128x160 ST7735S по SPI — самый распространённый маленький цветной
// дисплей для самодельных cold wallet: дешёвый, есть везде, и достаточно
// крупный, чтобы QR-код считывался камерой телефона с обычного расстояния.
//
// 128x160 меньше "комфортных" 240x320, но больше минимальных 128x64 из TZ 5.6.
// Полноэкранная клавиатура сюда не влезает, поэтому плата жёстко фиксирует
// SEED_INPUT_SCROLL_KB и использует схему TZ 5.7 (ввод 1-3 букв, выбор из
// списка кандидатов). Шесть кнопок + энкодер — это референсная схема TZ 2.5.
//
// Семантика кнопок из TZ 5.6, декодируется в src/hal/buttons.cpp:
//   короткое Back        один символ назад
//   длинное Back  >800ms очистить префикс текущего слова
//   очень длинное >2500ms очистить всю фразу
// Энкодер заменяет Left/Right; Left/Right всё равно разведены, чтобы плата
// работала и без энкодера.
//
// Политика пинов: см. boards/README.md. Избегаем strapping (0, 3, 45, 46),
// USB OTG (19, 20), flash/PSRAM (26..37 на octal-модулях) и UART0 (43, 44).
// Эта плата использует 14 GPIO.
#ifndef BOARD_CONFIG_H
#define BOARD_CONFIG_H

#include "../src/config/app_config.h"

#define BOARD_NAME "ESP32S3-ST7735S-128x160"

// ===== Дисплей =====
// ST7735S 128x160 по SPI. У панели своя память контроллера, принимает
// RGB565 напрямую, так же как и путь ST7789.
#define DISPLAY_DRIVER   DISPLAY_ST7735S
#define DISPLAY_WIDTH    128
#define DISPLAY_HEIGHT   160
#define DISPLAY_ROTATION 0
#define TFT_CS           10 //white
#define TFT_DC           9 //green
#define TFT_RST          8  //yellow 1
#define TFT_MOSI         11// brown
#define TFT_MISO         13//blue
#define TFT_SCK          12//yollow2
#define TFT_BL           14//fiolet   black-gnd
#define TFT_BL_ACTIVE_HIGH 1
// Панели ST7735S отличаются внутренним смещением RAM: у одних видимая
// область 128x160 начинается с колонки 0 / строки 0, у других — с 0/32
// или 2/1 в зависимости от модуля. Если картинка смещена — правьте эти
// два значения.
#define ST7735S_COL_OFFSET 26
#define ST7735S_ROW_OFFSET 0
#define DISPLAY_IPS      0
#define DISPLAY_SPI_HZ   20000000UL

// ===== Тач =====
#define HAS_TOUCH        0
#define TOUCH_DRIVER     TOUCH_NONE
#define TOUCH_SDA        -1
#define TOUCH_SCL        -1
#define TOUCH_INT        -1
#define TOUCH_RST        -1

// ===== SD-карта (делит SPI-шину с дисплеем) =====
#define HAS_SD           1
#define SD_CS            21
#define SD_MISO          13
#define SD_MOSI          11
#define SD_SCK           12

// ===== Камера =====
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

// ===== Кнопки =====
// Тактовые кнопки на GND, читаются через внутренние pull-up; антидребезг
// 20 мс в src/hal/buttons.cpp.
#define HAS_BUTTONS      1
#define BUTTON_ACTIVE_LOW 1
#define BUTTON_UP        4
#define BUTTON_DOWN      5
#define BUTTON_LEFT      6
#define BUTTON_RIGHT     7
#define BUTTON_SELECT    15
#define BUTTON_BACK      16
// EC11 с фиксацией; обе линии получают внутренние pull-up и прерывание по
// фронту, четыре квадратурных счёта дают один щелчок.
#define BUTTON_ENCODER_A 17
#define BUTTON_ENCODER_B 18
#define ENCODER_COUNTS_PER_DETENT 4

// ===== Питание =====
// Li-ion через делитель 2:1 на канале ADC1 (GPIO1 = ADC1_CH0).
// ADC2 непригоден, когда тактируется RF-блок; ADC1 — более безопасная
// привычка даже в air-gapped сборке.
#define BATTERY_ADC_PIN  1
#define BATTERY_DIV_NUM  2
#define BATTERY_DIV_DEN  1
#define BATTERY_MV_EMPTY 3300
#define BATTERY_MV_FULL  4180
#define USB_VBUS_DET_PIN -1

// ===== Фичи =====
#define HAS_PSRAM        1
#define PSRAM_SIZE_MB    8
#define HAS_HMAC         1
#define HAS_USB_OTG      1

// ===== Режим ввода по умолчанию =====
// TZ 5.5: HAS_TOUCH = 0 и экран меньше 240x320 -> клавиатура со скроллом.
#define DEFAULT_SEED_INPUT_MODE  SEED_INPUT_SCROLL_KB

#endif