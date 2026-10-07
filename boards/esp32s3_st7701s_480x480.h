// ESP32-S3 + 4.0" ST7701S 480x480 square RGB panel + GT911 touch.
//
// Modelled on the Guition ESP32-S3-4848S040 (and the Waveshare
// ESP32-S3-Touch-LCD-4 family): a 480x480 IPS panel driven through the S3
// LCD_CAM peripheral in 16-bit RGB565 mode, with the controller's registers
// loaded once over a 3-wire SPI link before the panel starts free-running.
//
// PIN BUDGET - the reason this board looks different from the others
// ------------------------------------------------------------------
// An RGB panel needs 16 data lines + DE/VSYNC/HSYNC/PCLK + 3 init-SPI lines +
// backlight = 24 GPIOs, and the touch controller wants 2 more.  The S3 has
// exactly 25 pins left once strapping, flash, octal PSRAM, USB and UART0 are
// excluded, so 26 does not fit.  The commercial 4848S040 solves this by
// putting RGB data on GPIO0, 3, 20 and 46 - i.e. on the strapping pins and on
// one of the USB pins, which costs it native USB entirely.
//
// This configuration keeps USB (TZ 3.3-3.5 need it) and spends GPIO45 on the
// backlight instead.  GPIO45 is the VDD_SPI strapping pin: it is sampled once
// at reset and must be LOW then, which it is - the LEDC channel is only
// attached later, in mw_display_backlight().  Put a pulldown on it.
//
// Consequences, both deliberate:
//   * no microSD (HAS_SD 0) - exchange is USB MSC/MTP or QR (TZ 3.1);
//   * GT911 INT and RST are tied to the panel reset net rather than to their
//     own GPIOs, so src/hal/touch.cpp probes both I2C addresses (0x5D, 0x14).
//
// PSRAM: an RGB panel streams its framebuffer straight out of PSRAM, so this
// board wants the octal (-N16R8) variant.  That is also why GPIO33..37 are
// off the table here.
#ifndef BOARD_CONFIG_H
#define BOARD_CONFIG_H

#include "../src/config/app_config.h"

#define BOARD_NAME "ESP32S3-ST7701S-480x480"

// ===== Display =====
#define DISPLAY_DRIVER   DISPLAY_ST7701S
#define DISPLAY_WIDTH    480
#define DISPLAY_HEIGHT   480
#define DISPLAY_ROTATION 0
// No SPI panel bus: TFT_CS/DC/MOSI/SCK/MISO are meaningless for an RGB panel.
// TFT_RST is passed to Arduino_RGB_Display and -1 means "tied to EN".
#define TFT_CS           -1
#define TFT_DC           -1
#define TFT_RST          -1
#define TFT_MOSI         -1
#define TFT_MISO         -1
#define TFT_SCK          -1
#define TFT_BL           45     // see the pin-budget note above
#define TFT_BL_ACTIVE_HIGH 1
#define DISPLAY_IPS      1

// ----- RGB565 data bus -----
#define LCD_R0           1
#define LCD_R1           2
#define LCD_R2           4
#define LCD_R3           5
#define LCD_R4           6
#define LCD_G0           7
#define LCD_G1           8
#define LCD_G2           9
#define LCD_G3           10
#define LCD_G4           11
#define LCD_G5           12
#define LCD_B0           13
#define LCD_B1           14
#define LCD_B2           15
#define LCD_B3           16
#define LCD_B4           17

// ----- RGB sync -----
#define LCD_DE           18
#define LCD_VSYNC        21
#define LCD_HSYNC        38
#define LCD_PCLK         39

// ----- 3-wire SPI used once, to push the ST7701S init registers -----
#define LCD_SPI_CS       40
#define LCD_SPI_SCK      41
#define LCD_SPI_SDA      42

// ----- panel timings (typical 480x480 ST7701S) -----
#define LCD_HSYNC_POLARITY    1
#define LCD_HSYNC_FRONT_PORCH 10
#define LCD_HSYNC_PULSE_WIDTH 8
#define LCD_HSYNC_BACK_PORCH  50
#define LCD_VSYNC_POLARITY    1
#define LCD_VSYNC_FRONT_PORCH 10
#define LCD_VSYNC_PULSE_WIDTH 8
#define LCD_VSYNC_BACK_PORCH  20
#define LCD_PCLK_ACTIVE_NEG   1
#define LCD_PREFER_SPEED      16000000L
// Arduino_GFX ships st7701_type1..type9_init_operations; which one is correct
// depends on the glass, not on the controller.  type1 matches the common
// 4848S040 panel.  If the display comes up with wrong colours or a shifted
// image, this is the define to change.
#define LCD_ST7701_INIT_OPS     st7701_type1_init_operations
#define LCD_ST7701_INIT_OPS_LEN sizeof(st7701_type1_init_operations)

// ===== Touch =====
#define HAS_TOUCH        1
#define TOUCH_DRIVER     TOUCH_GT911
#define TOUCH_SDA        47
#define TOUCH_SCL        48
#define TOUCH_INT        -1     // tied to the panel reset net (see above)
#define TOUCH_RST        -1

// ===== SD Card =====
// No pins left; see the pin-budget note.  USB MSC/MTP and QR carry the files.
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
// Mains/USB powered, no cell and no free ADC pin: the battery indicator of
// TZ 4.2 is hidden when mw_battery_percent() returns -1.
#define BATTERY_ADC_PIN  -1
#define USB_VBUS_DET_PIN -1

// ===== Feature flags =====
#define HAS_PSRAM        1
#define PSRAM_SIZE_MB    8
#define HAS_HMAC         1
#define HAS_USB_OTG      1

// ===== Default input mode =====
// 480x480 with touch -> full keyboard (TZ 5.5 AUTO rule).
#define DEFAULT_SEED_INPUT_MODE  SEED_INPUT_AUTO

#endif
