// ============================================================================
//  BOARD SELECTION  -  edit this file, nothing else (TZ 2.1: no auto-detect).
// ============================================================================
//
// Pick exactly one board by uncommenting its #define, or point the #include at
// your own file in boards/. See boards/README.md for the full list and
// for how to add a new board.
//
#ifndef BOARD_CONFIG_H_SELECTOR
#define BOARD_CONFIG_H_SELECTOR

 #define MW_BOARD_ES3C28P
// #define MW_BOARD_ST7789_240x320
// #define MW_BOARD_GC9A01_ROUND
// #define MW_BOARD_ILI9488_320x480
// #define MW_BOARD_ST7701S_480x480
// #define MW_BOARD_SSD1306_BUTTONS
//#define MW_BOARD_ST7789_240x240
// #define MW_BOARD_CAM_QR

#if defined(MW_BOARD_ES3C28P)
#  include "boards/es3c28p.h"

#elif defined(MW_BOARD_TOUCH_LCD_2_240x320)
#  include "boards/esp32s3_touch_lcd_2_240x320.h "


#elif defined(MW_BOARD_ST7789_240x320)
#  include "boards/esp32s3_st7789_240x320.h"

#elif defined(MW_BOARD_ST7789_240x240)
#  include "boards/esp32s3_st7789_240x240.h"


#elif defined(ESP32S3_ST7735S_128x160)
#  include "boards/esp32s3_st7735s_128x160.h"

#elif defined(MW_BOARD_GC9A01_ROUND)
#  include "boards/esp32s3_gc9a01_round.h"
#elif defined(MW_BOARD_ILI9488_320x480)
#  include "boards/esp32s3_ili9488_320x480.h"
#elif defined(MW_BOARD_ST7701S_480x480)
#  include "boards/esp32s3_st7701s_480x480.h"
#elif defined(MW_BOARD_SSD1306_BUTTONS)
#  include "boards/esp32s3_ssd1306_buttons.h"
#elif defined(MW_BOARD_SSD1306_NO_SD)
#  include "boards/esp32s3_ssd1306_no_sd.h"
#elif defined(MW_BOARD_CAM_QR)
#  include "boards/esp32s3_cam_qr.h"
#else
#  error "No board selected in MoneroColdWallet/board_config.h"
#endif

#endif

// Serial goes over UART0 (GPIO43 TX, GPIO44 RX) because DIS_USB_SERIAL_JTAG
// is burned: the native USB is now dedicated to USB-OTG.
#define MW_SERIAL_USE_UART0 1
//#define HAS_HMAC         0