# ColdPunk boards

Per-board notes: what is on the board, how to select it in `board_config.h`,
what to wire where, and how to flash it. The pin settings themselves live in
`boards/*.h` (shared rules and the table of all headers: `boards/README.md`).

| Board | Header / macro | Display | Input | SD | What to wire | Status |
| --- | --- | --- | --- | --- | --- | --- |
| [ES3C28P (LCDWiki 2.8")](es3c28p.md) | `boards/es3c28p.h` · `MW_BOARD_ES3C28P` | ILI9341 2.8" 240×320, IPS | FT6336G touch | yes, SDIO | nothing, all on board | tested |
| [Waveshare ESP32-S3-Touch-LCD-2](waveshare-esp32-s3-touch-lcd-2.md) | `boards/esp32s3_touch_lcd_2_240x320.h` · `MW_BOARD_TOUCH_LCD_2` | ST7789T3 2" 240×320, IPS | CST816D touch | yes, SPI | nothing, all on board | tested |
| [YD-ESP32-S3 + ST7789 240×240 + buttons](yd-esp32-s3-st7789-240x240.md) | `boards/esp32s3_st7789_240x240.h` · `MW_BOARD_ST7789_240x240` | ST7789 1.3"/1.54" 240×240, module without CS | 6 buttons | no | display and buttons, by wire | self-built |

A board is selected with one line in `board_config.h`: uncomment its
`#define MW_BOARD_...` and keep all others commented out. Then `build.bat` /
`./build.sh`, and `flash.bat` / `./flash.sh` from the `firmware/...` folder,
as in the project README.

## Common to all boards

- An ESP32-S3 module with 8 MB PSRAM (N8R8 / N16R8 / S3R8). The firmware does
  not run without PSRAM.
- The link to the PC is the chip's native USB (GPIO19/20): after the password
  the device shows up as "Monero Cold Wallet" (HID). Before the password and
  after a lock it is not on USB.
- Flashing over native USB: hold **BOOT**, plug in the cable (or press RESET),
  release BOOT — "USB JTAG/serial debug unit" appears; run `flash.bat`. The
  script notices that the chip is already waiting.
- A board with a USB-UART bridge (CH340 / CH343 / CP210x) and the usual
  auto-reset circuit is flashed through it without the button. Settings →
  "Flash only with BOOT" does not close that path: for the chip the circuit
  is the button.
