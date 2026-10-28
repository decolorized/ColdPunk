# Waveshare ESP32-S3-Touch-LCD-2 — 2" ESP32-S3 with touch

A ready-made Waveshare board: nothing to wire. Tested.

## On the board

| | |
| --- | --- |
| MCU | ESP32-S3R8 (8 MB in-package PSRAM), 16 MB flash |
| Display | 2" IPS ST7789T3, 240×320; the firmware uses landscape 320×240 (`DISPLAY_ROTATION 1`) |
| Touch | CST816D capacitive, I²C (CST816S driver, same register map) |
| microSD | TF slot in SPI mode, on the display's SPI bus |
| USB | Type-C, the ESP32-S3 native USB (PC link and flashing with BOOT) |
| Buttons | BOOT and RESET; no input buttons — everything is on the touch screen |
| Camera | 24-pin DVP connector: OV3660, OV2640 or OV5640 module (autodetected) — animated-QR exchange with Feather |
| Not used by the firmware | QMI8658 IMU |
| Battery | MX1.25 Li-Po connector and charger; not read by the firmware — no charge level shown |

## Selecting it

```c
// board_config.h
#define MW_BOARD_TOUCH_LCD_2
```

## Pins (`boards/esp32s3_touch_lcd_2_240x320.h`) — for reference, all routed on the board

| Part | Signal | GPIO |
| --- | --- | --- |
| Display (SPI, 40 MHz) | CS / DC / SCK / MOSI / MISO | 45 / 42 / 39 / 38 / 40 |
| | RST | — (no separate reset) |
| | backlight (active high) | 1 |
| Touch (I²C, 400 kHz) | SDA / SCL | 48 / 47 (INT and RST not used) |
| microSD (SPI, same bus) | CS / SCK / MOSI / MISO | 41 / 39 / 38 / 40 |
| Console | UART0 TX / RX | 43 / 44 |
| Camera (DVP) | XCLK / PCLK / VSYNC / HREF | 8 / 9 / 6 / 4 |
| | SCCB SDA / SCL | 21 / 16 |
| | D0..D7 (Y2..Y9) | 12 / 13 / 15 / 11 / 14 / 10 / 7 / 2 |
| | PWDN / RESET | 17 / — |

The display and the card share one SPI bus (each with its own CS); the
firmware arbitrates through SPI transactions (`MW_SPI_BUS_SHARED`). Without a
card, a build with `MW_USE_SD 0` gives the bus to the display alone (slightly
faster screen).

## Flashing

Hold BOOT → plug in USB (or press RESET) → release BOOT → `flash.bat` /
`./flash.sh`. The board restarts by itself after writing.

## Notes

- `TFT_BL_ACTIVE_HIGH 1` works on the tested board; if the backlight stays
  dark on another revision, set it to 0.
- Card: FAT32.
- Camera: plug the module into the connector with the board off. The sensor
  is detected at start (`camera: PID 0x...` in the log). OV3660 and OV5640
  are mounted the other way up than OV2640 on this connector; the firmware
  flips the picture for them. A mirrored picture is decoded anyway. The
  camera pins come from the Waveshare schematic and are not yet verified on
  hardware — wallet menu → *QR: sync / sign* is the quick test.
