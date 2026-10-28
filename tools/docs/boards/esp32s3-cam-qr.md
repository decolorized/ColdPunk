# ESP32-S3 CAM + ST7789 240×320 + touch — the QR board

A Freenove-style ESP32-S3 camera board (ESP32-S3-WROOM N8R8 / N16R8 with a
24-pin DVP camera connector) plus a 2.0"/2.4" ST7789 240×320 SPI display with
a CST816S touch panel and, optionally, a microSD slot on the same SPI bus.
The point of this build is the camera: the device exchanges files with
Feather as animated QR codes and needs no cable at all.

## Parts

| | |
| --- | --- |
| MCU | ESP32-S3 with **8 MB PSRAM** (required: the camera frame lives there) |
| Camera | OV3660, OV2640 or OV5640 module in the board's connector; detected at start |
| Display | ST7789 240×320 SPI module **with** CS, portrait |
| Touch | CST816S (I²C) |
| microSD | optional, SPI, on the display bus |

## Selecting it

In `board_config.h`:

```c
#define MW_BOARD_CAM_QR
```

## Pins (`boards/esp32s3_cam_qr.h`)

Camera — routed on the board (Freenove ESP32-S3 CAM pinout):

| Signal | GPIO |
| --- | --- |
| XCLK / PCLK / VSYNC / HREF | 15 / 13 / 6 / 7 |
| SCCB SDA / SCL | 4 / 5 |
| D0..D7 (Y2..Y9) | 11 / 9 / 8 / 10 / 12 / 18 / 17 / 16 |
| PWDN / RESET | not connected |

Wire the display, touch and card:

| Module pin | GPIO |
| --- | --- |
| Display VCC / GND | 3V3 / GND |
| Display SCL (SCK) | 39 |
| Display SDA (MOSI) | 40 |
| Display MISO (if any) / card MISO | 41 |
| Display CS | 21 |
| Display DC | 47 |
| Display RES | 48 |
| Display BLK | 42 (active high) |
| Card CS | 38 (card SCK / MOSI on 39 / 40) |
| Touch SDA / SCL | 1 / 2 |
| Touch INT | 14 |
| Touch RST | board EN / 3V3 |

All usable GPIOs are taken, so there is no battery level and no VBUS sense.

## Flashing

Native USB with BOOT, as on every board (see `README.md` in this folder). On
boards that also carry a USB-UART bridge, flash through either port.

## Use

Wallet menu → **QR: sync / sign**: scan Feather's animated QR (outputs or an
unsigned transaction), confirm on the device, and show the answer to the PC
webcam. Workflow in `user_guide.md` §8b, protocol in `qr_protocol.md`.

Status: builds; **not yet tested on hardware**.
