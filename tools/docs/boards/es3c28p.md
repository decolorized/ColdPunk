# ES3C28P — 2.8" ESP32-S3 with touch (LCDWiki)

A ready-made board-plus-display module: nothing to wire. The project's
reference board, tested.

## On the board

| | |
| --- | --- |
| MCU | ESP32-S3, 16 MB flash, 8 MB PSRAM (octal) |
| Display | 2.8" ILI9341V, 240×320, IPS; the firmware uses landscape 320×240 (`DISPLAY_ROTATION 1`) |
| Touch | FT6336G capacitive, I²C |
| microSD | SDIO (SD_MMC) slot, 4-bit; falls back to 1-bit when the 4-bit mount fails |
| USB | Type-C, the ESP32-S3 native USB (both the PC link and flashing with BOOT) |
| Buttons | BOOT and RESET on the board; no input buttons — everything is on the touch screen |
| Battery | connector and TP4054 charger, 200K/200K divider; not routed to an ADC — no charge level shown |

## Selecting it

```c
// board_config.h
#define MW_BOARD_ES3C28P
```

## Pins (`boards/es3c28p.h`) — for reference, all routed on the board

| Part | Signal | GPIO |
| --- | --- | --- |
| Display (SPI) | CS / DC / SCK / MOSI / MISO | 10 / 46 / 12 / 11 / 13 |
| | RST | — (tied to CHIP_PU, resets with the chip) |
| | backlight (active high, BSS138) | 45 |
| Touch (I²C, 400 kHz) | SDA / SCL / INT / RST | 16 / 15 / 17 / 18 |
| microSD (SDIO) | CLK / CMD / D0 / D1 / D2 / D3 | 38 / 40 / 39 / 41 / 48 / 47 |
| Console | UART0 TX / RX | 43 / 44 |

GPIO45 and GPIO46 are strapping pins; the vendor put the backlight and the
display DC on them, which the firmware takes into account (the backlight is
switched on after start).

## Flashing

Hold BOOT → plug in USB (or press RESET) → release BOOT → `flash.bat` /
`./flash.sh`. The board restarts by itself after writing (or press RESET).

## Notes

- Seed entry: the full on-screen keyboard; the keyboard type can be changed in
  Settings.
- Card: FAT32. With it the wallet works with any Monero wallet on the PC
  (Feather, GUI, CLI) without a cable.
