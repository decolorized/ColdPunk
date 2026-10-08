# Board configurations

Board selection is **manual** (TZ 2.1). Nothing in this firmware probes for a
display or a touch controller at runtime: the wrong guess on a cold wallet is
a brick, and a brick that half-works is worse than one that refuses to boot.
Every board-specific fact is a compile-time constant in one header.

## Picking a board

Edit **`MoneroColdWallet/board_config.h`** and nothing else. It contains one
`#define MW_BOARD_...` per supported board; uncomment exactly one:

```c
#define MW_BOARD_ES3C28P
// #define MW_BOARD_ST7789_240x320
// #define MW_BOARD_GC9A01_ROUND
// #define MW_BOARD_ILI9488_320x480
// #define MW_BOARD_ST7701S_480x480
// #define MW_BOARD_SSD1306_BUTTONS
// #define MW_BOARD_CAM_QR
```

and it turns that into a single `#include "../boards/<file>.h"`. Selecting
none is a build error, and the boards all share the `BOARD_CONFIG_H` include
guard, so selecting two cannot silently merge them.

Then set the Arduino IDE to **ESP32S3 Dev Module** with:

| Tools setting   | Value                                        |
| --------------- | -------------------------------------------- |
| Board           | ESP32S3 Dev Module                           |
| USB CDC On Boot | Enabled                                      |
| PSRAM           | OPI PSRAM (QSPI on `-N*R2` modules)          |
| Flash Size      | 8 MB or 16 MB, to match the module           |
| Partition       | a scheme with a `nvs` partition and ≥ 4 MB app |

`src/hal/hal_esp32.cpp` refuses to compile for a non-S3 target, and warns if
`HAS_PSRAM` is 1 while PSRAM is switched off in the IDE.

### How the HAL finds the header

`src/hal/display_drivers.h` resolves `board_config.h`, in this order:

1. `-DMW_BOARD_CONFIG_HEADER="\"…\""` — used by CI and by the checks below;
2. `"board_config.h"` on the include path — the normal Arduino IDE case, since
   the sketch folder is always on it;
3. `"../../MoneroColdWallet/board_config.h"` — for editors and non-Arduino
   builds.

Every HAL translation unit includes `display_drivers.h` first and gets the
board through it; none of them includes `board_config.h` directly. If none of
the three routes finds a header, the build stops with a pointer to this file.

## The board matrix

| Board header | Display | Touch | Other input | SD | Camera | Battery | Notes |
| --- | --- | --- | --- | --- | --- | --- | --- |
| `es3c28p.h` | ILI9341 240×320 SPI | FT6336G (I²C) | — | yes, shared bus | no | no | TZ 2.2 reference board |
| `esp32s3_st7789_240x320.h` | ST7789 240×320 SPI | CST816S (I²C) | — | yes, shared bus | no | GPIO4 | the common 2.4″/2.8″ S3 touch modules |
| `esp32s3_touch_lcd_2_240x320.h` | ST7789T3 240×320 SPI, landscape | CST816D (I²C) | — | **no** | no | no | Waveshare ESP32-S3-Touch-LCD-2 (`MW_BOARD_TOUCH_LCD_2`) |
| `esp32s3_gc9a01_round.h` | GC9A01 240×240 round | CST816S (I²C) | — | **no** | no | GPIO1 | Waveshare ESP32-S3-Touch-LCD-1.28; USB only |
| `esp32s3_ili9488_320x480.h` | ILI9488 320×480 SPI | XPT2046 (SPI, resistive) | — | yes, shared bus | no | GPIO4 | the only board that really needs calibration |
| `esp32s3_st7701s_480x480.h` | ST7701S 480×480 RGB | GT911 (I²C) | — | **no** | no | no | Guition ESP32-S3-4848S040 class; pin-starved |
| `esp32s3_ssd1306_buttons.h` | SSD1306 128×64 I²C mono | **none** | 6 buttons + EC11 encoder | yes, own bus | no | no | TZ 2.5 reference; minimum viable wallet |
| `esp32s3_cam_qr.h` | ST7789 240×320 SPI | CST816S (I²C) | — | yes, shared bus | **OV2640** | no | camera fitted but not used by the firmware |

Every board: ESP32-S3, 8 MB PSRAM, HMAC/eFuse, USB OTG. All seven exercise a
different corner of the HAL, which is the point — between them they cover both
monochrome and colour, SPI and RGB panels, I²C and SPI touch, touch-only and
button-only input, shared and exclusive SPI buses, and present and absent SD.

## Pin policy

On an ESP32-S3-WROOM-1 these GPIOs are **never** used by any board here:

| GPIO | Why |
| --- | --- |
| 0, 3 | strapping (BOOT, JTAG source select) |
| 19, 20 | USB OTG D−/D+ — the wallet needs USB MSC/MTP (TZ 3.3–3.5) |
| 26–32 | SPI flash |
| 33–37 | octal PSRAM on `-N8R8` / `-N16R8` modules |
| 43, 44 | UART0 console |
| 45, 46 | strapping (VDD_SPI, boot log) |

That leaves 25 usable GPIOs. One documented exception:
`esp32s3_st7701s_480x480.h` puts the backlight on GPIO45, because an RGB
panel plus a touch controller needs 26 pins and 25 exist. GPIO45 is sampled
only at reset and the LEDC channel is attached later, so it is safe with a
pulldown — the reasoning is written out at the top of that header. The
commercial equivalent board solves the same squeeze by spending GPIO19/20 and
losing native USB, which this project cannot afford.

Pins *are* deliberately shared in one case: when `SD_SCK == TFT_SCK`, the card
and the panel are on one SPI bus with separate chip selects.
`display_drivers.h` detects that and switches Arduino_GFX to its SPIClass
backend so both arbitrate through `beginTransaction()`.

### About the pin numbers in the specification

TZ section 2.2 lists classic-ESP32 pins (`TFT_MOSI 23`, `TOUCH_SDA 21`, …)
while section 1.4 mandates the S3, where those pins are absent or strapping —
and the table collides with itself (`CAM_PIN_SIOC 39` vs `TOUCH_INT 39`).
`es3c28p.h` set the precedent: keep the *structure* of the TZ template exactly,
substitute S3-correct pins, and explain the substitution in a comment at the
top of the file. Every board here follows it.

## Adding a board

1. Copy the closest existing header. Keep the section order of the TZ 2.2
   template (`Display / Touch / SD Card / Camera / Buttons / Feature flags /
   Default input mode`) — several of the checks below are textual.
2. Use the `BOARD_CONFIG_H` include guard, not a per-board one.
3. Set `BOARD_NAME` to something a user will recognise in the About screen.
4. `#include "../src/config/app_config.h"` first.
5. Add an `MW_BOARD_...` entry to `MoneroColdWallet/board_config.h`.
6. Comment anything surprising: which commercial board it matches, why a pin
   was moved, what is *not* fitted.

### Required defines

`BOARD_NAME`, `DISPLAY_DRIVER`, `DISPLAY_WIDTH`, `DISPLAY_HEIGHT`,
`HAS_TOUCH`, `HAS_SD`, `HAS_CAMERA`, `HAS_BUTTONS`, `HAS_PSRAM`,
`PSRAM_SIZE_MB`, `HAS_HMAC`, `HAS_USB_OTG`, `DEFAULT_SEED_INPUT_MODE`.

`DISPLAY_WIDTH` × `DISPLAY_HEIGHT` is the **physical** panel — its size at
rotation 0, as in the datasheet (240×320 for a 2.8" ILI9341 or a 2" ST7789T3),
whatever `DISPLAY_ROTATION` is. The logical size the UI uses is not written
anywhere: after `begin()` the firmware asks the driver (`s_gfx->width()` /
`height()`) and hands that to LVGL, the theme metrics and the touch code via
`mw_hal_caps()`. A driver that swaps the axes for an odd rotation and one that
keeps its RAM window both work, because LVGL always gets the size the driver
actually addresses. The boot log shows the result:
`panel 240x320 rot 1 -> logical 320x240`.

`DISPLAY_DRIVER` is one of `DISPLAY_ILI9341 / ST7789 / ST7701S / GC9A01 /
ILI9488 / SSD1306 / SH1106`; `TOUCH_DRIVER` is one of `TOUCH_NONE / FT6336G /
FT6236 / CST816S / GT911 / XPT2046` (`CST816D` / `CST816T` are aliases of
`CST816S`; all from `src/hal/hal.h`). An
unrecognised value is a compile error, not a runtime surprise.

### Optional defines and their defaults

Everything below has a fallback in `src/hal/display_drivers.h`, so an existing
header never has to be touched when a new knob is added.

| Define | Default | Meaning |
| --- | --- | --- |
| `DISPLAY_ROTATION` | 0 | 0–3, passed to the GFX driver; odd = landscape on a portrait panel |
| `DISPLAY_IPS` | 1 | inverted panel |
| `DISPLAY_SPI_HZ` | 40 MHz | panel clock |
| `TFT_BL` | −1 | −1 makes `mw_display_backlight()` a no-op |
| `TFT_BL_ACTIVE_HIGH` | 1 | 0 inverts the LEDC duty |
| `ST7789_COL_OFFSET` / `_ROW_OFFSET` | 0 | RAM offset of 240×240 panels |
| `TOUCH_CS`, `TOUCH_SPI_HZ` | −1, 2 MHz | XPT2046 only |
| `TOUCH_I2C_HZ` | 400 kHz | I²C touch controllers |
| `TOUCH_SWAP_XY` | 0 | pre-calibration axis order only |
| `BUTTON_ACTIVE_LOW` | 1 | 0 = pull-down wiring |
| `ENCODER_COUNTS_PER_DETENT` | 4 | 1 for a non-detented wheel |
| `SD_DETECT` | −1 | card-detect switch, active low |
| `BATTERY_ADC_PIN` | −1 | −1 ⇒ `mw_battery_percent()` returns −1 |
| `BATTERY_DIV_NUM` / `_DEN` | 2 / 1 | divider ratio |
| `BATTERY_MV_EMPTY` / `_FULL` | 3300 / 4180 | Li-ion endpoints |
| `USB_VBUS_DET_PIN` | −1 | falls back to USB CDC DTR |
| `OLED_I2C_SDA` / `_SCL` / `_ADDR` / `_HZ` | −1 / −1 / 0x3C / 400 kHz | mono panels |
| `CAM_PIN_*` (16 of them) | −1 | OV2640 wiring; required when `HAS_CAMERA` is 1 |
| `CAMERA_FRAME_SIZE` | `FRAMESIZE_QVGA` | 320×240 grayscale = 76.8 KB |
| `CAM_XCLK_FREQ_HZ` | 20 MHz | drop to 16 MHz on long flex cables |
| `CAM_LEDC_CHANNEL` / `_TIMER` | `LEDC_CHANNEL_1` / `LEDC_TIMER_1` | must not collide with the backlight |
| `CAM_VFLIP` / `CAM_HMIRROR` | 0 / 0 | sensor orientation |
| `LCD_R0…B4`, `LCD_DE/VSYNC/HSYNC/PCLK`, `LCD_SPI_*`, porches, `LCD_ST7701_INIT_OPS` | — / typical 480×480 | ST7701S RGB panels |

### Checks to run before trusting a new header

```sh
# 1. no duplicate pins, no strapping / flash / PSRAM / USB pins.
#    Prints every GPIO claimed more than once and every forbidden one; the
#    only legitimate repeats are SD_SCK/MOSI/MISO matching TFT_SCK/MOSI/MISO.
python3 - boards/<yours>.h <<'EOF'
import re, sys, collections
BAD = {0:'strapping',3:'strapping',19:'USB D-',20:'USB D+',
       43:'UART0 TXD',44:'UART0 RXD'}
BAD.update({p:'SPI flash' for p in range(26,33)})
BAD.update({p:'octal PSRAM' for p in range(33,38)})
NOTE = {45:'strapping VDD_SPI', 46:'strapping boot-log'}
SHARED = [{'TFT_MOSI','SD_MOSI'}, {'TFT_MISO','SD_MISO'}, {'TFT_SCK','SD_SCK'}]
SKIP = re.compile(r'(_HZ|_ADDR|_ACTIVE_HIGH|_ACTIVE_LOW|_POLARITY|_PORCH|'
                  r'_PULSE_WIDTH|_SWAP_XY|_DRIVER|_PER_DETENT|_ACTIVE_NEG|'
                  r'_PREFER_SPEED|_INIT_OPS|_INIT_OPS_LEN)$')
PIN  = re.compile(r'(TFT_|TOUCH_|SD_|CAM_PIN_|BUTTON_|LCD_|OLED_I2C_S|'
                  r'BATTERY_ADC_PIN|USB_VBUS_DET_PIN)')
used, bad = collections.defaultdict(list), 0
for line in open(sys.argv[1]):
    m = re.match(r'\s*#define\s+([A-Z0-9_]+)\s+(-?\d+)\s*(?://.*)?$', line)
    if m and PIN.match(m.group(1)) and not SKIP.search(m.group(1)):
        v = int(m.group(2))
        if v >= 0: used[v].append(m.group(1))
for gpio in sorted(used):
    names = used[gpio]
    if len(names) > 1 and not any(set(names) <= g for g in SHARED):
        print('DUPLICATE gpio%-2d: %s' % (gpio, ', '.join(names))); bad += 1
    if gpio in BAD:
        print('FORBIDDEN gpio%-2d (%s): %s' % (gpio, BAD[gpio], ', '.join(names))); bad += 1
    elif gpio in NOTE:
        print('note      gpio%-2d (%s): %s - needs a comment in the header'
              % (gpio, NOTE[gpio], ', '.join(names)))
print('%d GPIOs used:' % len(used), *sorted(used))
sys.exit(1 if bad else 0)
EOF

# 2. the header is self-consistent and every derived flag is sane
gcc -std=c11 -Wall -Wextra -Wundef -Isrc \
    -DMW_BOARD_CONFIG_HEADER='"../../boards/<yours>.h"' \
    -E src/hal/display_drivers.h > /dev/null

# 3. the host stub still builds (it must never see board_config.h)
gcc -std=c11 -Wall -Wextra -c -Isrc -DMW_HOST_BUILD=1 \
    src/hal/hal_host.c -o /tmp/hal_host.o
```

Then build the sketch and confirm the boot log: `mw_hal_init()` prints the
board name, the PSRAM total and its largest contiguous block, and the panel
geometry.

## Camera (TZ 3.7)

Only `esp32s3_cam_qr.h` sets `HAS_CAMERA 1`. `src/hal/camera.cpp` drives an
OV2640 through esp32-camera in **`PIXFORMAT_GRAYSCALE`**: a QR decoder only
looks at luminance, so grayscale is what it wants, costs a quarter of the RAM
of RGB565, and skips the sensor's colour interpolation. `mw_camera_preview()`
expands grey to RGB565 for the viewfinder as it downscales.

`mw_camera_capture()` lends the driver's buffer out without copying and
returns it at the top of the next call, which is exactly the lifetime
`hal.h` promises. `mw_camera_preview()` borrows and returns its own frame, so
the UI can keep drawing a viewfinder while the decoder still holds a captured
frame — that is what `fb_count = 2` buys. On every board with
`HAS_CAMERA 0`, all four functions return `MW_ERR_NOT_SUPPORTED`.

Two hazards to know about when wiring a new camera board:

* **`HAS_CAMERA` requires `HAS_PSRAM`.** The framebuffer will not fit in DRAM;
  the build fails with an `#error` if a header tries.
* **LEDC channels are a shared resource.** esp32-camera generates XCLK with an
  LEDC timer/channel and `display.cpp` drives the backlight with another. The
  backlight is attached first (`mw_hal_init()` brings the display up long
  before anything touches the camera) and lands on channel 0 / timer 0, so the
  camera is pinned to channel 1 / timer 1. A third PWM consumer must take
  channel 2 or higher.
* **SCCB field names.** esp32-camera renamed `pin_sscb_*` to `pin_sccb_*`
  partway through its history and both spellings are still in the wild.
  `camera.cpp` picks whichever member actually exists at compile time, so it
  builds against either core version with no configuration.

## The host build

`src/hal/hal_host.c` is a complete HAL for a desktop: an in-memory 240×320
framebuffer (dumpable as a PPM), a file-backed "SD card" under `./sdcard/`, no
touch, no buttons, `CLOCK_MONOTONIC` for `mw_millis()`. It never includes a
board header — `MW_HOST_BUILD` switches all of that off — which is what lets
the crypto, the Monero serialisation and the file formats be tested with
`make -C test` on a PC. It carries no-op camera stubs so the link still
succeeds. The device files (`hal_esp32.cpp`, `display.cpp`, `touch.cpp`,
`buttons.cpp`, `sdcard.cpp`, `camera.cpp`) compile to nothing without
`ARDUINO`.

## HAL extensions

Two things the UI needs do not fit in the frozen `src/hal/hal.h`, so they live
in `src/hal/display_drivers.h`:

**Button press length (TZ 5.6).** `mw_buttons_read()` packs three 8-bit fields
into its `uint32_t`:

| Bits | Meaning |
| --- | --- |
| 0–7 | currently pressed; bit index = `mw_button_t` value |
| 8–15 | held > 800 ms (`MW_BTN_LONG_MS`) |
| 16–23 | held > 2500 ms (`MW_BTN_VLONG_MS`) |

Use the `MW_BTN_MASK(b)` / `MW_BTN_LONG_MASK(b)` / `MW_BTN_VLONG_MASK(b)`
helpers. The long flags **latch while the button is still held**, so act on the
rising edge: a held `MW_BTN_BACK` raises the long bit once at 800 ms (clear the
word prefix) and the very-long bit once at 2500 ms (clear the whole phrase).
`mw_buttons_press_ms()` gives the exact duration if you need a progress ring.

**Display helpers.** `mw_display_fill()`, `mw_display_flush()` and
`mw_display_is_mono()`. `mw_display_flush()` must be called after a batch of
blits on a monochrome panel; it is harmless everywhere else, and
`mw_display_wait_dma()` already calls it.
