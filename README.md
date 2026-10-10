# ColdPunk

**ColdPunk** is an air-gapped Monero cold wallet firmware for ESP32-S3 boards
with a display. It keeps your seed on the device, computes key images and signs
transactions there, and talks to a watch-only wallet on your PC only through a
small USB protocol that carries files, never secrets.

The PC side is **[MoneroPunkSigner](https://github.com/decolorized/MoneroPunkSigner)**,
a fork of Feather Wallet that speaks the device protocol natively. A
stand-alone Python courier (`tools/tools/mwlink`) works with stock Feather as
well.

> [!WARNING]
> **Experimental. Not audited. Not tested with real funds.**
> Until it has passed the stagenet procedure in
> [`tools/docs/testing.md`](tools/docs/testing.md), treat the device as a
> demonstrator and do not keep money on it that you cannot afford to lose.
> Read [Security model](tools/docs/security.md) → *Known limitations* first.

---

## Contents

- [Key advantages](#key-advantages)
- [How it works](#how-it-works)
- [Features](#features)
- [Supported boards](#supported-boards)
- [Building and flashing](#building-and-flashing)
- [First start](#first-start)
- [Everyday use](#everyday-use)
- [Passphrases and seed formats](#passphrases-and-seed-formats)
- [USB protocol](#usb-protocol)
- [Security](#security)
- [Repository layout](#repository-layout)
- [Tests](#tests)
- [Documentation](#documentation)
- [Related projects](#related-projects)
- [License](#license)

---

## Key advantages

### The whole transaction is signed on the device, in one pass

ColdPunk takes Feather's standard *unsigned transaction* file and returns a
complete *signed transaction*. Every CLSAG ring signature and the
Bulletproofs+ range proof for all outputs are computed **on the device**. The
PC takes no part in building the signature: it only delivers the file and
collects the result, over USB or as a plain file.

Ledger and Trezor sign Monero differently. The host wallet drives the device
through a long interactive protocol and keeps part of the intermediate state
on the PC:

- **Ledger.** The Monero app runs a host-driven sequence of APDU commands
  (open, stealth, output keys, blind, prehash, MLSAG, close). Its own
  specification says the device "is not capable of holding the entire
  transaction or building the required proofs in RAM" ([app-monero
  spec](https://github.com/LedgerHQ/app-monero/blob/master/doc/developer/blue-app-commands.rst)),
  and intermediate values are offloaded to the desktop client
  ([Ledger LSB-007](https://donjon.ledger.com/lsb/007/)).
- **Trezor.** The protocol needs 14 host–device round trips for a 2-input,
  2-output transaction and 392 for 128 inputs. The device offloads encrypted
  state to the host, and Bulletproofs for 4 or more outputs cannot be generated
  on the Trezor, so their vector work is offloaded to the host in blinded form
  ([Klinec, Matyáš: IACR ePrint 2020/281](https://eprint.iacr.org/2020/281.pdf)).

With ColdPunk the PC only ever sees the unsigned file and the finished result.
No special support inside `wallet2` is needed, and signing works fully
air-gapped. What you approve on the device screen (amounts, fee, change and
every full destination address) is exactly what gets signed.

### The first Monero signer on ESP32-S3

As far as we could find (October 2026), ColdPunk is the first open-source
firmware that signs complete Monero transactions (CLSAG + Bulletproofs+) on an
**ESP32-S3**:

- other ESP32 wallets either do not support Monero
  ([Colibri](https://github.com/xtools-at/colibri),
  [LeekWallet](https://github.com/0xOucan/LeekWallet)) or only derive Monero
  addresses ([HexWallet](https://github.com/blueokanna/HexWallet), where Monero
  signing is "not implemented");
- other open-source Monero offline signers such as
  [MoneroSigner](https://ccs.getmonero.org/proposals/MoneroSigner.html) run on
  a Raspberry Pi Zero, a Linux single-board computer, not a microcontroller.

The result is a Monero cold wallet that runs on inexpensive, widely available
ESP32-S3 display boards, with no secure-element vendor SDK and no NDA.

If you know of an earlier project, please open an issue, and we will correct
this section.

---

## How it works

```
  PC (online)                                     ColdPunk (offline)
  ───────────────────────────────                 ───────────────────────────────
  MoneroPunkSigner / Feather                      seed, passphrase, spend key
  watch-only wallet                                 never leave the device

  export outputs        ───── USB (mwlink) ────▶  "Generate key images for N
                                                   outputs?"  → Yes
  import key images     ◀────────────────────────  key images

  create transaction    ───── unsigned tx ─────▶  review amount, fee, change and
                                                   every full destination address
  broadcast             ◀────── signed tx ──────  CLSAG + Bulletproofs+ on device

  "Restore from keys"   ── request view-only ──▶  "Send the view key?" → Yes
                        ◀─ address + view key ──
```

The device never has a network stack compiled in. Every action that produces
something for the PC (key images, a signed transaction, the view key) needs an
explicit confirmation on the device screen. The PC program is only a courier.

---

## Features

**Wallets**

- Monero **legacy 25-word** seeds and **Polyseed 16-word** seeds (with
  birthday, so no restore height is needed).
- New seeds from the hardware TRNG, or from **dice rolls mixed with the TRNG**
  (`HMAC-SHA512(trng, dice)`): weak dice cannot make the seed weaker than the
  TRNG alone.
- Optional **passphrase** (Feather / Monero "seed offset"). One phrase opens two
  wallets: with and without the passphrase.
- Restores **Cake Wallet / Cupcake** polyseeds whose phrase is encrypted with
  the passphrase (polyseed "encrypted" flag). Detected automatically from the
  phrase. New wallets are always created in the Feather format.
- Import from raw keys (spend + view) and **view-only** wallets.
- Several wallets per device; Mainnet, Testnet and Stagenet.

**Operations**

- **Key image sync**: Feather outputs export → key images, with a progress bar.
- **Transaction signing**: CLSAG ring signatures and Bulletproofs+ range proofs
  computed on the device. Up to 4 transactions per Feather transfer.
- The signing screen shows amount, fee, change, inputs and outputs, and the
  **full address of every recipient**. The change address is checked against
  the wallet (substitution protection).
- A **key image cache** remembers which outputs the device has seen. It is
  bound to the wallet and protected against rollback (generation counter in
  NVS), and the device warns about inputs already spent by an earlier
  signature.
- Address and private view key shown as text on the device.
- PC requests for the address or the view-only data (address + private view
  key + restore height) with a plain Yes / No on the device.
- **SD card exchange** (ES3C28P, Touch-LCD-2): the wallet menu lists the Feather files in
  the card root (newest first). Pick one to sign it or to make key images; the
  result is written next to it with the same date. The list follows the card:
  it empties when the card is pulled out and fills again when one is put in.
- **View key to SD card** (ES3C28P, Touch-LCD-2): `<wallet>_viewonly.txt` with the primary
  address, private view key and restore height, after a warning on the device.

**Device**

- Disguised as **Minesweeper** at power-on and after every lock.
- **Device password** (8–64 characters; weak ones draw a warning): 200 000
  PBKDF2-HMAC-SHA256 rounds on the SHA accelerator, with the chip's eFuse HMAC
  key mixed in between and at the end. The attempt
  counter is written before each check, and failed attempts back off
  exponentially (2 s … 10 min, kept across reboots).
- **USB is enabled only after the correct password.**
- Autolock (default 5 minutes): keys and passphrase are wiped from memory.
- LVGL 9 user interface in **English**. Touch screens, and
  4/5/6-button boards with long-press and auto-repeat navigation.
- Device log streamed to the PC. Secrets and authentication messages never
  leave the device; details are sent only in debug mode.

---

## Supported boards

The board is chosen at compile time in [`board_config.h`](board_config.h)
(uncomment one `#define`). All supported boards use an ESP32-S3 module with
8 MB octal PSRAM (N16R8 / N8R8).

| Define | Header | Display | Input | Notes |
| :--- | :--- | :--- | :--- | :--- |
| `MW_BOARD_ES3C28P` | `es3c28p.h` | ILI9341 2.8" 240×320, landscape | FT6336G touch | reference board |
| `MW_BOARD_TOUCH_LCD_2` | `esp32s3_touch_lcd_2_240x320.h` | ST7789T3 2" 240×320, landscape | CST816D touch | Waveshare ESP32-S3-Touch-LCD-2 |
| `MW_BOARD_ST7789_240x320` | `esp32s3_st7789_240x320.h` | ST7789 240×320 | buttons | common 2.4"/2.8" modules |
| `MW_BOARD_ST7789_240x240` | `esp32s3_st7789_240x240.h` | ST7789 240×240 | buttons | |
| `MW_BOARD_ST7735S_128x160` | `esp32s3_st7735s_128x160.h` | ST7735S 128×160 | buttons | |
| `MW_BOARD_GC9A01_ROUND` | `esp32s3_gc9a01_round.h` | GC9A01 240×240 round | CST816S touch | Waveshare Touch-LCD-1.28 |
| `MW_BOARD_ILI9488_320x480` | `esp32s3_ili9488_320x480.h` | ILI9488 320×480 | XPT2046 resistive touch | needs touch calibration |
| `MW_BOARD_ST7701S_480x480` | `esp32s3_st7701s_480x480.h` | ST7701S 480×480 RGB | GT911 touch | Guition 4848S040 class |
| `MW_BOARD_SSD1306_BUTTONS` | `esp32s3_ssd1306_buttons.h` | SSD1306 128×64 mono | 6 buttons + encoder | minimum viable wallet |
| `MW_BOARD_SSD1306_NO_SD` | `esp32s3_ssd1306_no_sd.h` | SSD1306 128×64 mono | buttons | |
| `MW_BOARD_CAM_QR` | `esp32s3_cam_qr.h` | ST7789 240×320 | CST816S touch | board with an OV2640 camera (camera not used) |

**SD card:** supported on ES3C28P (SDIO, 4-bit with 1-bit fallback) and on the
Waveshare ESP32-S3-Touch-LCD-2 (SPI, sharing the display bus: CS IO41, MOSI
IO38, SCK IO39, MISO IO40). On the other boards the slot is not used yet, and
all exchange with the PC goes over USB.

`DISPLAY_WIDTH` × `DISPLAY_HEIGHT` in a board header is the **physical** panel
size at rotation 0. The logical size after `DISPLAY_ROTATION` is read from the
display driver at runtime. See [`boards/README.md`](boards/README.md) for pin
policy and for adding a new board.

---

## Building and flashing

### With arduino-cli (recommended)

[`sketch.yaml`](sketch.yaml) pins the ESP32 core (3.3.11), the libraries
(`lvgl` 9.6.0, `GFX Library for Arduino` 1.6.9), every board option and the
path to `lv_conf.h`. You only need
[arduino-cli](https://arduino.github.io/arduino-cli/):

```sh
arduino-cli compile                      # build (profile "coldpunk")
arduino-cli compile -u -p COM5           # build and flash
arduino-cli compile --profile coldpunk-debug   # core log at Info level
arduino-cli board list                   # find the port
```

On the first build arduino-cli downloads the exact core and library versions
into its own cache. Uncomment `port:` in `sketch.yaml` to drop `-p`.

The native USB port is the wallet's USB-OTG link (HID + CDC), so the board is
flashed through its **USB-UART bridge** (UART0, a CH340/CP210x COM port).

### With Arduino IDE 2

Arduino IDE does not read build profiles. Install the `esp32` core by
Espressif (3.x, board manager URL
`https://espressif.github.io/arduino-esp32/package_esp32_index.json`), the two
libraries above, copy `lv_conf.h` next to the `lvgl` library folder, and set:

| Tools menu | Value |
| :--- | :--- |
| Board | ESP32S3 Dev Module |
| USB Mode | USB-OTG (TinyUSB) |
| USB CDC On Boot | Enabled |
| PSRAM | OPI PSRAM |
| Flash Size | 16MB (8MB also fits) |
| Partition Scheme | Custom (`partitions.csv`) |
| Erase All Flash Before Sketch Upload | **Disabled** (NVS holds the wallets) |
| Core Debug Level | None |

Do **not** install `Adafruit TinyUSB`: TinyUSB ships with the ESP32 core. Full
details are in [`tools/docs/build_arduino.md`](tools/docs/build_arduino.md).

### Exchange interfaces (build options)

Each way of talking to the PC can be left out of the firmware entirely, in
[`src/config/app_config.h`](src/config/app_config.h) or as a build flag
(`-DMW_USE_SERIAL=0`):

| Option | Default | What it is | Used by |
| :--- | :---: | :--- | :--- |
| `MW_USE_SERIAL` | 1 | mwlink over `Serial` (USB CDC port, or UART0 when *CDC On Boot* is off) | `tools/mwlink --serial`, serial terminals |
| `MW_USE_HID` | 1 | mwlink over USB HID (needs *USB Mode: USB-OTG*) | MoneroPunkSigner, `tools/mwlink` (default) |
| `MW_USE_SD` | 1 | microSD files, on boards with a slot (`HAS_SD 1`) | — |

At least one must stay on (the build stops otherwise). A transport that is
off has no code in the firmware and nothing listens on it. For a device that
shows **no COM port at all**, use the `coldpunk-hid` profile
(`MW_USE_SERIAL=0`, *CDC On Boot* disabled): UART0 then carries only the text
log. `MW_USE_SD=0` on the Touch-LCD-2 also gives the display its own, faster
SPI bus back. Flashing over USB is done by the chip's ROM bootloader and is not
affected by these options. Details: [`tools/docs/build_arduino.md`](tools/docs/build_arduino.md) §2a.

```sh
arduino-cli compile --profile coldpunk-hid -u -p COM5
```

### Partitions

| Name | Type | Offset | Size |
| :--- | :--- | ---: | ---: |
| nvs | data/nvs | 0x9000 | 20 KB |
| otadata | data/ota | 0xE000 | 8 KB |
| app0 | app/ota_0 | 0x10000 | 4 MB |
| storage | data/fat | 0x410000 | ~3.9 MB |

---

## First start

1. **Hardware key.** Right after the unlock gesture, before the password, a
   chip without the key offers to burn a random 32-byte key into the highest
   free eFuse key block (`BLOCK_KEY5` on a fresh chip; purpose `HMAC_UP`,
   read-protected) behind two confirmation screens. **This is irreversible.**
   The device does not work without it; declining returns to the game. Every wallet on the device
   is sealed with a key derived from it; a firmware image copied to another
   chip cannot open them. Bench provisioning with `espefuse.py` is described in
   [`tools/docs/security.md`](tools/docs/security.md) §4.
2. **Unlock gesture.** The device starts as Minesweeper. Step on a mine, then
   tap the exploded mine **three times within 2 seconds**.
3. **Device password.** Choose one (entered twice). It is needed at every
   unlock and also protects the sealed seeds.
4. **Create or import a wallet**, write the words on paper (they are shown
   only once), pass the word check and compare the address with your PC
   wallet.

---

## Everyday use

**Key image sync** (so the watch-only wallet knows what is spent):

1. Open the wallet on the device.
2. In MoneroPunkSigner: *Tools → Offline transaction signing*, method
   **HID device**, *Send via HID*. With stock Feather, save the outputs file
   into the folder watched by `mwlink_gui.py`.
3. Confirm on the device. Key images are imported automatically (or saved
   back to the folder for Feather).

**Signing:**

1. Create the transaction in the watch-only wallet and choose **Sign on HID**
   (or save the unsigned file for `mwlink`).
2. On the device check the amount, the fee and **every full address**, then
   *Sign*. Do not power off while Bulletproofs+ is computed.
3. The signed transaction comes back; review and broadcast it on the PC.

**Over the SD card (ES3C28P, Touch-LCD-2):**

1. Copy the Feather file (`…_outputs` or `…_unsigned_monero_tx`) into the
   **root** of a FAT32 microSD card and insert it into the device.
2. Open the wallet → **SD card files**. Only files the device can process are
   listed, newest first (by the date the PC set, or by the time in the file
   name). Each row shows the type, size and date; processed files are marked
   *done*.
3. Pick a file and confirm on the device, exactly as over USB.
4. The result (`…_keyImages` or `…_signed_monero_tx`) is written next to the
   source with the source's date. Import it in Feather.

On the first use the device writes `ColdPunk_readme.txt` with these steps to
the card. Files up to 256 KB. Every write is flushed and the card unmounted
right after it, and the card is mounted afresh each time the list opens, so it
can be pulled out and swapped at any time except during the write itself. The
open list notices a card pulled out or put in and updates itself.

**View-only wallet on the PC:** in MoneroPunkSigner, *Restore wallet from keys
→ ColdPunk*, then answer *Yes* on the device. Address, view key, restore height
and wallet name are filled in.

The full user guide (in Russian) is
[`tools/docs/user_guide.md`](tools/docs/user_guide.md).

---

## Passphrases and seed formats

| Phrase | Passphrase meaning | Restore on ColdPunk |
| :--- | :--- | :--- |
| Feather / ColdPunk polyseed, legacy 25 words | Monero seed offset: `key = sc_sub(key, cn_slow_hash(passphrase))` | optional; empty = wallet without passphrase |
| Cake Wallet / Cupcake polyseed (encrypted flag) | decrypts the phrase (`polyseed_crypt`), no seed offset | **required**; detected automatically |

The device never stores the passphrase, only a 14-byte check of the resulting
public keys inside the sealed record, so a typo is reported as a wrong
passphrase. For a Cake/Cupcake phrase a wrong passphrase cannot be detected:
it simply derives another wallet, so always compare the address.

---

## USB protocol

**mwlink protocol 3**, the same frames over vendor HID (64-byte reports) and USB
CDC serial (COBS):

| Offset | Size | Field |
| ---: | ---: | :--- |
| 0 | 8 | magic `4D 57 50 4B C7 3A 5E 91` |
| 8 | 1 | protocol version (3) |
| 9 | 1 | command |
| 10 | 1 | argument |
| 11 | 1 | reserved |
| 12 | 4 | payload length (≤ 256 KiB) |
| 16 | 4 | CRC32 of bytes 0..15 |
| 20 | n | payload |
| 20+n | 4 | CRC32 of bytes 0..20+n |

Commands: `PING`, `INFO`, `STATUS`, `PUT`, `GET`, `CLEAR`, `REQ` (address /
view-only data), and an unsolicited `LOG` event. The PC puts a file into the
device **inbox** and collects the result from the **outbox**. USB VID `0x303A`,
HID usage page `0xFF00`.

Specification: [`tools/docs/usb_link_protocol.md`](tools/docs/usb_link_protocol.md).
Reference implementation: `src/transfer/link.c` (device) and
`tools/tools/mwlink/mwlink.py` (PC).

On Linux, give your user access to the HID device with the udev rule from
[MoneroPunkSigner](https://github.com/decolorized/MoneroPunkSigner) ([`install-udev-rule.sh`](https://github.com/decolorized/MoneroPunkSigner/blob/HEAD/install-udev-rule.sh)).

---

## Security

- **No network stack.** The build refuses to compile if Wi-Fi or Bluetooth is
  enabled.
- **Sealed seeds.** Each seed record is AES-256-GCM encrypted with
  `HMAC(eFuse key, "mw.seed.v1.<id>")` computed inside the HMAC peripheral, and
  additionally bound to the device password. Records are constant-length, so
  the ciphertext does not reveal the seed type.
- **Fail-closed RNG.** The TRNG is health-tested at boot; a failure stops the
  device instead of producing weak keys.
- **Secrets are wiped** (`mw_memzero`) after use, including the CryptoNight
  scratchpad, transaction secrets after signing, and the session on lock.
- **Atomic password change**, with interrupted changes recovered on the next
  unlock.

Known limitations (details in [`tools/docs/security.md`](tools/docs/security.md)):
no secure boot or flash encryption by default; NVS encryption is limited under
the Arduino build; the ESP32-S3 has no glitching countermeasures; physical
access to an unlocked device means access to the funds.

---

## Repository layout

```
ColdPunk.ino          entry point: HAL, UI task (core 0), crypto task (core 1)
board_config.h        board selection
boards/               one header per supported board
sketch.yaml           arduino-cli build profiles
lv_conf.h             LVGL configuration
partitions.csv        flash layout
res/                  source images (monero.png -> src/ui/img_monero.c)
src/
  config/             app_config.h - build-wide constants
  crypto/             SHA-2, Keccak, HMAC/PBKDF2, AES-GCM, ChaCha, ed25519, CryptoNight, RNG
  data/               word lists (Monero, Polyseed/BIP39)
  monero/             keys, mnemonics, polyseed, addresses, key images, CLSAG,
                      Bulletproofs+, transaction parsing and signing, file formats
  wallet/             device password, sealed wallet store, session, key image cache
  transfer/           mwlink protocol (link.c), USB HID/CDC transport,
                      SD card file browser logic (sd_files.c)
  hal/                display, touch, buttons, SD (SPI and SDIO), logging, host stubs
  ui/                 LVGL screens, keyboards, flows, i18n, Minesweeper,
                      img_monero.c (generated logo, 160 px)
tools/
  img2lvgl.py         PNG -> LVGL 9 C image (RGB565A8): regenerates img_monero.c
  docs/               design, security, protocol, user guide, testing
  test/               host test suite (gcc, no hardware needed)
  tools/mwlink/       PC courier: CLI, Tk GUI, device simulator, tests
```

---

## Tests

The platform-independent core (crypto, Monero, wallet, protocol) builds with
plain `gcc` on the host:

```sh
cd tools/test
make run                 # all suites
make ASAN=1 run          # with AddressSanitizer + UBSan
../tools/run_tests.sh    # both, as CI should run it
```

The suites cover cryptographic test vectors, seed encoding (including
upstream polyseed vectors and a Cake/Cupcake encrypted phrase), passphrases,
deterministic signatures, the Feather file formats end to end, the USB
protocol, the device password and storage failure cases. On Windows,
[w64devkit](https://github.com/skeeto/w64devkit) is enough.

The PC courier has its own tests against a simulated device
(`tools/tools/mwlink/link_sim.c`), see
[`tools/tools/mwlink/README.md`](tools/tools/mwlink/README.md). What cannot be
tested on the host, and the stagenet procedure, are listed in
[`tools/docs/testing.md`](tools/docs/testing.md).

---

## Documentation

| Document | Contents |
| :--- | :--- |
| [`tools/docs/user_guide.md`](tools/docs/user_guide.md) | user guide (RU) |
| [`tools/docs/security.md`](tools/docs/security.md) | threat model, key hierarchy, eFuse provisioning, limitations |
| [`tools/docs/device_password.md`](tools/docs/device_password.md) | device password scheme and record format |
| [`tools/docs/usb_link_protocol.md`](tools/docs/usb_link_protocol.md) | mwlink protocol 3 (RU) |
| [`tools/docs/architecture.md`](tools/docs/architecture.md) | layers, FreeRTOS tasks, memory budget, data flows (RU) |
| [`tools/docs/ui_screens.md`](tools/docs/ui_screens.md) | screens and navigation |
| [`tools/docs/build_arduino.md`](tools/docs/build_arduino.md) | build settings in detail (RU) |
| [`tools/docs/testing.md`](tools/docs/testing.md) | host tests and stagenet checklist (RU) |
| [`boards/README.md`](boards/README.md) | board headers and adding a board |

---

## Related projects

| Project | Role |
| :--- | :--- |
| **[ColdPunk](https://github.com/decolorized/ColdPunk)** (this repository) | firmware of the offline signing device |
| **[MoneroPunkSigner](https://github.com/decolorized/MoneroPunkSigner)** | Feather Wallet fork for the PC: watch-only wallet with native ColdPunk support over USB HID |

Use matching versions: both sides must speak the same mwlink protocol version
(currently 3).

---

## License

Project code is **MIT** (see the `SPDX-License-Identifier` line in each file).
Code derived from Monero is **BSD-3-Clause**, the ref10 ed25519 parts are
public domain, and the Polyseed implementation is ported from tevador/polyseed
(Apache-2.0). LVGL, GFX Library for Arduino and the ESP32 Arduino core keep
their own licenses.

ColdPunk is not affiliated with the Monero Project, Feather Wallet or Cake
Wallet.
