#  ColdPunk

**ColdPunk** is an air-gapped Monero cold wallet firmware for ESP32-S3 boards
with a display. It keeps your seed on the device, computes key images and signs
transactions there, and talks to a watch-only wallet on your PC only through a
small USB protocol that carries files, never secrets.

Website: **[monerocoldwallet.diy](http://monerocoldwallet.diy)**

Two ways to talk to the PC:

- **USB** - **[MoneroPunkSigner](https://github.com/decolorized/MoneroPunkSigner)**,
  a fork of Feather Wallet that speaks the device protocol natively. A
  stand-alone Python courier (`tools/tools/mwlink`) works with stock Feather
  as well.
- **microSD card** (boards with a slot) - **any** Monero wallet with the
  standard cold-signing files: stock **Feather**, **monero-wallet-gui** or
  **monero-wallet-cli** as a view-only wallet. Nothing to install on the PC.

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
  watch-only wallet                               seed, passphrase, spend key
    USB: MoneroPunkSigner                           never leave the device
    SD:  Feather, monero-wallet-gui,
         monero-wallet-cli
                         USB (mwlink) or microSD
  export outputs        ──────── outputs ───────▶  "Generate key images for N
                                                   outputs?"  → Yes
  import key images     ◀────── key images ──────  key images

  create transaction    ───── unsigned tx ─────▶  review amount, fee, change and
                                                   every full destination address
  broadcast             ◀────── signed tx ──────  CLSAG + Bulletproofs+ on device

  restore from keys     ── request view-only ──▶  "Send the view key?" → Yes
    (view-only)         ◀─ address + view key ──    USB
                        ◀─ <wallet>_viewonly.txt    SD: wallet menu →
                                                    View key to SD card
```

Over USB the files travel inside the mwlink protocol; over the card they are
ordinary files - the same ones Feather, the Monero GUI and the CLI write and
read for cold signing - placed in the card's root folder.

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
  wallets: with and without the passphrase. A wallet always opens **without**
  it; the passphrase wallet is reached through **Open passphrase** in the
  wallet's menu - which every wallet has, so nothing shows which one has a
  passphrase (see [Passphrases](#passphrases-and-seed-formats)).
- Restores **Cake Wallet / Cupcake** polyseeds whose phrase is encrypted with
  the passphrase (polyseed "encrypted" flag). Detected automatically from the
  phrase. New wallets are always created in the Feather format.
- Import from raw keys (spend + view) and **view-only** wallets.
- Up to 64 wallets per user; Mainnet, Testnet and Stagenet.

**Operations**

- **Key image sync**: Feather outputs export → key images, with a progress bar.
  An export of **all** outputs (`export_outputs all` in monero-wallet-cli)
  also tells the device which old outputs are no longer the wallet's.
  The **All saved key images** checkbox on the confirmation adds the key
  images of earlier outputs the device already gave out (by their transfer
  number in the PC wallet) in front of a partial export.
- **Transaction signing**: CLSAG ring signatures and Bulletproofs+ range proofs
  computed on the device. Up to 4 transactions per Feather transfer.
- The signing screen shows amount, fee, change, inputs and outputs, and the
  **full address of every recipient**. The change address is checked against
  the wallet (substitution protection).
- A **key image cache** remembers which outputs the device has seen. It is
  bound to the wallet, protected against rollback (generation counter in the
  sealed account directory) and not limited in size, and the device warns
  about inputs already spent by an earlier signature.
- Address and private view key shown as text on the device.
- PC requests for the address or the view-only data (address + private view
  key + restore height) with a plain Yes / No on the device.
- **SD card exchange** (ES3C28P, Touch-LCD-2): the wallet menu lists the
  standard Monero cold-signing files (outputs, unsigned transactions) of
  Feather, monero-wallet-gui or monero-wallet-cli in the card root (newest
  first). Pick one to sign it or to make key images; the
  result is written next to it with the same date. The list follows the card:
  it empties when the card is pulled out and fills again when one is put in.
- **View key to SD card** (ES3C28P, Touch-LCD-2): `<wallet>_viewonly.txt` with the primary
  address, private view key and restore height, after a warning on the device.

**Device**

- Optional disguise: with **Settings → Minesweeper at start** on, the device
  shows a Minesweeper game at power-on and after every lock and opens the
  password screen only after a secret gesture. Off by default.
- **Account password** (always 8–64 characters; weak ones draw a warning): 200 000
  PBKDF2-HMAC-SHA256 rounds on the SHA accelerator, with the chip's eFuse HMAC
  key mixed in between and at the end. The attempt
  counter is written before each check; after 10 wrong passwords the delay
  grows from 1 minute to 8 hours (at most 10 minutes once an account has
  logged in since power-on); any correct password clears the count; from
  the 45th a number on the screen has to be typed first, and the 50th in a
  row erases the device (`MW_PW_*` in
  `app_config.h`). Typing the reset phrase into the password field erases
  the device too.
- **Accounts with their own passwords** (16..24 per chip, 64 wallets each,
  each with a name you can change): each password opens only its own
  wallets, nothing on the device lists the accounts or their number (always
  24 same-size slots), and an account can only be deleted with its own
  password.
- Per wallet: its own **network** (Mainnet / Stagenet / Testnet), **Check
  seed** (does a typed phrase match the wallet?), an estimated **balance**
  with a **transaction list** (per account, can be switched off): everything
  received, grouped by transaction, newest first; the transactions signed on
  this device marked `*`; what was spent elsewhere and outputs of unknown
  amount marked `?`.
- **Lock firmware updates**: burns the eFuses that switch JTAG and the
  USB/UART download mode off for good (irreversible).
- Power-loss-safe storage (**LittleFS**; FAT storage of older firmware is
  converted once, through PSRAM, after a confirmation).
- **Passphrase hint** per wallet (optional, shown on *Open passphrase*, only to
  its own account; any wallet can have one). Made
  for showing only part of the funds under coercion; what a flash dump still
  shows is in [`tools/docs/security.md`](tools/docs/security.md) §4a.
- **USB is enabled only after the correct password.** Before it nothing at all
  appears on USB (the builds use *CDC On Boot: Disabled*); after it the
  device enumerates as "Monero Cold Wallet" with its HID link (and, built
  with `MW_USE_SERIAL 1`, its own CDC port), and the console stays on UART0.
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

### One script (recommended)

`build.bat` (Windows) and `build.sh` (Linux, macOS) download everything the
build needs into `toolchain/` inside the project folder - arduino-cli, the
pinned ESP32 core with its compilers, the libraries and esptool - and install
nothing into the system or the home folder. Next to the built firmware they
put esptool and a flash script, so the result is one folder you can flash
from, on this computer or on another one.

**What you need**

| | Windows | Linux | macOS |
| :--- | :--- | :--- | :--- |
| System | 10 (1803 or later) or 11, 64-bit | x86-64 or ARM64 | Intel or Apple Silicon |
| Tools | nothing (curl, tar, certutil come with Windows) | `curl` or `wget`, `tar`, `sha256sum` | nothing extra |
| Disk | about 3 GB free | about 3 GB free | about 3 GB free |
| Network | the first build downloads about 1.5 GB | | |

Plus a USB **data** cable (a charge-only cable shows no port) and, on
Windows, the driver of the board's USB-UART chip if Windows does not install
it itself (CH340: wch-ic.com, CP210x: silabs.com).

#### 1. Get the source

```sh
git clone https://github.com/decolorized/ColdPunk.git
```

or download the ZIP from GitHub and unpack it. **The folder must be named
`ColdPunk`** (arduino-cli requires the folder to match `ColdPunk.ino`): a
GitHub ZIP unpacks as `ColdPunk-main` - rename it. On Windows keep the path
short, e.g. `C:\ColdPunk` or `Documents\ColdPunk`: the ESP32 core has deeply
nested folders.

With git, enable the hooks once so that Settings → About shows the commit
(see [Commit hash in About](#commit-hash-in-about)); the build scripts refresh
it themselves when git is installed.

#### 2. Choose the board

Open [`board_config.h`](board_config.h) and leave exactly one
`#define MW_BOARD_...` uncommented ([Supported boards](#supported-boards)).
The reference board `MW_BOARD_ES3C28P` is selected by default.

#### 3. Build

| | Windows | Linux / macOS |
| :--- | :--- | :--- |
| Release | `build.bat` (or double-click it) | `./build.sh` |
| Core log at Info level | `build.bat debug` | `./build.sh debug` |
| HID only, no COM port | `build.bat hid` | `./build.sh hid` |

The first build takes 10-30 minutes, most of it downloading; later builds
take a minute or two. The script checks the SHA-256 of arduino-cli and
esptool; the core and the libraries are pinned in
[`sketch.yaml`](sketch.yaml) and checked by arduino-cli. At the end it
prints the folder with the result:

```
firmware/ColdPunk-0.3.4-ES3C28P/
  bootloader.bin  partitions.bin  boot_app0.bin  coldpunk.bin
  SHA256SUMS.txt  esptool(.exe)   flash.bat  flash.sh  README.txt
```

`esptool` is the one for the OS the build ran on. Elsewhere the flash scripts
use esptool v5 from `PATH` (`pip install esptool`).

#### 4. Connect the board

The native USB port is the wallet's own link to the PC (HID, CDC), so the
firmware is written through the board's **USB-UART bridge** (UART0, a CH340
or CP210x chip). On a board with two USB connectors use the one marked
UART / COM.

| | Where the port shows up |
| :--- | :--- |
| Windows | Device Manager → Ports (COM & LPT): `USB-SERIAL CH340 (COM5)` or `Silicon Labs CP210x (COM5)` |
| Linux | `/dev/ttyUSB0` or `/dev/ttyACM0` (`ls /dev/tty{USB,ACM}*`) |
| macOS | `/dev/cu.usbserial-*` or `/dev/cu.wchusbserial*` |

A board with **only the native USB port** is flashed through the chip's ROM
bootloader: hold **BOOT**, plug the cable in (or press and release **RESET**
while holding BOOT), release BOOT. A new port appears (*USB JTAG/serial debug
unit*); flash to it, then press RESET.

#### 5. Flash

Run the script from the firmware folder:

```sh
flash.bat                   # Windows: asks for the port (Enter = find it)
flash.bat COM5              # Windows, this port
./flash.sh /dev/ttyUSB0     # Linux / macOS
flash.bat COM5 460800       # a lower speed if 921600 fails
```

The script first checks the images against `SHA256SUMS.txt` and refuses to
flash damaged files. It then writes the bootloader (0x0), the partition
table (0x8000), `boot_app0` (0xe000) and the program (0x10000), and restarts
the board. Go on with [First start](#first-start).

#### Updating

Build the new version (or take its firmware folder) and flash it the same
way. **The wallets are kept:** only the four images are written; the NVS
partition (wallets, settings, password record) and the `storage` partition
stay untouched, exactly as with an upload from the IDE. Never flash a merged
16 MB image or run `esptool erase-flash`: that wipes the wallets (have your
seed words at hand before any update anyway).

From a version before 0.3 the first start converts the `storage` partition
from FAT to LittleFS ("Storage update"): the device reads the files into
PSRAM, checks them and asks for a code. **Do not cut the power for about a
minute after the code** - the partition is erased and written back, and a cut
then loses the wallets (restore them from the seed). Declining keeps the old
format until the next start. Firmware older than 0.3 cannot read the
converted partition.

#### If something goes wrong

| Message / symptom | What to do |
| :--- | :--- |
| `The project folder must be named ColdPunk` | Rename the folder (a GitHub ZIP gives `ColdPunk-main`). |
| `Download failed`, `checksum mismatch` | Run the script again (a damaged download is deleted). Behind a proxy, set `HTTPS_PROXY`. |
| Windows: `No such file or directory` deep inside the core during the build | The path is too long: move the project to `C:\ColdPunk`. |
| No new port when the board is plugged in | Another cable (data, not charge-only), another USB port, the CH340 / CP210x driver. |
| `Failed to connect to ESP32-S3` / `No serial data received` | Close everything that holds the port (a serial monitor, MoneroPunkSigner, mwlink), then use BOOT / RESET as in step 4; try a lower speed. |
| Linux: `Permission denied: /dev/ttyUSB0` | `sudo usermod -aG dialout $USER`, then log out and in. |
| macOS: "esptool cannot be opened" | The folder came through a browser or AirDrop: `xattr -dr com.apple.quarantine .` in the firmware folder. |
| `The firmware files are damaged` | The folder was changed or copied incompletely: copy it again or rebuild. |

`toolchain/` can be deleted at any time to free the space; the next build
downloads it again. `firmware/` keeps one folder per version and board.

### Secure boot and flash encryption (optional, irreversible)

Without secure boot anyone with the device and a cable can flash their own
firmware and use the chip's HMAC key to guess the password at full speed
([security.md](tools/docs/security.md) §6.3). Three more script pairs close
that, with a bootloader built by ESP-IDF 5.5.5 - the version the Arduino core
is built from, with the same options.

`build` uses the bootloader that ships with the Arduino core. The Arduino
core is built without secure boot and flash encryption, so its bootloader has
no code for them; the secured device needs a bootloader built with those
options:

* `build-idf-bootloader` builds the bootloader with ESP-IDF using exactly the
  Arduino core's options. Its code is identical to Arduino's byte for byte
  (only the build date and the maximum chip revision field in the header
  differ: v0.99 instead of "any"). It is not a different bootloader but a
  check that the ESP-IDF build is set up as the Arduino one.
* `build-secure` builds the same bootloader plus the secure boot and flash
  encryption options. That adds code (signature check of the firmware at
  every start, enabling the protection and encrypting the flash on the first
  start), so it is larger and does not match Arduino's.

| Script | What it does |
| :--- | :--- |
| `build-idf-bootloader.bat` / `.sh` | the normal firmware with the IDF-built bootloader (same code as Arduino's), **no** secure boot, nothing burned |
| `make-keys.bat` / `.sh` | creates `keys/secure_boot_signing_key.pem` (RSA-3072) and `keys/flash_encryption_key.bin` (XTS-AES-128) once; refuses to run when either exists |
| `build-secure.bat` / `.sh` | the firmware plus a bootloader with Secure Boot V2 and flash encryption in release mode; signs both, and makes encrypted copies for updates |

These download ESP-IDF 5.5.5 (2 GB), a portable Python, the IDF compiler,
cmake and ninja into `toolchain/` as well - about 3 GB once, 6 GB on disk.
The keys stay in `keys/` (or where `COLDPUNK_KEYS` points); they never go into
a firmware folder and `keys/` is in `.gitignore`.

**Order:**

1. Flash a normal build and finish the [first start](#first-start): the
   wallet's eFuse key (`HMAC_UP`) must exist before securing - afterwards the
   chip can no longer read-protect a new key.
2. Optionally flash a `build-idf-bootloader` folder and check that the device
   starts and works as before.
3. `make-keys` once; copy `keys/` to two offline places. **Lose the keys and
   the device can never be updated again; leak them and anyone can make
   firmware it will run.**
4. `build-secure`, then in its folder `secure-first-flash.bat COM5` /
   `./secure-first-flash.sh /dev/ttyUSB0`. It checks the eFuses (stops if the
   device is already secured, has no wallet key, or lacks two free key
   blocks), asks you to type `SECURE`, burns the flash encryption key
   (espefuse asks for `BURN`) and writes the signed images. On that start the
   bootloader burns the digest of your signing key, revokes the two other
   digest slots, encrypts the bootloader, partition table, otadata and
   firmware in place, turns JTAG off and the ROM download mode into its secure
   variant. **Up to a minute with a dark screen - do not cut the power.** The
   wallets are kept.
   The script asks for a name and records the device in `keys/devices.txt`.
5. From then on update only with `flash.bat` / `flash.sh` from a newer
   `build-secure` folder made with the same keys. It writes **only the
   firmware** by default (`full` also writes the bootloader, partition table
   and otadata - it says when this folder's bootloader differs from the one
   recorded for the device). Before writing it checks that the folder is
   signed and encrypted with the keys in `keys/`, shows the signing key digest
   and asks you to compare it with **Settings → About → SB key** on the
   device. The secured chip makes esptool refuse ordinary writes ("flash
   encryption is enabled ... could brick the device"); the images are already
   encrypted, so the script writes them with `--force` after its own checks.
   A normal build no longer boots.

Size note: the Arduino core keeps the partition table at 0x8000, so the
signed bootloader must fit into 32 KB. With secure boot and flash encryption
it does only without log output (`CONFIG_BOOTLOADER_LOG_LEVEL_NONE`): a
secured device that does not start prints nothing on the serial port.

### With arduino-cli

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
| Erase All Flash Before Sketch Upload | **Disabled** (NVS and the `storage` partition hold the wallets) |
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

### Commit hash in About

Settings → About and the boot log show which commit the firmware was built
from (`commit c50033e`, `-dirty` when there were uncommitted changes). The hash
comes from `src/config/build_commit.h`, which the git hooks in `.githooks/`
write after every commit and checkout. Enable them once in your clone:

```sh
git config core.hooksPath .githooks
sh .githooks/update-build-commit      # first time, or after editing files
```

Without the hooks (or from a source archive) About says `commit unknown`. A
hash rather than a build time keeps the build reproducible: the same commit
gives the same binary.

### Partitions

| Name | Type | Offset | Size |
| :--- | :--- | ---: | ---: |
| nvs | data/nvs | 0x9000 | 20 KB |
| otadata | data/ota | 0xE000 | 8 KB |
| app0 | app/ota_0 | 0x10000 | 4 MB |
| storage | data/spiffs (LittleFS) | 0x410000 | ~3.9 MB |

---

## First start

1. **Hardware key.** At the first start, before the password, a
   chip without the key offers to burn a random 32-byte key into the highest
   free eFuse key block (`BLOCK_KEY5` on a fresh chip; purpose `HMAC_UP`,
   read-protected) behind two confirmation screens. **This is irreversible.**
   The device does not work without it; declining goes back to the start. Every wallet on the device
   is sealed with a key derived from it; a firmware image copied to another
   chip cannot open them. Bench provisioning with `espefuse.py` is described in
   [`tools/docs/security.md`](tools/docs/security.md) §4.
2. **Account password.** Choose one (entered twice). It is needed at every
   unlock and also protects the sealed seeds.
3. **Create or import a wallet**, write the words on paper (they are shown
   only once), pass the word check and compare the address with your PC
   wallet.

**Minesweeper disguise (optional).** By default the device starts straight at
the password screen. **Settings → Minesweeper at start → On** makes it start -
and return after every lock - as a Minesweeper game that names no wallet.
Before the option is switched on the device shows how to get past the game:

1. step on a mine (lose the game);
2. tap the exploded mine **three times within 2 seconds** (button boards:
   select it and press SELECT three times).

Any other tap resets the count; there is no other way out of the game, so
remember the gesture. It is a disguise, not a protection - the password is.
Devices updated from firmware before 0.3.4, which always started with the
game, keep it on until it is switched off.

---

## Everyday use

**Key image sync** (so the watch-only wallet knows what is spent):

1. Open the wallet on the device.
2. In MoneroPunkSigner: *Tools → Offline transaction signing*, method
   **HID device**, *Send via HID*. With stock Feather, save the outputs file
   into the folder watched by `mwlink_gui.py`.
3. Confirm on the device. Key images are imported automatically (or saved
   back to the folder for Feather).

After importing key images the watch-only wallet knows which outputs are
spent (the balance drops accordingly), but it lists the **outgoing
transactions** only after it scans the blocks again knowing them: rescan
the blockchain keeping the key images (`rescan_bc keep_ki` in
monero-wallet-cli; in Feather and the GUI a rescan from the restore
height). This is the Monero wallet's own behaviour, not the device's.

**Signing:**

1. Create the transaction in the watch-only wallet and choose **Sign on HID**
   (or save the unsigned file for `mwlink`).
2. On the device check the amount, the fee and **every full address**, then
   *Sign*. Do not power off while Bulletproofs+ is computed.
3. The signed transaction comes back; review and broadcast it on the PC.

**Over the SD card (ES3C28P, Touch-LCD-2) - with any Monero wallet:**

The card carries the standard cold-signing files of Monero's own wallet code,
so the PC side can be stock **Feather**, **monero-wallet-gui** or
**monero-wallet-cli**; no MoneroPunkSigner, no driver, no courier.

1. Copy the wallet's file (outputs export, or the unsigned transaction) into
   the **root** of a FAT32 microSD card and insert it into the device.
2. Open the wallet → **SD card files**. Only files the device can process are
   listed, newest first (by the date the PC set, or by the time in the file
   name). Each row shows the type, size and date; processed files are marked
   *done*.
3. Pick a file and confirm on the device, exactly as over USB.
4. The result (`…_keyImages` or `…_signed_monero_tx`) is written next to the
   source with the source's date. Import it in the PC wallet.

| | Feather | monero-wallet-gui | monero-wallet-cli |
| :--- | :--- | :--- | :--- |
| View-only wallet | *Restore wallet from keys → View only* | *Restore wallet from keys*, spend key empty | `monero-wallet-cli --generate-from-view-key <name>` |
| Outputs → card | *Tools → Offline transaction signing*: export outputs | export outputs (offline signing) | `export_outputs <card>/wallet_outputs` |
| Key images ← card | same dialog: import key images | import key images | `import_key_images <card>/wallet_keyImages` |
| Transaction → card | create the transaction, save the unsigned file | create the transaction file | `transfer <address> <amount>` writes `unsigned_monero_tx` |
| Signed ← card | load the signed file, broadcast | submit the signed file | `submit_transfer` reads `signed_monero_tx` from the current folder |

For the view-only wallet take the address, view key and restore height from
`<wallet>_viewonly.txt` (below). The CLI writes `unsigned_monero_tx` into its
current folder: copy it to the card, and the device's `signed_monero_tx` back
into that folder before `submit_transfer`.

On the first use the device writes `ColdPunk_readme.txt` with these steps to
the card. Files up to 256 KB. Every write is flushed and the card unmounted
right after it, and the card is mounted afresh each time the list opens, so it
can be pulled out and swapped at any time except during the write itself. The
open list notices a card pulled out or put in and updates itself.

**View-only wallet on the PC:** in MoneroPunkSigner, *Restore wallet from keys
→ ColdPunk*, then answer *Yes* on the device. Address, view key, restore height
and wallet name are filled in. Without USB: wallet menu → **View key to SD
card** writes `<wallet>_viewonly.txt` (wallet name, network, primary address,
private view key, restore height) to the card for any of the wallets above;
delete the file after use - it shows every incoming payment to whoever reads
it.

The full user guide (in Russian) is
[`tools/docs/user_guide.md`](tools/docs/user_guide.md).

---

## Passphrases and seed formats

| Phrase | Passphrase meaning | Restore on ColdPunk |
| :--- | :--- | :--- |
| Feather / ColdPunk polyseed, legacy 25 words | Monero seed offset: `key = sc_sub(key, cn_slow_hash(passphrase))` | optional; empty = wallet without passphrase |
| Cake Wallet / Cupcake polyseed (encrypted flag) | decrypts the phrase (`polyseed_crypt`), no seed offset | **required**; detected automatically |

**How a passphrase wallet is opened (0.3.5).** Selecting a wallet opens it
without a passphrase, at once. Its menu - every wallet's menu - has **Open
passphrase**: the same screen, about a second of work (`MW_PP_KDF_ROUNDS` =
500 000 PBKDF2-HMAC-SHA256 rounds in 8 chunks with the chip's eFuse HMAC
between them, then AES-256-GCM) and the same answer for every wallet. Only
the right passphrase of a wallet that has one opens its passphrase wallet;
anything else - and any passphrase on a wallet without one - says *Wrong
passphrase*. The "with passphrase" mark is shown only inside that session.

Every wallet has a passphrase record of the same 64 bytes in the sealed
directory: the passphrase wallet's spend key under a key derived from the
passphrase, or random bytes. The slow CryptoNight of the seed offset runs
only once, when the wallet is created or imported. A passphrase is given only
then; it cannot be added, changed or removed later (import the seed again for
that). A guess needs this chip (the eFuse HMAC), so a flash dump cannot be
attacked on a GPU. Wallets of firmware before 0.3.5 that have a passphrase
are opened the old way once (CryptoNight, checked) and then get their record.

A Cake/Cupcake phrase opened without its passphrase gives some other, empty
wallet instead of an error - like any seed without its passphrase. A wrong
passphrase for a Cake/Cupcake phrase cannot be detected at import: it simply
derives another wallet, so always compare the address.

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
  additionally bound to the account password. Records are constant-length, so
  the ciphertext does not reveal the seed type.
- **Fail-closed RNG.** The TRNG is health-tested at boot; a failure stops the
  device instead of producing weak keys.
- **Secrets are wiped** (`mw_memzero`) after use, including the CryptoNight
  scratchpad, transaction secrets after signing, and the session on lock.
- **Atomic password change**, with interrupted changes recovered on the next
  unlock.
- **Users are unlinkable without their passwords**: one sealed directory file
  per account, named after that account's key, among decoys of the same size
  (24 slots in all); no per-user data in NVS; one device-wide attempt
  counter.

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
build.bat, build.sh   build with everything downloaded into toolchain/
build-idf-bootloader, build-secure, make-keys (.bat/.sh)
                      IDF bootloader, secure boot + flash encryption, keys
lv_conf.h             LVGL configuration
partitions.csv        flash layout
res/                  source images (monero.png -> src/ui/img_monero.c)
src/
  config/             app_config.h - build-wide constants
  crypto/             SHA-2, Keccak, HMAC/PBKDF2, AES-GCM, ChaCha, ed25519, CryptoNight, RNG
  data/               word lists (Monero, Polyseed/BIP39)
  monero/             keys, mnemonics, polyseed, addresses, key images, CLSAG,
                      Bulletproofs+, transaction parsing and signing, file formats
  wallet/             account password, sealed wallet store, session, key image cache
  transfer/           mwlink protocol (link.c), USB HID/CDC transport,
                      SD card file browser logic (sd_files.c)
  hal/                display, touch, buttons, SD (SPI and SDIO), logging, host stubs
  ui/                 LVGL screens, keyboards, flows, i18n, Minesweeper,
                      img_monero.c (generated logo, 160 px)
tools/
  img2lvgl.py         PNG -> LVGL 9 C image (RGB565A8): regenerates img_monero.c
  docs/               design, security, protocol, user guide, testing
  build/              lib.bat, lib.sh - shared code of the build scripts
  bootloader/         ESP-IDF project for the bootloader (sdkconfig.defaults, .secure)
  flash/              flash.bat, flash.sh, README.txt copied next to a build;
                      secure/: the scripts of a build-secure folder
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
protocol, the SD card file logic (file kinds, ordering, result and safe file
names), the account password (including weak-password rules) and storage
failure cases. On Windows,
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
| [`tools/docs/device_password.md`](tools/docs/device_password.md) | account password scheme, record format, password rules, eFuse requirement |
| [`tools/docs/usb_link_protocol.md`](tools/docs/usb_link_protocol.md) | mwlink protocol 3 (RU) |
| [`tools/docs/architecture.md`](tools/docs/architecture.md) | layers, FreeRTOS tasks, memory budget, data flows over USB and the SD card (RU) |
| [`tools/docs/ui_screens.md`](tools/docs/ui_screens.md) | screens and navigation |
| [`tools/docs/build_arduino.md`](tools/docs/build_arduino.md) | build settings in detail (RU) |
| [`tools/docs/testing.md`](tools/docs/testing.md) | host tests, on-device checklist (incl. SD card), stagenet procedure (RU) |
| [`boards/README.md`](boards/README.md) | board headers and adding a board |

---

## Related projects

| Project | Role |
| :--- | :--- |
| **[ColdPunk](https://github.com/decolorized/ColdPunk)** (this repository) | firmware of the offline signing device |
| **[MoneroPunkSigner](https://github.com/decolorized/MoneroPunkSigner)** | Feather Wallet fork for the PC: watch-only wallet with native ColdPunk support over USB HID |
| **[monerocoldwallet.diy](http://monerocoldwallet.diy)** | project website |

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
