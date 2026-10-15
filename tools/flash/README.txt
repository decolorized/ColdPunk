ColdPunk firmware
================

Files
  bootloader.bin   0x0       second-stage bootloader
  partitions.bin   0x8000    partition table (partitions.csv)
  boot_app0.bin    0xe000    selects the app partition
  coldpunk.bin     0x10000   the wallet firmware
  SHA256SUMS.txt   checksums of the four images (checked before flashing)
  esptool(.exe)    Espressif's flashing tool, for the OS the build ran on
  flash.bat        flashing on Windows
  flash.sh         flashing on Linux / macOS

Flashing
  1. Connect the board through its USB-UART port (CH340 / CP210x chip,
     UART0) - not the native USB the wallet uses for its HID link.
  2. Windows:        flash.bat            (or: flash.bat COM5)
     Linux / macOS:  ./flash.sh           (or: ./flash.sh /dev/ttyUSB0)
     Without a port esptool tries the ports itself.
  3. If 921600 baud fails, pass a lower speed: flash.bat COM5 460800

  If the board does not enter the bootloader by itself, hold BOOT, press and
  release RESET, release BOOT, and run the script again.

The wallets are kept
  Only the four images above are written. The NVS partition (wallets,
  settings, password record) and the storage partition are not touched,
  exactly as with an upload from the Arduino IDE. Do not flash a "merged"
  16 MB image or run "erase-flash": that wipes the wallets.

Without the bundled esptool (e.g. a folder built on another OS), install
esptool v5 (pip install esptool); the scripts use it from PATH.
