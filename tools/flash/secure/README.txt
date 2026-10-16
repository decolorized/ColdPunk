ColdPunk firmware - SECURE BOOT + FLASH ENCRYPTION
=================================================

Built by build-secure for the keys in the project's keys/ folder:
  secure_boot_key_digest.txt       digest of the public signing key (what
                                   the chip holds after the first start)
  flash_encryption_key_sha256.txt  hash of the flash encryption key file
                                   (to recognise the right file)

Files
  first/        signed images, NOT encrypted - only for secure-first-flash
  update/       signed AND encrypted images - for flash on a secured device
  esptool, espefuse (.exe)   Espressif's tools for the OS the build ran on
  secure-first-flash.bat/.sh  one time: burns the key, writes first/
  flash.bat/.sh               updates of an already secured device
  SHA256SUMS.txt              checksums of all images (checked by both)

Before the first time
  * The device must have been started with the NORMAL firmware once and
    gone through its first start: the wallet's own eFuse key (HMAC_UP) has
    to exist. After securing, the chip cannot read-protect a new key.
  * Write down the seed words of every wallet.
  * Keep copies of keys/ in two offline places. Lose them and the device
    can never be updated again; leak them and others can make firmware it
    will run.
  * The keys stay in the project's keys/ folder (or set COLDPUNK_KEYS);
    secure-first-flash needs flash_encryption_key.bin from there.

First time (IRREVERSIBLE)
  Windows:        secure-first-flash.bat COM5
  Linux / macOS:  ./secure-first-flash.sh /dev/ttyUSB0
  Type SECURE, then BURN when espefuse asks. After writing, the board
  restarts and its bootloader turns on secure boot and flash encryption:
  up to a minute with a dark screen - do NOT unplug it. Then it starts as
  usual. Wallets and settings are kept.

Updates
  flash.bat COM5   /   ./flash.sh /dev/ttyUSB0
  Always from a build-secure folder made with the same keys. A normal
  build (build.bat / build.sh) does not boot on a secured device.

What changes on the device
  * Only firmware signed with your key runs; the other two key digest
    slots are revoked.
  * Flash contents are encrypted (bootloader, partition table, otadata,
    firmware); the wallets stay sealed by the device's own eFuse key as
    before.
  * JTAG is off; the ROM download mode works only in its secure variant:
    writing is possible, reading the flash is not.
  * Settings -> Lock firmware updates still works; some of its eFuses
    are already burned or locked by the bootloader then.
  * The bootloader prints nothing (log level none): a device that does not
    start shows nothing on the serial port.
