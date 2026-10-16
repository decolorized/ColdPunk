#!/bin/sh
# ColdPunk: builds the firmware on Linux / macOS. Everything the build needs
# is downloaded into ./toolchain next to this script - arduino-cli, the ESP32
# core with its compilers, the libraries and esptool - nothing is installed
# into the system or the home folder. The first build downloads about 1.5 GB;
# later builds reuse it.
#
#   ./build.sh            release build (sketch.yaml profile "coldpunk")
#   ./build.sh debug      core log at Info level ("coldpunk-debug")
#   ./build.sh hid        HID only, no serial transport ("coldpunk-hid")
#
# The board is the one selected in board_config.h. The result goes to
# firmware/ColdPunk-<version>-<board>[-debug|-hid]/: the images, esptool and
# flash.sh / flash.bat, which flash the board without touching the wallets.
#
# See also build-idf-bootloader.sh and build-secure.sh.
# Needs: curl (or wget), tar, sha256sum (or shasum).
set -eu
cd "$(dirname "$0")"
case "${1:-}" in -h|--help) sed -n '2,17p' "$0"; exit 0 ;; esac
. tools/build/lib.sh
cp_init build.sh "${1:-release}"

cp_arduino_cli
cp_esptool
cp_commit
cp_board_version
NAME="ColdPunk-$VERSION-$BOARD$SUFFIX"
echo "Building $NAME (profile $PROFILE)"
cp_arduino_build

cp_out "$NAME"
cp "$BUILD/ColdPunk.ino.bootloader.bin" "$OUT/bootloader.bin"
cp "$BUILD/ColdPunk.ino.partitions.bin" "$OUT/partitions.bin"
cp "$BUILD/boot_app0.bin"               "$OUT/boot_app0.bin"
cp "$BUILD/ColdPunk.ino.bin"            "$OUT/coldpunk.bin"
cp "$ESPTOOL"                           "$OUT/esptool"
cp "$ET_DIR/LICENSE"                    "$OUT/esptool-LICENSE.txt"
cp tools/flash/flash.sh tools/flash/flash.bat tools/flash/README.txt "$OUT/"
chmod +x "$OUT/flash.sh" "$OUT/esptool"
cp_sums "$OUT" bootloader.bin partitions.bin boot_app0.bin coldpunk.bin

echo
echo "Done: firmware/$NAME"
echo "Flash: firmware/$NAME/flash.sh [port]   (wallets are kept)"
