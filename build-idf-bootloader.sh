#!/bin/sh
# ColdPunk: the normal firmware with a bootloader built by ESP-IDF 5.5.5
# instead of the one the Arduino core ships - same version, same options, no
# secure boot and no flash encryption. For checking that the device behaves
# the same with an IDF-built bootloader before going to build-secure.sh,
# which uses one too. Nothing is burned into eFuse; flashing it is as
# reversible as a normal build.
#
#   ./build-idf-bootloader.sh [release|debug|hid]
#
# Besides what build.sh downloads, this one fetches ESP-IDF 5.5.5 (2 GB),
# a portable Python, the ESP-IDF compiler, cmake and ninja into toolchain/
# (about 3 GB downloaded once, 6 GB on disk). The result goes to
# firmware/ColdPunk-<version>-<board>[-debug|-hid]-idfboot/ with the usual
# flash.sh / flash.bat.
set -eu
cd "$(dirname "$0")"
case "${1:-}" in -h|--help) sed -n '2,16p' "$0"; exit 0 ;; esac
. tools/build/lib.sh
cp_init build-idf-bootloader.sh "${1:-release}"

cp_arduino_cli
cp_esptool
cp_commit
cp_board_version
NAME="ColdPunk-$VERSION-$BOARD$SUFFIX-idfboot"
echo "Building $NAME (profile $PROFILE)"
cp_arduino_build
cp_idf_bootloader plain

cp_out "$NAME"
cp "$BL_BIN"                            "$OUT/bootloader.bin"
cp "$BUILD/ColdPunk.ino.partitions.bin" "$OUT/partitions.bin"
cp "$BUILD/boot_app0.bin"               "$OUT/boot_app0.bin"
cp "$BUILD/ColdPunk.ino.bin"            "$OUT/coldpunk.bin"
cp "$ESPTOOL"                           "$OUT/esptool"
cp "$ET_DIR/LICENSE"                    "$OUT/esptool-LICENSE.txt"
cp tools/flash/flash.sh tools/flash/flash.bat tools/flash/README.txt "$OUT/"
chmod +x "$OUT/flash.sh" "$OUT/esptool"
cp_sums "$OUT" bootloader.bin partitions.bin boot_app0.bin coldpunk.bin

echo
echo "Done: firmware/$NAME (bootloader: ESP-IDF $IDF_VERSION, no secure boot)"
echo "Flash: firmware/$NAME/flash.sh [port]   (wallets are kept)"
echo "Back to the Arduino bootloader: flash a build.sh folder."
