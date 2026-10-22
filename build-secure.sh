#!/bin/sh
# ColdPunk: firmware for a device with Secure Boot V2 and flash encryption
# (release mode). Needs the keys from make-keys.sh.
#
#   ./build-secure.sh [release|debug|hid]
#
# Builds the firmware as build.sh does and a bootloader with ESP-IDF 5.5.5
# (secure boot + flash encryption, tools/bootloader/sdkconfig.secure), signs
# both with keys/secure_boot_signing_key.pem and encrypts copies with
# keys/flash_encryption_key.bin. The result,
# firmware/ColdPunk-<version>-<board>[-debug|-hid]-secure/, holds:
#
#   first/    signed, not encrypted: for secure-first-flash, which burns the
#             flash encryption key into the chip and writes these; on that
#             first start the bootloader turns on secure boot and flash
#             encryption itself (irreversible)
#   update/   signed and encrypted: for flash.sh / flash.bat on a device that
#             is already secured
#
# The keys never go into the firmware folder. Downloads as
# build-idf-bootloader.sh (ESP-IDF etc., about 3 GB once).
set -eu
cd "$(dirname "$0")"
case "${1:-}" in -h|--help) sed -n '2,22p' "$0"; exit 0 ;; esac
. tools/build/lib.sh
cp_init build-secure.sh "${1:-release}"
cp_keys_dir
[ -f "$SB_KEY" ] && [ -f "$FE_KEY" ] ||
    die "no keys in $KEYS - run ./make-keys.sh once first"

cp_arduino_cli
cp_esptool
cp_commit
cp_board_version
NAME="ColdPunk-$VERSION-$BOARD$SUFFIX-secure"
echo "Building $NAME (profile $PROFILE)"
cp_arduino_build
cp_idf_bootloader secure

W="$TC/secure/$PROFILE"
rm -rf "$W"; mkdir -p "$W"

# ---- the app image, padded for the signature ----------------------------------
# The same elf2image call as the Arduino recipe, plus --secure-pad-v2. Checked
# first without the padding: it must give exactly Arduino's own image.
IMG_ARGS="--chip esp32s3 elf2image --flash-mode dio --flash-freq 80m --flash-size 16MB --elf-sha256-offset 0xb0"
# shellcheck disable=SC2086
"$ESPTOOL" $IMG_ARGS -o "$W/app_check.bin" "$BUILD/ColdPunk.ino.elf" >/dev/null
cmp -s "$W/app_check.bin" "$BUILD/ColdPunk.ino.bin" ||
    die "the app image does not match the Arduino build (flash options changed? see IMG_ARGS)"
# shellcheck disable=SC2086
"$ESPTOOL" $IMG_ARGS --secure-pad-v2 -o "$W/app_padded.bin" "$BUILD/ColdPunk.ino.elf" >/dev/null

# ---- signing -------------------------------------------------------------------
"$ESPSECURE" sign-data --version 2 --keyfile "$SB_KEY" --output "$W/bootloader.bin" "$BL_BIN" >/dev/null
"$ESPSECURE" sign-data --version 2 --keyfile "$SB_KEY" --output "$W/coldpunk.bin" "$W/app_padded.bin" >/dev/null
for f in bootloader.bin coldpunk.bin; do
    "$ESPSECURE" verify-signature --version 2 --keyfile "$SB_KEY" "$W/$f" >/dev/null ||
        die "signature check of $f failed"
done
bl_size=$(wc -c < "$W/bootloader.bin")
[ "$bl_size" -le 32768 ] ||
    die "the signed bootloader is $bl_size bytes; it must fit below the partition table (32768)"
cp "$BUILD/ColdPunk.ino.partitions.bin" "$W/partitions.bin"
cp "$BUILD/boot_app0.bin"               "$W/boot_app0.bin"

# ---- the firmware folder ---------------------------------------------------------
cp_out "$NAME"
mkdir "$OUT/first" "$OUT/update"
for f in bootloader.bin partitions.bin boot_app0.bin coldpunk.bin; do
    cp "$W/$f" "$OUT/first/$f"
done
enc() {  # enc ADDRESS FILE
    "$ESPSECURE" encrypt-flash-data --aes-xts --keyfile "$FE_KEY" --address "$1" \
        --output "$OUT/update/$2" "$W/$2" >/dev/null
}
enc 0x0     bootloader.bin
enc 0x8000  partitions.bin
enc 0xe000  boot_app0.bin
enc 0x10000 coldpunk.bin

cp "$ESPTOOL" "$ESPEFUSE"     "$OUT/"
cp "$ET_DIR/LICENSE"          "$OUT/esptool-LICENSE.txt"
for f in flash.sh flash.bat secure-first-flash.sh secure-first-flash.bat efuse-state.ps1 devices.ps1 README.txt; do
    cp "tools/flash/secure/$f" "$OUT/"
done
chmod +x "$OUT/flash.sh" "$OUT/secure-first-flash.sh" "$OUT/esptool" "$OUT/espefuse"
# Which keys this folder belongs to: the digest of the signing key's public
# part (what the chip will hold) and a hash of the encryption key (only to
# recognise the right key file; it reveals nothing about the key).
"$ESPSECURE" digest-sbv2-public-key --keyfile "$SB_KEY" --output "$W/digest.bin" >/dev/null
od -An -tx1 -v "$W/digest.bin" | tr -d ' \n' > "$OUT/secure_boot_key_digest.txt"
echo >> "$OUT/secure_boot_key_digest.txt"
echo "$(sha256 "$FE_KEY")" > "$OUT/flash_encryption_key_sha256.txt"
# The bootloader in this folder (signed, before encryption) and the version:
# secure-first-flash records them in keys/devices.txt, flash.sh compares.
echo "$(sha256 "$OUT/first/bootloader.bin")" > "$OUT/bootloader_sha256.txt"
echo "$VERSION" > "$OUT/version.txt"
cp_sums "$OUT" first/bootloader.bin first/partitions.bin first/boot_app0.bin first/coldpunk.bin \
    update/bootloader.bin update/partitions.bin update/boot_app0.bin update/coldpunk.bin

echo
echo "Done: firmware/$NAME"
echo "  signed bootloader: $bl_size bytes; key digest $(cat "$OUT/secure_boot_key_digest.txt")"
echo "First time (irreversible): firmware/$NAME/secure-first-flash.sh [port]"
echo "Updates of a secured device: firmware/$NAME/flash.sh [port]   (firmware only; 'full' also writes the bootloader)"
