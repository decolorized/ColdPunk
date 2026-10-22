#!/bin/sh
# Updates a SECURED ColdPunk device (secure boot + flash encryption already on)
# with the signed and encrypted images in update/ (Linux / macOS).
#
#   ./flash.sh                    the firmware only (0x10000), port found by esptool
#   ./flash.sh /dev/ttyUSB0       this port
#   ./flash.sh /dev/ttyUSB0 460800    a lower speed, if 921600 fails
#   ./flash.sh full [port] [baud] also the bootloader, partition table and
#                                 otadata - only when this folder's bootloader
#                                 must replace the one on the device
#
# Before writing it checks, and stops on any mismatch:
#   * the images against SHA256SUMS.txt;
#   * that the keys this folder was built with are YOUR keys: the signing key
#     digest against keys/secure_boot_key_digest.txt and the flash
#     encryption key file against flash_encryption_key_sha256.txt
#     (keys folder: ../../keys, or $COLDPUNK_KEYS);
#   * keys/devices.txt (written by secure-first-flash): which bootloader the
#     device got, so "full" is suggested only when it changed;
#   * you confirm that the digest shown matches Settings -> About -> "SB key"
#     on the device.
# The chip is in Secure Download Mode: esptool runs without its stub, cannot
# read the flash and cannot tell an encrypted image from a plain one, so it
# refuses to write unless forced; the checks above are why --force is safe
# here. The wallets (NVS) and the storage partition are never touched.
set -eu
cd "$(dirname "$0")"
here=$(pwd)
die() { echo "flash.sh: $*" >&2; exit 1; }

FULL=0; PORT=""; BAUD=921600; n=0
for a in "$@"; do
    case "$a" in
        full) FULL=1 ;;
        *) n=$((n + 1)); if [ $n = 1 ]; then PORT=$a; else BAUD=$a; fi ;;
    esac
done

if [ -x ./esptool ] && ./esptool version >/dev/null 2>&1; then
    ESPTOOL=./esptool
elif command -v esptool >/dev/null 2>&1; then
    ESPTOOL=esptool
else
    die "no esptool here or in PATH (pip install esptool)"
fi

if command -v sha256sum >/dev/null 2>&1; then
    sha() { sha256sum "$1" | cut -d' ' -f1; }
    sha256sum -c --quiet SHA256SUMS.txt || die "the firmware files are damaged (SHA256SUMS.txt)"
else
    sha() { shasum -a 256 "$1" | cut -d' ' -f1; }
    shasum -a 256 -c --quiet SHA256SUMS.txt || die "the firmware files are damaged (SHA256SUMS.txt)"
fi

# ---- the keys ----------------------------------------------------------------
KEYS="${COLDPUNK_KEYS:-$here/../../keys}"
DIGEST=$(tr -d ' \r\n' < secure_boot_key_digest.txt)
[ -f "$KEYS/secure_boot_key_digest.txt" ] ||
    die "no keys in $KEYS (set COLDPUNK_KEYS to the keys folder of make-keys)"
[ "$(tr -d ' \r\n' < "$KEYS/secure_boot_key_digest.txt")" = "$DIGEST" ] ||
    die "this folder is signed with a DIFFERENT key than $KEYS - the device would not boot it"
[ -f "$KEYS/flash_encryption_key.bin" ] || die "no $KEYS/flash_encryption_key.bin"
[ "$(sha "$KEYS/flash_encryption_key.bin")" = "$(tr -d ' \r\n' < flash_encryption_key_sha256.txt)" ] ||
    die "this folder is encrypted with a DIFFERENT flash encryption key than $KEYS"

# ---- the device registry -------------------------------------------------------
BL_SHA=$(tr -d ' \r\n' < bootloader_sha256.txt)
REG="$KEYS/devices.txt"
known_bl=""
if [ -f "$REG" ]; then
    known_bl=$(awk -F '\t' -v d="$DIGEST" '$1 !~ /^#/ && $3 == d { b = $4 } END { print b }' "$REG")
    [ -n "$known_bl" ] || echo "keys/devices.txt lists no device secured with these keys."
fi
if [ "$FULL" = 0 ] && [ -n "$known_bl" ] && [ "$known_bl" != "$BL_SHA" ]; then
    echo "Note: this folder's bootloader differs from the one recorded for your device."
    echo "      Only the firmware is written; the bootloader on the device keeps working."
    echo "      Run with 'full' only if the new bootloader is needed."
fi

# ---- confirm ---------------------------------------------------------------------
echo
echo "  Signing key digest: $(printf %s "$DIGEST" | cut -c1-8)...$(printf %s "$DIGEST" | cut -c57-64)"
echo "  On the device: Settings -> About -> \"SB key\" must show the same."
if [ "$FULL" = 1 ]; then
    echo "  Writing: bootloader, partition table, otadata and firmware."
else
    echo "  Writing: firmware only."
fi
printf 'Same digest on the device? Type y to write: '
read -r answer
[ "$answer" = "y" ] || [ "$answer" = "Y" ] || die "cancelled, nothing was written"

PORT_ARGS=""
[ -n "$PORT" ] && PORT_ARGS="--port $PORT"

# 0.3.6: a board without a USB-UART bridge is put into the ROM download mode
# by hand: hold BOOT, plug in or press RESET, release BOOT. The chip then
# already waits, and esptool must not reset it first - after "Flash only with
# BOOT" (DIS_FORCE_DOWNLOAD) a reset from the host may not bring it back into
# the download mode. So: talk to it as it is; only if nothing answers, let
# esptool reset it the usual way (USB-UART auto-reset).
BEFORE=no-reset
# shellcheck disable=SC2086
if ! "$ESPTOOL" --chip esp32s3 $PORT_ARGS --no-stub --connect-attempts 2 --before no-reset --after no-reset \
        get-security-info >/dev/null 2>&1; then
    BEFORE=default-reset
    echo "Not in the download mode yet: esptool resets the board (or hold BOOT and press RESET, then run this again)."
fi
if [ "$FULL" = 1 ]; then
    set -- 0x0 update/bootloader.bin 0x8000 update/partitions.bin \
           0xe000 update/boot_app0.bin 0x10000 update/coldpunk.bin
else
    set -- 0x10000 update/coldpunk.bin
fi
# shellcheck disable=SC2086
"$ESPTOOL" --chip esp32s3 $PORT_ARGS --baud "$BAUD" --no-stub \
    --before "$BEFORE" --after hard-reset \
    write-flash --force -z --flash-mode keep --flash-freq keep --flash-size keep "$@"

if [ "$FULL" = 1 ] && [ -f "$REG" ]; then
    # Remember the bootloader now on the device(s) with these keys.
    awk -F '\t' -v d="$DIGEST" -v b="$BL_SHA" 'BEGIN { OFS = "\t" } $1 !~ /^#/ && $3 == d { $4 = b } { print }' \
        "$REG" > "$REG.new" && mv "$REG.new" "$REG"
fi
echo "Done. The board restarts with the new firmware."
