#!/bin/sh
# Updates a SECURED ColdPunk device (secure boot + flash encryption already on)
# with the signed and encrypted images in update/ (Linux / macOS).
#
#   ./flash.sh                  esptool finds the port
#   ./flash.sh /dev/ttyUSB0     this port
#   ./flash.sh /dev/ttyUSB0 460800    a lower speed, if 921600 fails
#
# The chip is in Secure Download Mode: esptool runs without its stub, cannot
# read the flash and cannot verify what it wrote. The wallets (NVS) and the
# storage partition are not touched. For a device that is NOT secured yet
# use secure-first-flash.sh: these encrypted images do not boot there.
set -eu
cd "$(dirname "$0")"

if [ -x ./esptool ] && ./esptool version >/dev/null 2>&1; then
    ESPTOOL=./esptool
elif command -v esptool >/dev/null 2>&1; then
    ESPTOOL=esptool
else
    echo "flash.sh: no esptool here or in PATH (pip install esptool)" >&2
    exit 1
fi

if command -v sha256sum >/dev/null 2>&1; then
    sha256sum -c --quiet SHA256SUMS.txt
else
    shasum -a 256 -c --quiet SHA256SUMS.txt
fi || { echo "flash.sh: the firmware files are damaged (SHA256SUMS.txt)" >&2; exit 1; }

PORT_ARGS=""
[ -n "${1:-}" ] && PORT_ARGS="--port $1"
BAUD=${2:-921600}

# shellcheck disable=SC2086
"$ESPTOOL" --chip esp32s3 $PORT_ARGS --baud "$BAUD" --no-stub \
    --before default-reset --after hard-reset \
    write-flash -z --flash-mode keep --flash-freq keep --flash-size keep \
    0x0 update/bootloader.bin \
    0x8000 update/partitions.bin \
    0xe000 update/boot_app0.bin \
    0x10000 update/coldpunk.bin

echo "Done. The board restarts with the new firmware."
