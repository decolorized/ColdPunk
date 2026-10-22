#!/bin/sh
# Flashes the ColdPunk firmware in this folder (Linux / macOS).
#
#   ./flash.sh                  esptool finds the board's port itself
#   ./flash.sh /dev/ttyUSB0     this port
#   ./flash.sh /dev/ttyUSB0 460800    a lower speed, if 921600 fails
#
# The port: the board's USB-UART bridge (CH340 / CP210x) if it has one;
# otherwise the native USB in the ROM download mode - hold BOOT, plug in (or
# press RESET), release BOOT: "USB JTAG/serial debug unit" appears. Only the bootloader, the partition table and the
# program are written: the wallets (NVS) and the storage partition are kept,
# exactly as with an upload from the Arduino IDE.
#
# Uses ./esptool from this folder, or esptool (v5) from PATH.
set -eu
cd "$(dirname "$0")"

if [ -x ./esptool ] && ./esptool version >/dev/null 2>&1; then
    ESPTOOL=./esptool
elif command -v esptool >/dev/null 2>&1; then
    ESPTOOL=esptool
elif command -v esptool.py >/dev/null 2>&1; then
    ESPTOOL=esptool.py
else
    echo "flash.sh: no esptool here or in PATH (pip install esptool)" >&2
    exit 1
fi

# The images must be the ones the build wrote.
if [ -f SHA256SUMS.txt ]; then
    if command -v sha256sum >/dev/null 2>&1; then
        sha256sum -c --quiet SHA256SUMS.txt
    else
        shasum -a 256 -c --quiet SHA256SUMS.txt
    fi || { echo "flash.sh: the firmware files are damaged (SHA256SUMS.txt)" >&2; exit 1; }
fi

PORT_ARGS=""
[ -n "${1:-}" ] && PORT_ARGS="--port $1"
BAUD=${2:-921600}

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

# shellcheck disable=SC2086
"$ESPTOOL" --chip esp32s3 $PORT_ARGS --baud "$BAUD" \
    --before "$BEFORE" --after hard-reset \
    write-flash -z --flash-mode keep --flash-freq keep --flash-size keep \
    0x0 bootloader.bin \
    0x8000 partitions.bin \
    0xe000 boot_app0.bin \
    0x10000 coldpunk.bin

echo "Done. The board restarts with the new firmware."
