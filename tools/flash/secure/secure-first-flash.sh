#!/bin/sh
# Turns on Secure Boot V2 and flash encryption on a ColdPunk device
# (Linux / macOS). IRREVERSIBLE: afterwards the chip runs only firmware
# signed with your key, and accepts only images encrypted with your key.
#
#   ./secure-first-flash.sh [port] [baud]
#
# What it does:
#   1. checks the images (SHA256SUMS.txt) and that both keys this folder was
#      built with are the ones in the keys folder (../../keys, or
#      $COLDPUNK_KEYS): the signing key digest and the flash encryption key;
#   2. reads the chip's eFuses and stops when: secure boot or flash
#      encryption is already on (use flash.sh), the wallet's own eFuse key
#      (HMAC_UP) is missing (start the normal firmware once and finish the
#      first start - it cannot be burned afterwards), or fewer than two key
#      blocks are free;
#   3. after you type SECURE, burns the flash encryption key into the lowest
#      free key block (espefuse asks once more: type BURN);
#   4. writes the signed images from first/.
# On that start the bootloader burns the digest of your signing key, revokes
# the other two digest slots, encrypts the bootloader, partition table,
# otadata and firmware in place and locks the chip down (JTAG off, Secure
# Download Mode). This takes up to a minute with a dark screen: do not cut
# the power. The wallets (NVS, storage) are kept.
# The device is then recorded in keys/devices.txt (date, name, key digest,
# bootloader hash, version); flash.sh of later build-secure folders checks it.
set -eu
cd "$(dirname "$0")"
here=$(pwd)
die() { echo "secure-first-flash.sh: $*" >&2; exit 1; }

[ -x ./esptool ] && ./esptool version >/dev/null 2>&1 || die "./esptool is missing or does not run on this system"
[ -x ./espefuse ] && ./espefuse --help >/dev/null 2>&1 || die "./espefuse is missing or does not run on this system"

if command -v sha256sum >/dev/null 2>&1; then
    sha() { sha256sum "$1" | cut -d' ' -f1; }
    sha256sum -c --quiet SHA256SUMS.txt || die "the firmware files are damaged (SHA256SUMS.txt)"
else
    sha() { shasum -a 256 "$1" | cut -d' ' -f1; }
    shasum -a 256 -c --quiet SHA256SUMS.txt || die "the firmware files are damaged (SHA256SUMS.txt)"
fi

KEYS="${COLDPUNK_KEYS:-$here/../../keys}"
FE_KEY="$KEYS/flash_encryption_key.bin"
[ -f "$FE_KEY" ] || die "no $FE_KEY (set COLDPUNK_KEYS to the keys folder)"
[ "$(sha "$FE_KEY")" = "$(tr -d ' \r\n' < flash_encryption_key_sha256.txt)" ] ||
    die "$FE_KEY is not the key this folder was built with"
DIGEST=$(tr -d ' \r\n' < secure_boot_key_digest.txt)
[ -f "$KEYS/secure_boot_key_digest.txt" ] &&
[ "$(tr -d ' \r\n' < "$KEYS/secure_boot_key_digest.txt")" = "$DIGEST" ] ||
    die "this folder is signed with a different key than $KEYS/secure_boot_signing_key.pem"

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
if ! ./esptool --chip esp32s3 $PORT_ARGS --no-stub --connect-attempts 2 --before no-reset --after no-reset \
        get-security-info >/dev/null 2>&1; then
    BEFORE=default-reset
    echo "Not in the download mode yet: esptool resets the board (or hold BOOT and press RESET, then run this again)."
fi

# ---- the chip's state ----------------------------------------------------------
state=$(mktemp)
trap 'rm -f "$state"' EXIT
# shellcheck disable=SC2086
./espefuse --chip esp32s3 $PORT_ARGS --before "$BEFORE" --after no-reset summary --format json --file "$state" >/dev/null ||
    die "cannot read the eFuses (port? BOOT button? see README.txt)"
# efv NAME FIELD: one field of one eFuse from the JSON summary.
efv() {
    awk -v n="\"$1\": {" -v f="\"$2\":" '
        index($0, n) { o = 1; next }
        o && index($0, f) { sub(/^[^:]*: */, ""); sub(/,[ \t\r]*$/, ""); gsub(/"/, ""); print; exit }
        o && /^[ \t]*}/ { exit }' "$state"
}
[ "$(efv SECURE_BOOT_EN value)" = "false" ] && [ "$(efv SPI_BOOT_CRYPT_CNT value)" = "Disable" ] ||
    die "secure boot or flash encryption is already on - use ./flash.sh for updates"

hmac=""; xts=""; free=""
for i in 0 1 2 3 4 5; do
    p=$(efv "KEY_PURPOSE_$i" value)
    case "$p" in
        HMAC_UP) hmac="$hmac $i" ;;
        XTS_AES_128_KEY) xts="$xts $i" ;;
        USER)
            raw=$(efv "BLOCK_KEY$i" raw_value)
            if [ "$(efv "BLOCK_KEY$i" readable)" = "true" ] &&
               [ -z "$(printf %s "${raw#0x}" | tr -d 0)" ]; then
                free="$free $i"
            fi ;;
    esac
done
[ -n "$hmac" ] || die "the wallet's eFuse key (HMAC_UP) is not burned yet. Flash the normal
firmware, finish its first start (it burns the key), then run this again:
after this script the chip can no longer read-protect a new key."
set -- $free
nfree=$#
if [ -n "$xts" ]; then
    set -- $xts
    burn_block=""
    echo "A flash encryption key is already burned in BLOCK_KEY$1 (an interrupted"
    echo "earlier run?). It is used as it is; if it is not your key, the update"
    echo "images will not boot later."
    [ "$nfree" -ge 1 ] || die "no free key block left for the secure boot digest"
else
    [ "$nfree" -ge 2 ] || die "need two free key blocks (flash encryption key, secure boot digest); free:${free:- none}"
    set -- $free
    burn_block=$1
fi

# ---- confirm ---------------------------------------------------------------------
cat <<EOF

  Wallet eFuse key:          BLOCK_KEY$(echo $hmac | cut -d' ' -f1) (HMAC_UP) - kept
  Flash encryption key:      ${burn_block:+BLOCK_KEY$burn_block (burned now)}${burn_block:-already burned}
  Secure boot key digest:    $(cat secure_boot_key_digest.txt)
                             (burned by the bootloader on the first start)

  THIS CANNOT BE UNDONE. Afterwards the device:
    * runs only firmware signed with keys/secure_boot_signing_key.pem
    * takes updates only as images encrypted with keys/flash_encryption_key.bin
      (build-secure.sh, flash.sh in its folder)
    * has JTAG off and the ROM download mode in its secure variant
  Lose the keys and the device can never be updated again.
  Have the seed words of every wallet on paper before you go on.

EOF
printf 'Type SECURE to continue: '
read -r answer
[ "$answer" = "SECURE" ] || die "cancelled, nothing was changed"
printf 'A name for this device in keys/devices.txt (Enter: device): '
read -r DEVNAME
DEVNAME=$(printf %s "${DEVNAME:-device}" | tr '\t' ' ')

# ---- burn the key, write the images ------------------------------------------------
if [ -n "$burn_block" ]; then
    # shellcheck disable=SC2086
    ./espefuse --chip esp32s3 $PORT_ARGS --before no-reset --after no-reset burn-key "BLOCK_KEY$burn_block" "$FE_KEY" XTS_AES_128_KEY ||
        die "burning the key failed or was cancelled - nothing was written to the flash"
fi
# shellcheck disable=SC2086
./esptool --chip esp32s3 $PORT_ARGS --baud "$BAUD" \
    --before no-reset --after hard-reset \
    write-flash -z --flash-mode keep --flash-freq keep --flash-size keep \
    0x0 first/bootloader.bin \
    0x8000 first/partitions.bin \
    0xe000 first/boot_app0.bin \
    0x10000 first/coldpunk.bin ||
    die "writing failed. Run this script again (the key is kept), or flash a normal build to undo."

REG="$KEYS/devices.txt"
[ -f "$REG" ] || printf '# date\tname\tsecure boot key digest\tbootloader sha256\tversion\n' > "$REG"
printf '%s\t%s\t%s\t%s\t%s\n' "$(date +%Y-%m-%d)" "$DEVNAME" "$DIGEST" \
    "$(tr -d ' \r\n' < bootloader_sha256.txt)" "$(tr -d ' \r\n' < version.txt)" >> "$REG"

cat <<EOF

Written. The board restarts and the bootloader now turns on secure boot and
flash encryption: the screen stays dark for up to a minute. DO NOT unplug it.
Then the device starts as usual. Settings -> About shows "SB key" with the
digest above.

Recorded in $REG. From now on update it only with flash.sh from a
build-secure folder made with the same keys (firmware only by default).
EOF
