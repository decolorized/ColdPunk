#!/bin/sh
# ColdPunk: creates the two keys build-secure.sh needs, once.
#
#   keys/secure_boot_signing_key.pem   RSA-3072, signs the bootloader and the
#                                      firmware (Secure Boot V2)
#   keys/flash_encryption_key.bin      256-bit XTS-AES-128 key, encrypts the
#                                      images for updates; secure-first-flash
#                                      burns it into the chip
#
# The folder can be set with COLDPUNK_KEYS=/path. The script never overwrites
# a key: if either file exists it stops and changes nothing. A device secured
# with these keys accepts firmware ONLY signed and encrypted with them - lose
# them and the device can never be updated again; leak them and anyone can
# build firmware the device will run. Keep copies offline.
set -eu
cd "$(dirname "$0")"
case "${1:-}" in -h|--help) sed -n '2,14p' "$0"; exit 0 ;; esac
. tools/build/lib.sh
cp_init make-keys.sh release
cp_keys_dir

for k in "$SB_KEY" "$FE_KEY"; do
    if [ -e "$k" ]; then
        echo "make-keys.sh: $k already exists - nothing was changed." >&2
        echo "The keys are made once. To start over with new keys (only for a" >&2
        echo "device that was never secured with the old ones) move the old" >&2
        echo "files away yourself." >&2
        exit 1
    fi
done

cp_esptool
umask 077
mkdir -p "$KEYS"
chmod 700 "$KEYS"
tmp="$KEYS/.new"
rm -rf "$tmp"; mkdir "$tmp"
"$ESPSECURE" generate-signing-key --version 2 --scheme rsa3072 "$tmp/secure_boot_signing_key.pem" >/dev/null
"$ESPSECURE" generate-flash-encryption-key --keylen 256 "$tmp/flash_encryption_key.bin" >/dev/null
"$ESPSECURE" digest-sbv2-public-key --keyfile "$tmp/secure_boot_signing_key.pem" \
    --output "$tmp/digest.bin" >/dev/null
digest=$(od -An -tx1 -v "$tmp/digest.bin" | tr -d ' \n')
rm -f "$tmp/digest.bin"
# Moved in only when both were made: never half a set.
mv "$tmp/secure_boot_signing_key.pem" "$SB_KEY"
mv "$tmp/flash_encryption_key.bin" "$FE_KEY"
rmdir "$tmp"
chmod 400 "$SB_KEY" "$FE_KEY"
echo "$digest" > "$KEYS/secure_boot_key_digest.txt"
chmod 444 "$KEYS/secure_boot_key_digest.txt"

echo
echo "Keys created in $KEYS:"
echo "  secure_boot_signing_key.pem   (public key digest $digest)"
echo "  flash_encryption_key.bin"
echo
echo "Back them up NOW to two offline places (e.g. two USB sticks)."
echo "Without them a secured device can never be updated."
