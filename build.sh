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
# Needs: curl (or wget), tar, sha256sum (or shasum).
set -eu

CLI_VERSION=1.5.1
ESPTOOL_VERSION=5.3.1

cd "$(dirname "$0")"
ROOT=$(pwd)
TC="$ROOT/toolchain"

die() { echo "build.sh: $*" >&2; exit 1; }

case "${1:-release}" in
    release) PROFILE=coldpunk;       SUFFIX="" ;;
    debug)   PROFILE=coldpunk-debug; SUFFIX="-debug" ;;
    hid)     PROFILE=coldpunk-hid;   SUFFIX="-hid" ;;
    -h|--help) sed -n '2,15p' "$0"; exit 0 ;;
    *) die "unknown build '$1' (release, debug or hid)" ;;
esac

# arduino-cli wants the sketch folder named after the .ino file.
[ "$(basename "$ROOT")" = "ColdPunk" ] ||
    die "the project folder must be named ColdPunk (it is $(basename "$ROOT"))"

# ---- host -------------------------------------------------------------------
os=$(uname -s); arch=$(uname -m)
case "$os/$arch" in
    Linux/x86_64)          CLI_PKG=Linux_64bit.tar.gz;  ET_PKG=linux-amd64.tar.gz
        CLI_SHA=28a8e119c498a25607821c36cb2dc49e8463941b261a0d99091baa7bc692dd2b
        ET_SHA=e9cc641f8e4a0b644b52836d7a6b59f3c6d3261213c5ccc41f8f3c3035d06aa4 ;;
    Linux/aarch64|Linux/arm64) CLI_PKG=Linux_ARM64.tar.gz; ET_PKG=linux-aarch64.tar.gz
        CLI_SHA=1e69e077479f300614d4551334e0a33f08ee40b04315d83b8e7e0e94f0d0ee62
        ET_SHA=dd2613cdc8e73d1200a3daff2025ff51daa5bbdb3a352fe35d6b7377891aecc8 ;;
    Darwin/x86_64)         CLI_PKG=macOS_64bit.tar.gz;  ET_PKG=macos-amd64.tar.gz
        CLI_SHA=c982e940027996bea9901050e95fae99c59c1dcfee54beedecaf28141e7bf2e7
        ET_SHA=f8ec4fcaf7d79845a0e8ad60b24be9f584d8fe03f341b5ad4ec0df0ec855e670 ;;
    Darwin/arm64)          CLI_PKG=macOS_ARM64.tar.gz;  ET_PKG=macos-arm64.tar.gz
        CLI_SHA=cb952e8c1621c95ef5f1d17831c945e3d0ec5973f89c557a7ec8feb9c4f7d4c9
        ET_SHA=f63f7203d88cfe4c17aea34d6cf82769458ce204e49a05816c6384c2d299e6ca ;;
    *) die "no prebuilt tools for $os/$arch" ;;
esac

sha256() {
    if command -v sha256sum >/dev/null 2>&1; then sha256sum "$1" | cut -d' ' -f1
    else shasum -a 256 "$1" | cut -d' ' -f1; fi
}

# fetch URL FILE SHA256: downloads once, checks the checksum every time.
fetch() {
    if [ ! -f "$2" ]; then
        echo "Downloading $1"
        if command -v curl >/dev/null 2>&1; then
            curl -fL --retry 3 -o "$2.part" "$1" || die "download failed: $1"
        else
            wget -O "$2.part" "$1" || die "download failed: $1"
        fi
        mv "$2.part" "$2"
    fi
    if [ "$(sha256 "$2")" != "$3" ]; then
        rm -f "$2"
        die "checksum mismatch for $(basename "$2") (removed; run again)"
    fi
}

mkdir -p "$TC/downloads"

# ---- arduino-cli ------------------------------------------------------------
CLI="$TC/arduino-cli-$CLI_VERSION/arduino-cli"
if [ ! -x "$CLI" ]; then
    f="$TC/downloads/arduino-cli_${CLI_VERSION}_$CLI_PKG"
    fetch "https://github.com/arduino/arduino-cli/releases/download/v$CLI_VERSION/arduino-cli_${CLI_VERSION}_$CLI_PKG" "$f" "$CLI_SHA"
    mkdir -p "$TC/arduino-cli-$CLI_VERSION"
    tar -xzf "$f" -C "$TC/arduino-cli-$CLI_VERSION"
fi

# ---- esptool (for the flash script next to the firmware) --------------------
ET_DIR="$TC/esptool-$ESPTOOL_VERSION"
if [ ! -x "$ET_DIR/esptool" ]; then
    f="$TC/downloads/esptool-v$ESPTOOL_VERSION-$ET_PKG"
    fetch "https://github.com/espressif/esptool/releases/download/v$ESPTOOL_VERSION/esptool-v$ESPTOOL_VERSION-$ET_PKG" "$f" "$ET_SHA"
    rm -rf "$ET_DIR.tmp"; mkdir -p "$ET_DIR.tmp"
    tar -xzf "$f" -C "$ET_DIR.tmp"
    rm -rf "$ET_DIR"; mv "$ET_DIR.tmp"/esptool-* "$ET_DIR"; rm -rf "$ET_DIR.tmp"
fi

# ---- arduino-cli configuration: every folder inside ./toolchain -------------
CFG="$TC/arduino-cli.yaml"
cat > "$CFG" <<EOF
# Written by build.sh: arduino-cli keeps everything inside the project.
directories:
  data: '$TC/data'
  downloads: '$TC/downloads'
  user: '$TC/user'
build_cache:
  path: '$TC/cache'
updater:
  enable_notification: false
EOF

# ---- the commit shown in About (src/config/build_commit.h) ------------------
if command -v git >/dev/null 2>&1 && [ -d .git ]; then
    sh .githooks/update-build-commit || true
fi

# ---- board and version ------------------------------------------------------
BOARD=$(sed -n 's/^[[:space:]]*#define[[:space:]]\{1,\}MW_BOARD_\([A-Za-z0-9_]*\).*/\1/p' board_config.h | head -n 1)
[ -n "$BOARD" ] || die "no board selected in board_config.h"
VERSION=$(sed -n 's/^#define[[:space:]]\{1,\}MW_FIRMWARE_VERSION[[:space:]]\{1,\}"\([^"]*\)".*/\1/p' src/config/app_config.h)
NAME="ColdPunk-$VERSION-$BOARD$SUFFIX"
echo "Building $NAME (profile $PROFILE)"

# ---- build ------------------------------------------------------------------
BUILD="$TC/build/$PROFILE"
"$CLI" --config-file "$CFG" compile --profile "$PROFILE" \
    --build-path "$BUILD" --warnings default "$ROOT"

# ---- the firmware folder ----------------------------------------------------
OUT="$ROOT/firmware/$NAME"
rm -rf "$OUT"; mkdir -p "$OUT"
cp "$BUILD/ColdPunk.ino.bootloader.bin" "$OUT/bootloader.bin"
cp "$BUILD/ColdPunk.ino.partitions.bin" "$OUT/partitions.bin"
cp "$BUILD/boot_app0.bin"               "$OUT/boot_app0.bin"
cp "$BUILD/ColdPunk.ino.bin"            "$OUT/coldpunk.bin"
cp "$ET_DIR/esptool"                    "$OUT/esptool"
cp "$ET_DIR/LICENSE"                    "$OUT/esptool-LICENSE.txt"
cp tools/flash/flash.sh tools/flash/flash.bat tools/flash/README.txt "$OUT/"
chmod +x "$OUT/flash.sh" "$OUT/esptool"
(
    cd "$OUT"
    for f in bootloader.bin partitions.bin boot_app0.bin coldpunk.bin; do
        echo "$(sha256 "$f")  $f"
    done > SHA256SUMS.txt
)

echo
echo "Done: firmware/$NAME"
echo "Flash: firmware/$NAME/flash.sh [port]   (wallets are kept)"
