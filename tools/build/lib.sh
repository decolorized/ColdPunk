# ColdPunk build helpers for Linux / macOS, sourced by build.sh,
# build-idf-bootloader.sh, build-secure.sh and make-keys.sh in the project
# folder. Everything is downloaded into toolchain/ there; nothing goes into
# the system or the home folder. Not meant to be run by itself.
#
# Pinned versions (with the SHA-256 of every archive this file downloads):
#   arduino-cli 1.5.1            the Arduino build (core and libraries: sketch.yaml)
#   esptool 5.3.1                esptool, espsecure, espefuse (standalone)
#   ESP-IDF 5.5.5                the version the Arduino core 3.3.11 is built from
#   Python 3.12.13               python-build-standalone 20260610, for ESP-IDF

CLI_VERSION=1.5.1
ESPTOOL_VERSION=5.3.1
IDF_VERSION=5.5.5
IDF_SHA=48fffe90304573ef366bda06e38c92fd65c6f3636d785ce103ff82e4647964c8
PY_RELEASE=20260610
PY_VERSION=3.12.13
# ESP-IDF 5.5.5 tools (tools/tools.json) the bootloader build needs.
IDF_GCC=esp-14.2.0_20260121
IDF_CMAKE=3.30.2
IDF_NINJA=1.12.1

die() { echo "$SCRIPT: $*" >&2; exit 1; }

# cp_init SCRIPT [release|debug|hid]: ROOT, TC, PROFILE, SUFFIX, host packages.
cp_init() {
    SCRIPT=$1
    ROOT=$(pwd)
    TC="$ROOT/toolchain"
    case "${2:-release}" in
        release) PROFILE=coldpunk;       SUFFIX="" ;;
        debug)   PROFILE=coldpunk-debug; SUFFIX="-debug" ;;
        hid)     PROFILE=coldpunk-hid;   SUFFIX="-hid" ;;
        *) die "unknown build '$2' (release, debug or hid)" ;;
    esac
    # arduino-cli wants the sketch folder named after the .ino file.
    [ "$(basename "$ROOT")" = "ColdPunk" ] ||
        die "the project folder must be named ColdPunk (it is $(basename "$ROOT"))"

    os=$(uname -s); arch=$(uname -m)
    case "$os/$arch" in
        Linux/x86_64)
            CLI_PKG=Linux_64bit.tar.gz;  CLI_SHA=28a8e119c498a25607821c36cb2dc49e8463941b261a0d99091baa7bc692dd2b
            ET_PKG=linux-amd64.tar.gz;   ET_SHA=e9cc641f8e4a0b644b52836d7a6b59f3c6d3261213c5ccc41f8f3c3035d06aa4
            PY_PKG=x86_64-unknown-linux-gnu; PY_SHA=c218f50baeb2c06a30c2f03db5986b2bad6ab7c8a52faad2d5a59bda0677b93a ;;
        Linux/aarch64|Linux/arm64)
            CLI_PKG=Linux_ARM64.tar.gz;  CLI_SHA=1e69e077479f300614d4551334e0a33f08ee40b04315d83b8e7e0e94f0d0ee62
            ET_PKG=linux-aarch64.tar.gz; ET_SHA=dd2613cdc8e73d1200a3daff2025ff51daa5bbdb3a352fe35d6b7377891aecc8
            PY_PKG=aarch64-unknown-linux-gnu; PY_SHA=bc74cf1bb517651868342b0619b21eaaf9f94a2022c9c61886dd980e16fb091b ;;
        Darwin/x86_64)
            CLI_PKG=macOS_64bit.tar.gz;  CLI_SHA=c982e940027996bea9901050e95fae99c59c1dcfee54beedecaf28141e7bf2e7
            ET_PKG=macos-amd64.tar.gz;   ET_SHA=f8ec4fcaf7d79845a0e8ad60b24be9f584d8fe03f341b5ad4ec0df0ec855e670
            PY_PKG=x86_64-apple-darwin; PY_SHA=ba02164e4db381af8c288c0bc1657584a835e9121a0fa2836b0f2e712ff8cdf5 ;;
        Darwin/arm64)
            CLI_PKG=macOS_ARM64.tar.gz;  CLI_SHA=cb952e8c1621c95ef5f1d17831c945e3d0ec5973f89c557a7ec8feb9c4f7d4c9
            ET_PKG=macos-arm64.tar.gz;   ET_SHA=f63f7203d88cfe4c17aea34d6cf82769458ce204e49a05816c6384c2d299e6ca
            PY_PKG=aarch64-apple-darwin; PY_SHA=e18ddd4c1e8f4a1d6c4590b37f423d76aec734447edc20ed08e93983d95f2132 ;;
        *) die "no prebuilt tools for $os/$arch" ;;
    esac
    mkdir -p "$TC/downloads"
}

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

# ---- esptool, espsecure, espefuse ---------------------------------------------
cp_esptool() {
    ET_DIR="$TC/esptool-$ESPTOOL_VERSION"
    if [ ! -x "$ET_DIR/esptool" ]; then
        f="$TC/downloads/esptool-v$ESPTOOL_VERSION-$ET_PKG"
        fetch "https://github.com/espressif/esptool/releases/download/v$ESPTOOL_VERSION/esptool-v$ESPTOOL_VERSION-$ET_PKG" "$f" "$ET_SHA"
        rm -rf "$ET_DIR.tmp"; mkdir -p "$ET_DIR.tmp"
        tar -xzf "$f" -C "$ET_DIR.tmp"
        rm -rf "$ET_DIR"; mv "$ET_DIR.tmp"/esptool-* "$ET_DIR"; rm -rf "$ET_DIR.tmp"
    fi
    ESPTOOL="$ET_DIR/esptool"; ESPSECURE="$ET_DIR/espsecure"; ESPEFUSE="$ET_DIR/espefuse"
}

# ---- arduino-cli and the Arduino build -----------------------------------------
cp_arduino_cli() {
    CLI="$TC/arduino-cli-$CLI_VERSION/arduino-cli"
    if [ ! -x "$CLI" ]; then
        f="$TC/downloads/arduino-cli_${CLI_VERSION}_$CLI_PKG"
        fetch "https://github.com/arduino/arduino-cli/releases/download/v$CLI_VERSION/arduino-cli_${CLI_VERSION}_$CLI_PKG" "$f" "$CLI_SHA"
        mkdir -p "$TC/arduino-cli-$CLI_VERSION"
        tar -xzf "$f" -C "$TC/arduino-cli-$CLI_VERSION"
    fi
    # Every folder arduino-cli uses lies inside toolchain/.
    CFG="$TC/arduino-cli.yaml"
    cat > "$CFG" <<EOF
# Written by the build scripts: arduino-cli keeps everything inside the project.
directories:
  data: '$TC/data'
  downloads: '$TC/downloads'
  user: '$TC/user'
build_cache:
  path: '$TC/cache'
updater:
  enable_notification: false
EOF
}

# The commit shown in About (src/config/build_commit.h).
cp_commit() {
    if command -v git >/dev/null 2>&1 && [ -d .git ]; then
        sh .githooks/update-build-commit || true
    fi
}

# BOARD (from board_config.h) and VERSION (MW_FIRMWARE_VERSION).
cp_board_version() {
    BOARD=$(sed -n 's/^[[:space:]]*#define[[:space:]]\{1,\}MW_BOARD_\([A-Za-z0-9_]*\).*/\1/p' board_config.h | head -n 1)
    [ -n "$BOARD" ] || die "no board selected in board_config.h"
    VERSION=$(sed -n 's/^#define[[:space:]]\{1,\}MW_FIRMWARE_VERSION[[:space:]]\{1,\}"\([^"]*\)".*/\1/p' src/config/app_config.h)
}

# Builds the sketch; BUILD: the folder with ColdPunk.ino.{bin,elf,...}.
cp_arduino_build() {
    BUILD="$TC/build/$PROFILE"
    "$CLI" --config-file "$CFG" compile --profile "$PROFILE" \
        --build-path "$BUILD" --warnings default "$ROOT"
}

# ---- ESP-IDF, only for its bootloader ------------------------------------------
# A portable Python, ESP-IDF 5.5.5 (the release archive, with submodules),
# its compiler, cmake and ninja, and its Python environment - about 3 GB
# downloaded on first use, 6 GB on disk.
cp_idf() {
    case "$TC" in *" "*) die "ESP-IDF does not work in a path with spaces: $TC" ;; esac
    PY_DIR="$TC/python-$PY_VERSION"
    PY="$PY_DIR/bin/python3"
    if [ ! -x "$PY" ]; then
        name="cpython-$PY_VERSION+$PY_RELEASE-$PY_PKG-install_only.tar.gz"
        f="$TC/downloads/$name"
        fetch "https://github.com/astral-sh/python-build-standalone/releases/download/$PY_RELEASE/cpython-$PY_VERSION+$PY_RELEASE-$PY_PKG-install_only.tar.gz" "$f" "$PY_SHA"
        rm -rf "$PY_DIR.tmp"; mkdir -p "$PY_DIR.tmp"
        tar -xzf "$f" -C "$PY_DIR.tmp"
        rm -rf "$PY_DIR"; mv "$PY_DIR.tmp/python" "$PY_DIR"; rm -rf "$PY_DIR.tmp"
    fi

    IDF_PATH="$TC/esp-idf-v$IDF_VERSION"
    if [ ! -f "$IDF_PATH/tools/idf.py" ]; then
        f="$TC/downloads/esp-idf-v$IDF_VERSION.zip"
        echo "ESP-IDF $IDF_VERSION is a 2 GB download (once)."
        fetch "https://github.com/espressif/esp-idf/releases/download/v$IDF_VERSION/esp-idf-v$IDF_VERSION.zip" "$f" "$IDF_SHA"
        rm -rf "$IDF_PATH.tmp"; mkdir -p "$IDF_PATH.tmp"
        echo "Unpacking ESP-IDF..."
        if command -v unzip >/dev/null 2>&1; then
            unzip -q "$f" -d "$IDF_PATH.tmp" || die "unpacking ESP-IDF failed"
        else
            "$PY" -c 'import sys, zipfile; zipfile.ZipFile(sys.argv[1]).extractall(sys.argv[2])' "$f" "$IDF_PATH.tmp" ||
                die "unpacking ESP-IDF failed"
        fi
        rm -rf "$IDF_PATH"; mv "$IDF_PATH.tmp/esp-idf-v$IDF_VERSION" "$IDF_PATH"; rm -rf "$IDF_PATH.tmp"
    fi

    IDF_TOOLS_PATH="$TC/idf-tools"
    export IDF_PATH IDF_TOOLS_PATH
    export PIP_CACHE_DIR="$TC/pip-cache"
    export IDF_COMPONENT_MANAGER=0 IDF_CCACHE_ENABLE=0
    export IDF_COMPONENT_CACHE_PATH="$TC/idf-component-cache"
    stamp="$IDF_TOOLS_PATH/.coldpunk-$IDF_VERSION-py$PY_VERSION"
    if [ ! -f "$stamp" ]; then
        "$PY" "$IDF_PATH/tools/idf_tools.py" --non-interactive install \
            "xtensa-esp-elf@$IDF_GCC" "cmake@$IDF_CMAKE" "ninja@$IDF_NINJA" ||
            die "installing the ESP-IDF tools failed"
        "$PY" "$IDF_PATH/tools/idf_tools.py" --non-interactive install-python-env ||
            die "installing the ESP-IDF Python environment failed"
        touch "$stamp"
    fi
    IDF_PYTHON_ENV_PATH=$(ls -d "$IDF_TOOLS_PATH"/python_env/idf5.5_py*_env 2>/dev/null | head -n 1)
    [ -n "$IDF_PYTHON_ENV_PATH" ] || die "no ESP-IDF Python environment in $IDF_TOOLS_PATH"
    export IDF_PYTHON_ENV_PATH
    VENV_PY="$IDF_PYTHON_ENV_PATH/bin/python"
    cmake_bin=$(dirname "$(find "$IDF_TOOLS_PATH/tools/cmake/$IDF_CMAKE" -type f -name cmake -perm -u+x | head -n 1)")
    IDF_PATHS="$IDF_TOOLS_PATH/tools/xtensa-esp-elf/$IDF_GCC/xtensa-esp-elf/bin:$cmake_bin:$IDF_TOOLS_PATH/tools/ninja/$IDF_NINJA"
}

# cp_idf_bootloader plain|secure: builds tools/bootloader with ESP-IDF;
# BL_BIN: the (unsigned) bootloader.bin.
cp_idf_bootloader() {
    cp_idf
    proj="$TC/bootloader/project"
    rm -rf "$proj"; mkdir -p "$TC/bootloader"; cp -R "$ROOT/tools/bootloader" "$proj"
    defaults="$proj/sdkconfig.defaults"
    [ "$1" = secure ] && defaults="$defaults;$proj/sdkconfig.secure"
    out="$TC/bootloader/$1"
    rm -rf "$out"
    echo "Building the ESP-IDF $IDF_VERSION bootloader ($1)"
    PATH="$IDF_PATHS:$IDF_PYTHON_ENV_PATH/bin:$PATH" \
        "$VENV_PY" "$IDF_PATH/tools/idf.py" -C "$proj" -B "$out" \
        -D "SDKCONFIG=$out/sdkconfig" -D "SDKCONFIG_DEFAULTS=$defaults" bootloader ||
        die "the bootloader build failed"
    BL_BIN="$out/bootloader/bootloader.bin"
    [ -f "$BL_BIN" ] || die "no bootloader.bin after the build"
}

# ---- keys -----------------------------------------------------------------------
cp_keys_dir() {
    KEYS="${COLDPUNK_KEYS:-$ROOT/keys}"
    SB_KEY="$KEYS/secure_boot_signing_key.pem"
    FE_KEY="$KEYS/flash_encryption_key.bin"
}

# ---- the firmware folder --------------------------------------------------------
# cp_out NAME: a fresh firmware/NAME (OUT).
cp_out() {
    OUT="$ROOT/firmware/$1"
    rm -rf "$OUT"; mkdir -p "$OUT"
}

# cp_sums DIR FILE...: SHA256SUMS.txt in DIR for the files (paths relative to DIR).
cp_sums() {
    d=$1; shift
    (
        cd "$d"
        for f in "$@"; do echo "$(sha256 "$f")  $f"; done > SHA256SUMS.txt
    )
}
