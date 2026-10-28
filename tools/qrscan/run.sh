#!/bin/sh
# Host check of the camera QR decoder (src/transfer/camera_scan.cpp):
# generates test frames, compiles the decoder natively and decodes them all.
#   sh tools/qrscan/run.sh        (needs g++, python3, segno, pillow)
set -e
HERE=$(cd "$(dirname "$0")" && pwd)
SRC="$HERE/../../src"
OUT="${TMPDIR:-/tmp}/coldpunk-qrscan"
rm -rf "$OUT"; mkdir -p "$OUT/img"
python3 "$HERE/gen.py" "$OUT/img" > /dev/null
g++ -O2 -DMW_HOST_BUILD -DMW_QR_SCAN_ON_HOST -I"$SRC" -I"$SRC/hal" \
    -o "$OUT/harness" "$HERE/harness.cpp" "$SRC/transfer/camera_scan.cpp" \
    -x c "$SRC/transfer/qr_encode.c"
"$OUT/harness" $(ls "$OUT"/img/*.pgm | sed 's/\.pgm$//')
