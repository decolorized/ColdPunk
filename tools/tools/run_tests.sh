#!/bin/sh
# Builds and runs the whole host test suite, first normally and then under
# AddressSanitizer + UBSan. This is what CI should run.
set -e
root=$(cd "$(dirname "$0")/.." && pwd)

echo "=== host tests (O2) ==="
make -C "$root/test" clean
make -C "$root/test" run

echo
echo "=== host tests (asan + ubsan) ==="
make -C "$root/test" clean
make -C "$root/test" ASAN=1 run

echo
echo "=== host HAL stub compiles ==="
gcc -std=c11 -Wall -Wextra -c -I"$root/src" -DMW_HOST_BUILD=1 \
    "$root/src/hal/hal_host.c" -o /tmp/mw_hal_host.o
echo "ok"

make -C "$root/test" clean
echo
echo "ALL CHECKS PASSED"
