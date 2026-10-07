#!/bin/sh
# Arduino IDE compiles the sketch folder plus its src/ subtree. The repository
# keeps the sources at the root, and MoneroColdWallet/src is a symlink to them.
#
# Some Arduino IDE builds (notably on Windows) do not follow that symlink.
# Run this script there to replace the symlink with a real copy before
# building, and re-run it after every edit to src/.
set -e
here=$(cd "$(dirname "$0")/.." && pwd)
sketch="$here/MoneroColdWallet"
if [ -L "$sketch/src" ]; then
    rm "$sketch/src"
fi
mkdir -p "$sketch/src"
cp -a "$here/src/." "$sketch/src/"
echo "copied $here/src -> $sketch/src"
echo "NOTE: MoneroColdWallet/src is now a copy, not a symlink."
echo "      Edit the originals under src/ and re-run this script."
