#!/bin/bash
# Sync the kemu overlay into the Linux tree and build bzImage.
# usage: build.sh [make args...]
set -euo pipefail
here=$(cd "$(dirname "$0")/.." && pwd)
linux=${LINUX:-$HOME/src/linux-6.18}
rsync -a --checksum "$here/overlay/" "$linux/" \
  --exclude 'target/' --exclude 'Cargo.lock' --exclude '*.o'
cd "$linux"
grep -q '^CONFIG_KEMU=y' .config || { ./scripts/config -e KEMU; make LLVM=1 olddefconfig >/dev/null; }
make LLVM=1 -j"$(nproc)" "${@:-bzImage}"
