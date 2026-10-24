#!/bin/sh
# Differential-test the kemu interpreter against qemu-aarch64 across all classes.
set -e
cd "$(dirname "$0")"
cargo +1.88.0 build --release
exec ./target/release/difftest "$@"
