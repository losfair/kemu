#!/bin/bash
# Apply kemu to a pristine Linux v6.18 tree: copy overlay/ and apply patches/.
# usage: apply.sh <linux-6.18-dir>
set -euo pipefail
here=$(cd "$(dirname "$0")/.." && pwd)
linux=${1:?usage: apply.sh <linux-dir>}
for p in "$here"/patches/*.patch; do
	patch -d "$linux" -p1 --forward --quiet < "$p"
done
rsync -a "$here/overlay/" "$linux/" --exclude target/ --exclude Cargo.lock
echo "kemu applied to $linux; enable CONFIG_KEMU (requires CONFIG_RUST)."
