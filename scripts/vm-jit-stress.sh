#!/bin/bash
# Boot the kemu kernel with an arm64 rootfs that has the guest JIT runtimes
# (scripts/mkrootfs.sh full) and run tests/jit-workloads: several rounds,
# then several copies at once. Exits non-zero unless everything passes.
#   KEMU_DISK=build/arm64-jit.img scripts/vm-jit-stress.sh [rounds] [copies]
set -euo pipefail
here=$(cd "$(dirname "$0")/.." && pwd)
rounds=${1:-2}
copies=${2:-2}
: "${KEMU_DISK:=$here/build/arm64-jit.img}"
export KEMU_DISK
log=$(mktemp)
trap 'rm -f "$log"' EXIT
KEMU_TIMEOUT=${KEMU_TIMEOUT:-2400} KEMU_MEM=${KEMU_MEM:-6144} "$here/scripts/run-vm.sh" "
. scripts/chroot-run.sh
w=/mnt/kemu/tests/jit-workloads/run.sh
echo '== sequential'
chroot /r /bin/bash \$w 1 $rounds > /tmp/seq.log 2>&1
cat /tmp/seq.log
echo '== concurrent'
pids=
for i in \$(seq $copies); do chroot /r /bin/bash \$w 1 1 > /tmp/par\$i.log 2>&1 & pids=\"\$pids \$!\"; done
wait \$pids
for i in \$(seq $copies); do echo \"-- copy \$i\"; cat /tmp/par\$i.log; done
dmesg | grep -E 'kemu.*cannot recover|BUG|WARNING|Oops' | head
" 2>&1 | grep -vE '^\[ |iPXE|SeaBIOS|Press|Booting' | sed 's/\x1b\[[0-9;?]*[a-zA-Z]//g; s/\x1bc//g' | tee "$log"
want=$((1 + copies))
got=$(grep -c "^jit-workloads: 0 failures" "$log" || true)
if grep -qE "cannot recover|BUG|WARNING|Oops" "$log"; then
	echo "vm-jit-stress: kernel reported problems"
	exit 1
fi
if [ "$got" != "$want" ]; then
	echo "vm-jit-stress: $got of $want runs passed"
	exit 1
fi
echo "vm-jit-stress: all passed"
