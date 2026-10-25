#!/bin/bash
# Boot the kemu kernel and run the AArch64 test programs under it.
# Exits non-zero unless every check passes. Used by CI.
# KEMU_APPEND adds kernel parameters, e.g. KEMU_APPEND=kemu.jitoff=1.
set -euo pipefail
here=$(cd "$(dirname "$0")/.." && pwd)
log=$(mktemp)
trap 'rm -f "$log"' EXIT
KEMU_TIMEOUT=${KEMU_TIMEOUT:-600} "$here/scripts/run-vm.sh" '
cd /mnt/tests/kernel
echo "== hello"; ./hello-static; a=$?; ./hello-dyn; b=$?; [ $a = 42 ] && [ $b = 42 ] && echo "SMOKE ok hello"
echo "== abi"; ./abi > /tmp/abi.log 2>&1; grep FAIL /tmp/abi.log; tail -1 /tmp/abi.log
grep -q "ALL PASSED" /tmp/abi.log && echo "SMOKE ok abi"
echo "== mtstress"; ./mtstress | tail -3 | tee /tmp/mt.log; grep -q "mtstress: ok" /tmp/mt.log && echo "SMOKE ok mtstress"
echo "== tbi"; ./tbi > /tmp/tbi.log 2>&1; grep FAIL /tmp/tbi.log; tail -1 /tmp/tbi.log
grep -q "TBI ALL PASSED" /tmp/tbi.log && echo "SMOKE ok tbi"
echo "== vector-state"; ./vector-state && echo "SMOKE ok vector-state"
echo "== syscall-state"; ./syscall-state && echo "SMOKE ok syscall-state"
echo "== intbench"; ../bench/intbench.arm64 && echo "SMOKE ok intbench"
' 2>&1 | grep -vE '^\[ |iPXE|SeaBIOS|Press|Booting|^.\[\?7l' | tee "$log"
want="hello abi tbi vector-state syscall-state mtstress intbench"
rc=0
for t in $want; do
	grep -q "SMOKE ok $t" "$log" || { echo "FAILED: $t"; rc=1; }
done
[ $rc = 0 ] && echo "vm-smoke: all passed"
exit $rc
