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
echo "== fp-status"; ./fp-status && echo "SMOKE ok fp-status"
echo "== kemu-sec"; ./kemu-sec > /tmp/sec.log 2>&1; grep -E "^(PASS|FAIL)" /tmp/sec.log; tail -1 /tmp/sec.log
grep -q "KEMU-SEC ALL PASSED" /tmp/sec.log && echo "SMOKE ok kemu-sec"
echo "== divrace"; ./divrace > /tmp/div.log 2>&1; grep -E "^FAIL" /tmp/div.log; tail -1 /tmp/div.log
grep -q "DIVRACE ALL PASSED" /tmp/div.log && echo "SMOKE ok divrace"
echo "== intbench"; ../bench/intbench.arm64 && echo "SMOKE ok intbench"
echo "== sysctl";
if [ -f /proc/sys/kernel/kemu/enabled ]; then
  echo 0 > /proc/sys/kernel/kemu/enabled
  if ./hello-static >/dev/null 2>&1; then echo "sysctl-disable did not take effect";
  else echo "SMOKE ok sysctl"; fi
  echo 1 > /proc/sys/kernel/kemu/enabled
  ./hello-static >/dev/null 2>&1 && echo "sysctl re-enabled ok"
else echo "no kemu sysctl"; fi
' 2>&1 | grep -vE '^\[ |iPXE|SeaBIOS|Press|Booting|^.\[\?7l' | tee "$log"
want="hello abi tbi vector-state syscall-state fp-status kemu-sec divrace mtstress intbench sysctl"
rc=0
for t in $want; do
	grep -q "SMOKE ok $t" "$log" || { echo "FAILED: $t"; rc=1; }
done
[ $rc = 0 ] && echo "vm-smoke: all passed"
exit $rc
