#!/bin/bash
# Boot the kemu kernel in QEMU/KVM. Usage: run-vm.sh [command-run-in-/mnt]
# The kemu repo is shared at /mnt (9p), the aarch64 sysroot at /sysroot.
set -euo pipefail
here=$(cd "$(dirname "$0")/.." && pwd)
kernel=${KERNEL:-$HOME/src/linux-6.18/arch/x86/boot/bzImage}
initrd=$here/build/initramfs.cpio.gz
[ -f "$initrd" ] || "$here/scripts/mkinitramfs.sh" "$initrd" >/dev/null
append="console=ttyS0 panic=-1 oops=panic quiet loglevel=4 ${KEMU_APPEND:-}"
if [ $# -gt 0 ]; then printf '%s\n' "$*" > "$here/build/vmcmd.sh"; append="$append kemu_test=1"; fi
exec timeout ${KEMU_TIMEOUT:-300} qemu-system-x86_64 -enable-kvm -cpu host -smp ${KEMU_SMP:-4} -m ${KEMU_MEM:-2048} \
  -kernel "$kernel" -initrd "$initrd" -append "$append" \
  -nographic -no-reboot \
  -fsdev local,id=fs0,path="$here",security_model=none -device virtio-9p-pci,fsdev=fs0,mount_tag=kemu \
  -fsdev local,id=fs1,path=/usr/aarch64-linux-gnu,security_model=none,readonly=on -device virtio-9p-pci,fsdev=fs1,mount_tag=sysroot
