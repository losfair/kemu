#!/bin/bash
# Build a minimal x86_64 initramfs: static busybox + /init that mounts the
# host test directory over 9p (tag "kemu") at /mnt and runs /mnt/$KEMU_TEST
# (or drops to a shell).
set -euo pipefail
out=${1:-$(dirname "$0")/../build/initramfs.cpio.gz}
work=$(mktemp -d)
trap 'rm -rf "$work"' EXIT
mkdir -p "$work"/{bin,sbin,proc,sys,dev,tmp,mnt,etc,lib,lib64,usr/lib}
cp /bin/busybox "$work/bin/busybox"
for a in $("$work/bin/busybox" --list); do [ "$a" = busybox ] || ln -sf busybox "$work/bin/$a"; done
cat > "$work/init" <<'INIT'
#!/bin/sh
mount -t proc proc /proc
mount -t sysfs sys /sys
mount -t devtmpfs dev /dev 2>/dev/null
mount -t tmpfs tmp /tmp
mount -t 9p -o trans=virtio,version=9p2000.L,msize=262144 kemu /mnt
# aarch64 sysroot for dynamic binaries (exported by run-vm.sh as tag "sysroot")
mkdir -p /sysroot && mount -t 9p -o trans=virtio,version=9p2000.L,msize=262144,ro sysroot /sysroot 2>/dev/null && {
  ln -sf /sysroot/lib/ld-linux-aarch64.so.1 /lib/ld-linux-aarch64.so.1
  mkdir -p /lib/aarch64-linux-gnu && mount --bind /sysroot/lib /lib/aarch64-linux-gnu
}
if grep -q kemu_test=1 /proc/cmdline; then
  cd /mnt
  sh /mnt/build/vmcmd.sh
  echo "=== kemu test exit: $?"
  poweroff -f
fi
exec setsid cttyhack sh
INIT
chmod +x "$work/init"
mkdir -p "$(dirname "$out")"
(cd "$work" && find . | cpio -o -H newc --quiet | gzip -1) > "$out"
echo "$out"
