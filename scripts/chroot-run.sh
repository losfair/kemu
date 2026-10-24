# Sourced inside the VM: mount the arm64 rootfs (virtio disk) at /r and
# run "$@" chrooted (as a login-ish shell).
# Use absolute paths after "chroot /r": the static busybox chroot prefers its
# own applets, so "chroot /r sh" would run busybox's x86 ash, not /r/bin/sh.
mkdir -p /r && mount /dev/vda /r
mount -t proc proc /r/proc; mount -t sysfs sys /r/sys; mount --bind /dev /r/dev; mount -t tmpfs tmp /r/tmp
mkdir -p /r/mnt/kemu && mount --bind /mnt /r/mnt/kemu
