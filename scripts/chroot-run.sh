# Sourced inside the VM: mount the arm64 rootfs (virtio disk) at /r and
# run "$@" chrooted (as a login-ish shell).
mkdir -p /r && mount /dev/vda /r
mount -t proc proc /r/proc; mount -t sysfs sys /r/sys; mount --bind /dev /r/dev; mount -t tmpfs tmp /r/tmp
mkdir -p /r/mnt/kemu && mount --bind /mnt /r/mnt/kemu
