#!/bin/bash
# Build a Debian arm64 rootfs image for testing kemu with real programs.
#   mkrootfs.sh stage1   debootstrap --foreign on the host (no emulation)
#   mkrootfs.sh stage2   run debootstrap's second stage under kemu in the VM
#   mkrootfs.sh full [out.img]
#                        whole rootfs plus the guest JIT runtimes for
#                        tests/jit-workloads, built on the host with
#                        qemu-user binfmt (no kemu involved; used by CI)
# Stage 1 is kept as build/arm64-stage1.img so stage 2 can be retried.
set -euo pipefail
here=$(cd "$(dirname "$0")/.." && pwd)
b=$here/build
pkgs=bash,coreutils,python3,busybox,gcc,libc6-dev,make,file,procps,strace,xz-utils,findutils,grep,sed,gawk,diffutils,perl,git
jitpkgs=openjdk-21-jdk-headless,nodejs,luajit,pypy3,ruby
case "${1:-}" in
full)
	out=${2:-$b/arm64-jit.img}
	[ -e /proc/sys/fs/binfmt_misc/qemu-aarch64 ] || { echo "needs qemu-user binfmt for aarch64 (qemu-user-static)" >&2; exit 1; }
	root=$b/rootfs-full
	sudo rm -rf "$root"
	mkdir -p "$b"
	script=/usr/share/debootstrap/scripts/trixie
	[ -e "$script" ] || script=/usr/share/debootstrap/scripts/sid
	sudo debootstrap --arch=arm64 --variant=minbase --include=$pkgs,$jitpkgs \
		--keyring=/usr/share/keyrings/debian-archive-keyring.gpg \
		trixie "$root" http://deb.debian.org/debian "$script" > "$b/debootstrap-full.log" 2>&1 ||
		{ tail -20 "$b/debootstrap-full.log"; exit 1; }
	sudo rm -rf "$root"/var/cache/apt/archives/*.deb "$root"/var/lib/apt/lists/*
	mb=$(( $(sudo du -sm "$root" | cut -f1) * 13 / 10 + 512 ))
	rm -f "$out"
	truncate -s ${mb}M "$out"
	sudo mkfs.ext4 -q -F -d "$root" "$out"
	sudo rm -rf "$root"
	echo "$out: ${mb} MiB"
	;;
stage1)
	command -v debootstrap >/dev/null || sudo DEBIAN_FRONTEND=noninteractive apt-get install -y debootstrap
	mkdir -p "$b/mnt"
	rm -f "$b/arm64-stage1.img"
	truncate -s 6G "$b/arm64-stage1.img"
	mkfs.ext4 -q -F "$b/arm64-stage1.img"
	sudo mount -o loop "$b/arm64-stage1.img" "$b/mnt"
	trap 'sudo umount "$b/mnt"' EXIT
	sudo debootstrap --arch=arm64 --foreign --variant=minbase --include=$pkgs \
		trixie "$b/mnt" http://deb.debian.org/debian > "$b/debootstrap.log" 2>&1
	tail -1 "$b/debootstrap.log"
	;;
stage2)
	cp --sparse=always "$b/arm64-stage1.img" "$b/arm64.img"
	KEMU_DISK=$b/arm64.img KEMU_TIMEOUT=${KEMU_TIMEOUT:-3500} KEMU_MEM=4096 "$here/scripts/run-vm.sh" \
		'. scripts/chroot-run.sh; chroot /r /debootstrap/debootstrap --second-stage > /tmp/ds2.log 2>&1; echo "ds2 exit=$?"; tail -15 /tmp/ds2.log; sync' 2>&1 |
		grep -vE '^\[ |iPXE|SeaBIOS|Press|Booting' | tail -20
	;;
*)
	echo "usage: $0 stage1|stage2" >&2
	exit 1
	;;
esac
