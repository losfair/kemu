# SPDX-License-Identifier: GPL-2.0
obj-y += core.o syscall.o jit.o abi.o signal.o ptrace.o proc.o env.o binfmt_kemu.o kemu_rs.o xcache.o

# A panic from the Rust core would be a kernel BUG(); keep its arithmetic from
# trapping under CONFIG_RUST_OVERFLOW_CHECKS=y (the translator uses explicit
# wrapping where it relies on two's-complement) (audit H-03).
RUSTFLAGS_kemu_rs.o += -Coverflow-checks=no
