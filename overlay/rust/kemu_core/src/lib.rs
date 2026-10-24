// SPDX-License-Identifier: GPL-2.0
//! kemu translator core.
//!
//! This crate is built twice from the same sources: by cargo for userspace
//! tests and fuzzing, and by kbuild as part of `kernel/kemu/kemu_rs.rs`
//! (which mounts these files as a module tree via `#[path]`). It therefore
//! must stay `no_std`, must not use `alloc`, floating point or 128-bit
//! division, and must not panic on any guest input.
#![no_std]
#![forbid(unsafe_code)]
#![allow(dead_code)]

#[cfg(feature = "std")]
extern crate std;

pub mod state;
pub mod env;
pub mod decode;
pub mod sysregs;
pub mod softfloat;
pub mod interp;
pub mod sigframe;
pub mod jit;
