// SPDX-License-Identifier: GPL-2.0
//! The x86-64 JIT: encoder, register map, stubs, tier-1 translator and the
//! metadata used to recover precise guest state.

pub mod meta;
pub mod regmap;
pub mod stubs;
pub mod t1;
pub mod x86;
pub mod xcache;
