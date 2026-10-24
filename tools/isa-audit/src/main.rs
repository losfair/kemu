// SPDX-License-Identifier: GPL-2.0
//! Print `decode(w)` for every hex word on stdin (one per line), as
//! `<word>\t<Debug of Insn>`. Used by audit.py to compare the decoder with
//! the Arm A64 ISA XML.
use std::io::{BufRead, Write};

fn main() {
    let stdin = std::io::stdin();
    let stdout = std::io::stdout();
    let mut out = std::io::BufWriter::new(stdout.lock());
    for line in stdin.lock().lines() {
        let line = match line {
            Ok(l) => l,
            Err(_) => break,
        };
        let t = line.trim().trim_start_matches("0x");
        if t.is_empty() {
            continue;
        }
        if let Ok(w) = u32::from_str_radix(t, 16) {
            let _ = writeln!(out, "{:08x}\t{:?}", w, kemu_core::decode::decode(w));
        }
    }
}
