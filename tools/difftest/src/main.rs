// SPDX-License-Identifier: GPL-2.0
//! Differential tester: compares the kemu interpreter against QEMU (the
//! oracle) on randomly generated AArch64 instructions.
//!
//! For each test it builds an initial architectural state and an instruction
//! encoding, runs the instruction (a) in the interpreter via `kemu_core`, and
//! (b) natively under `qemu-aarch64` by assembling a tiny program that loads
//! the state, executes the instruction, and dumps the resulting state. The
//! final X/SP/NZCV/FPSR/V state must match bit-for-bit.
//!
//! Instructions are batched (many per assembled program) to amortize the
//! assembler + QEMU startup cost.

use kemu_core::env::{Access, Env, Fault};
use kemu_core::interp::{self, Exit};
use kemu_core::state::CpuState;
use std::process::Command;

mod gen;

/// One test's architectural state (inputs = outputs layout).
#[derive(Clone)]
pub struct Arch {
    pub x: [u64; 31], // x0..x30 (x30 reserved by the harness, not compared)
    pub sp: u64,
    pub nzcv: u64,
    pub fpcr: u32,
    pub fpsr: u32,
    pub v: [[u64; 2]; 32],
}

impl Arch {
    fn zeroed() -> Self {
        Arch { x: [0; 31], sp: 0, nzcv: 0, fpcr: 0, fpsr: 0, v: [[0; 2]; 32] }
    }
}

/// Flat scratch memory for interpreter memory ops (not used by the
/// register-only classes but present so loads/stores don't panic).
struct Mem {
    base: u64,
    data: Vec<u8>,
}
impl Mem {
    fn off(&self, a: u64) -> Option<usize> {
        a.checked_sub(self.base).map(|x| x as usize).filter(|i| *i + 16 <= self.data.len())
    }
}
impl Env for Mem {
    fn fetch(&mut self, _pc: u64) -> Result<u32, Fault> {
        Ok(0)
    }
    fn read_u8(&mut self, a: u64) -> Result<u8, Fault> {
        self.off(a).map(|i| self.data[i]).ok_or(fault(a, Access::Read))
    }
    fn read_u16(&mut self, a: u64) -> Result<u16, Fault> {
        let i = self.off(a).ok_or(fault(a, Access::Read))?;
        Ok(u16::from_le_bytes(self.data[i..i + 2].try_into().unwrap()))
    }
    fn read_u32(&mut self, a: u64) -> Result<u32, Fault> {
        let i = self.off(a).ok_or(fault(a, Access::Read))?;
        Ok(u32::from_le_bytes(self.data[i..i + 4].try_into().unwrap()))
    }
    fn read_u64(&mut self, a: u64) -> Result<u64, Fault> {
        let i = self.off(a).ok_or(fault(a, Access::Read))?;
        Ok(u64::from_le_bytes(self.data[i..i + 8].try_into().unwrap()))
    }
    fn write_u8(&mut self, a: u64, v: u8) -> Result<(), Fault> {
        let i = self.off(a).ok_or(fault(a, Access::Write))?;
        self.data[i] = v;
        Ok(())
    }
    fn write_u16(&mut self, a: u64, v: u16) -> Result<(), Fault> {
        let i = self.off(a).ok_or(fault(a, Access::Write))?;
        self.data[i..i + 2].copy_from_slice(&v.to_le_bytes());
        Ok(())
    }
    fn write_u32(&mut self, a: u64, v: u32) -> Result<(), Fault> {
        let i = self.off(a).ok_or(fault(a, Access::Write))?;
        self.data[i..i + 4].copy_from_slice(&v.to_le_bytes());
        Ok(())
    }
    fn write_u64(&mut self, a: u64, v: u64) -> Result<(), Fault> {
        let i = self.off(a).ok_or(fault(a, Access::Write))?;
        self.data[i..i + 8].copy_from_slice(&v.to_le_bytes());
        Ok(())
    }
    fn cmpxchg(&mut self, _a: u64, _s: u32, _e: [u64; 2], _n: [u64; 2]) -> Result<[u64; 2], Fault> {
        Ok([0, 0])
    }
    fn cntvct(&mut self) -> u64 {
        0
    }
    fn cntfrq(&mut self) -> u64 {
        1_000_000_000
    }
    fn random(&mut self) -> Option<u64> {
        Some(0)
    }
}
fn fault(a: u64, acc: Access) -> Fault {
    Fault { addr: a, access: acc, align: false }
}

/// Run one instruction in the interpreter. Returns the output state, or None
/// if the interpreter raised an undefined/fault exit (we then expect QEMU to
/// trap too, handled by the caller).
fn run_interp(a: &Arch, word: u32) -> (Arch, Option<Exit>) {
    let mut cpu = CpuState::new();
    cpu.x = a.x;
    cpu.sp = a.sp;
    cpu.pc = 0x1000;
    cpu.nzcv = a.nzcv;
    cpu.fpcr = a.fpcr & kemu_core::softfloat::FPCR_MASK;
    cpu.fpsr = a.fpsr & kemu_core::softfloat::FPSR_MASK;
    cpu.v = a.v;
    let mut mem = Mem { base: SCRATCH, data: vec![0u8; 4096] };
    // Single instruction: use a fetch env that returns `word` once.
    struct One {
        word: u32,
        mem: Mem,
    }
    impl Env for One {
        fn fetch(&mut self, _pc: u64) -> Result<u32, Fault> {
            Ok(self.word)
        }
        fn read_u8(&mut self, a: u64) -> Result<u8, Fault> {
            self.mem.read_u8(a)
        }
        fn read_u16(&mut self, a: u64) -> Result<u16, Fault> {
            self.mem.read_u16(a)
        }
        fn read_u32(&mut self, a: u64) -> Result<u32, Fault> {
            self.mem.read_u32(a)
        }
        fn read_u64(&mut self, a: u64) -> Result<u64, Fault> {
            self.mem.read_u64(a)
        }
        fn write_u8(&mut self, a: u64, v: u8) -> Result<(), Fault> {
            self.mem.write_u8(a, v)
        }
        fn write_u16(&mut self, a: u64, v: u16) -> Result<(), Fault> {
            self.mem.write_u16(a, v)
        }
        fn write_u32(&mut self, a: u64, v: u32) -> Result<(), Fault> {
            self.mem.write_u32(a, v)
        }
        fn write_u64(&mut self, a: u64, v: u64) -> Result<(), Fault> {
            self.mem.write_u64(a, v)
        }
        fn cmpxchg(&mut self, a: u64, s: u32, e: [u64; 2], n: [u64; 2]) -> Result<[u64; 2], Fault> {
            self.mem.cmpxchg(a, s, e, n)
        }
        fn cntvct(&mut self) -> u64 {
            0
        }
        fn cntfrq(&mut self) -> u64 {
            1_000_000_000
        }
        fn random(&mut self) -> Option<u64> {
            Some(0)
        }
    }
    let _ = &mut mem;
    let mut env = One { word, mem: Mem { base: SCRATCH, data: vec![0u8; 4096] } };
    let (exit, _n) = interp::run(&mut cpu, &mut env, 1);
    let out = Arch {
        x: cpu.x,
        sp: cpu.sp,
        nzcv: cpu.nzcv,
        fpcr: cpu.fpcr,
        fpsr: cpu.fpsr,
        v: cpu.v,
    };
    let abn = match exit {
        Exit::Undefined(_) | Exit::Fault(_) | Exit::Brk(_) => Some(exit),
        _ => None,
    };
    (out, abn)
}

const SCRATCH: u64 = 0x4000_0000;

fn main() {
    let args: Vec<String> = std::env::args().collect();
    let mut count = 2000usize;
    let mut batch = 400usize;
    let mut seed = 0xdead_beefu64;
    let mut classes: Vec<String> = Vec::new();
    let mut i = 1;
    while i < args.len() {
        match args[i].as_str() {
            "-n" => {
                count = args[i + 1].parse().unwrap();
                i += 1;
            }
            "-b" => {
                batch = args[i + 1].parse().unwrap();
                i += 1;
            }
            "-s" => {
                seed = args[i + 1].parse().unwrap();
                i += 1;
            }
            "-c" => {
                classes.push(args[i + 1].clone());
                i += 1;
            }
            _ => {}
        }
        i += 1;
    }
    let all = gen::CLASSES.iter().map(|c| c.name.to_string()).collect::<Vec<_>>();
    if classes.is_empty() {
        classes = all;
    }

    let mut rng = Rng(seed);
    let mut total = 0usize;
    let mut mism = 0usize;
    let mut per_class: Vec<(String, usize, usize)> = Vec::new();

    for cname in &classes {
        let class = match gen::CLASSES.iter().find(|c| c.name == cname) {
            Some(c) => c,
            None => {
                eprintln!("unknown class {cname}");
                continue;
            }
        };
        let mut cls_total = 0;
        let mut cls_mism = 0;
        let mut done = 0;
        while done < count {
            let this = batch.min(count - done);
            let mut cases = Vec::with_capacity(this);
            for _ in 0..this {
                let a = gen::random_state(&mut rng);
                let w = (class.gen)(&mut rng);
                cases.push((a, w));
            }
            let qemu_out = eval_cases(&cases);
            for (idx, (a, w)) in cases.iter().enumerate() {
                let (iout, abn) = run_interp(a, *w);
                let q = &qemu_out[idx];
                cls_total += 1;
                total += 1;
                match q {
                    QResult::State(qa) => {
                        if abn.is_some() {
                            report_mismatch(cname, *w, a, Some(qa), &iout, "interp trapped, qemu ran");
                            cls_mism += 1;
                            mism += 1;
                        } else if let Some(diff) = compare(qa, &iout) {
                            report_mismatch(cname, *w, a, Some(qa), &iout, &diff);
                            cls_mism += 1;
                            mism += 1;
                        }
                    }
                    QResult::Trap(sig) => {
                        if abn.is_none() {
                            report_mismatch(cname, *w, a, None, &iout, &format!("qemu trapped sig {sig}, interp ran"));
                            cls_mism += 1;
                            mism += 1;
                        }
                    }
                }
            }
            done += this;
        }
        per_class.push((cname.clone(), cls_total, cls_mism));
    }

    println!("\n=== difftest summary (seed {seed}) ===");
    for (c, t, m) in &per_class {
        println!("  {:<16} {:>8} cases  {:>6} mismatches", c, t, m);
    }
    println!("  {:<16} {:>8} cases  {:>6} mismatches", "TOTAL", total, mism);
    if mism > 0 {
        std::process::exit(1);
    }
}

fn compare(q: &Arch, i: &Arch) -> Option<String> {
    for r in 2..31 {
        if q.x[r] != i.x[r] {
            return Some(format!("x{r}: qemu={:#018x} interp={:#018x}", q.x[r], i.x[r]));
        }
    }
    if q.sp != i.sp {
        return Some(format!("sp: qemu={:#018x} interp={:#018x}", q.sp, i.sp));
    }
    if q.nzcv & 0xf000_0000 != i.nzcv & 0xf000_0000 {
        return Some(format!("nzcv: qemu={:#x} interp={:#x}", q.nzcv, i.nzcv));
    }
    if q.fpsr & 0x9f != i.fpsr & 0x9f {
        return Some(format!("fpsr: qemu={:#x} interp={:#x}", q.fpsr & 0x9f, i.fpsr & 0x9f));
    }
    for r in 0..32 {
        if q.v[r] != i.v[r] {
            return Some(format!(
                "v{r}: qemu={:#018x}:{:#018x} interp={:#018x}:{:#018x}",
                q.v[r][1], q.v[r][0], i.v[r][1], i.v[r][0]
            ));
        }
    }
    None
}

use std::sync::atomic::{AtomicUsize, Ordering};
static SHOWN: AtomicUsize = AtomicUsize::new(0);
fn report_mismatch(class: &str, w: u32, inp: &Arch, q: Option<&Arch>, i: &Arch, diff: &str) {
    if SHOWN.fetch_add(1, Ordering::SeqCst) < 40 {
        eprintln!("MISMATCH [{class}] insn={:#010x}: {diff}", w);
        let _ = (inp, q, i);
    }
}

enum QResult {
    State(Arch),
    Trap(i32),
}

/// Evaluate cases under qemu with per-case fault isolation: records that
/// dumped are states; the first case that failed to dump is a trap; remaining
/// cases are retried recursively.
fn eval_cases(cases: &[(Arch, u32)]) -> Vec<QResult> {
    let (stdout, sig) = match run_qemu_raw(cases) {
        Ok(v) => v,
        Err(e) => {
            eprintln!("qemu invocation failed: {e}");
            std::process::exit(1);
        }
    };
    let full = stdout.len() / REC_BYTES;
    let mut out = Vec::with_capacity(cases.len());
    // Parse the complete records.
    if let Ok(mut states) = parse_dump(&stdout[..full * REC_BYTES], full) {
        out.append(&mut states);
    }
    if out.len() == cases.len() {
        return out;
    }
    // Case `out.len()` trapped (killed the program before its dump).
    out.push(QResult::Trap(sig.unwrap_or(0)));
    let rest = &cases[out.len()..];
    if !rest.is_empty() {
        let mut more = eval_cases(rest);
        out.append(&mut more);
    }
    out
}

/// Assemble and run a batch, returning raw stdout and the terminating signal.
fn run_qemu_raw(cases: &[(Arch, u32)]) -> Result<(Vec<u8>, Option<i32>), String> {
    let dir = std::env::temp_dir().join(format!("kemu-diff-{}", std::process::id()));
    std::fs::create_dir_all(&dir).map_err(|e| e.to_string())?;
    let asm_path = dir.join("t.s");
    let bin_path = dir.join("t.elf");
    let asm = emit_asm(cases);
    std::fs::write(&asm_path, asm).map_err(|e| e.to_string())?;

    let st = Command::new("aarch64-linux-gnu-gcc")
        .args(["-nostdlib", "-static", "-o"])
        .arg(&bin_path)
        .arg(&asm_path)
        .output()
        .map_err(|e| e.to_string())?;
    if !st.status.success() {
        return Err(format!("as/ld: {}", String::from_utf8_lossy(&st.stderr)));
    }

    let out = Command::new("qemu-aarch64")
        .arg(&bin_path)
        .output()
        .map_err(|e| e.to_string())?;
    use std::os::unix::process::ExitStatusExt;
    let sig = out.status.signal();
    Ok((out.stdout, sig))
}

const REC_BYTES: usize = (31 + 1 + 1 + 1) * 8 + 32 * 16 + 8; // x0..30,sp,nzcv,fpsr + V + marker

fn parse_dump(bytes: &[u8], n: usize) -> Result<Vec<QResult>, String> {
    let mut out = Vec::with_capacity(n);
    if bytes.len() < n * REC_BYTES {
        return Err(format!("short dump: got {} want {}", bytes.len(), n * REC_BYTES));
    }
    for k in 0..n {
        let base = k * REC_BYTES;
        let rec = &bytes[base..base + REC_BYTES];
        let g = |i: usize| u64::from_le_bytes(rec[i * 8..i * 8 + 8].try_into().unwrap());
        let marker = g(34 + 64);
        if marker != 0 {
            out.push(QResult::Trap(marker as i32));
            continue;
        }
        let mut a = Arch::zeroed();
        for r in 0..31 {
            a.x[r] = g(r);
        }
        a.sp = g(31);
        a.nzcv = g(32);
        a.fpsr = g(33) as u32;
        for r in 0..32 {
            a.v[r] = [g(34 + r * 2), g(34 + r * 2 + 1)];
        }
        out.push(QResult::State(a));
    }
    Ok(out)
}

/// Emit the assembly program that runs all cases and dumps their results.
///
/// Register convention: x0 and x1 are harness scratch (used to address the
/// input/output buffers), so the generator never uses them as a destination;
/// their results are not compared. Every other GPR, SP, NZCV, FPSR and all V
/// registers are loaded from the per-case input and dumped afterwards.
fn emit_asm(cases: &[(Arch, u32)]) -> String {
    let mut s = String::new();
    s.push_str(".text\n.global _start\n_start:\n");
    for (idx, (_, w)) in cases.iter().enumerate() {
        // --- load state ---
        s.push_str(&format!("  adrp x0, in_{idx}\n  add x0, x0, :lo12:in_{idx}\n"));
        s.push_str("  ldr x1, [x0, #256]\n  msr nzcv, x1\n");
        s.push_str("  ldr w1, [x0, #272]\n  msr fpcr, x1\n");
        s.push_str("  ldr w1, [x0, #276]\n  msr fpsr, x1\n");
        for r in 0..32 {
            s.push_str(&format!("  ldr q{r}, [x0, #{}]\n", 512 + r * 16));
        }
        s.push_str("  ldr x1, [x0, #248]\n  mov sp, x1\n");
        for r in 2..=30 {
            s.push_str(&format!("  ldr x{r}, [x0, #{}]\n", r * 8));
        }
        s.push_str("  ldr x1, [x0, #8]\n");
        s.push_str("  ldr x0, [x0, #0]\n");
        // --- instruction under test ---
        s.push_str(&format!("  .inst {:#010x}\n", w));
        // --- dump --- (x0,x1 are scratch; not written by the test insn)
        // Fill the record buffer, then write it immediately so a later case's
        // trap can't discard earlier results.
        s.push_str("  adrp x1, outbuf\n  add x1, x1, :lo12:outbuf\n");
        for r in 2..=30 {
            s.push_str(&format!("  str x{r}, [x1, #{}]\n", r * 8));
        }
        s.push_str("  mov x2, sp\n  str x2, [x1, #248]\n");
        s.push_str("  mrs x2, nzcv\n  str x2, [x1, #256]\n");
        s.push_str("  mrs x2, fpsr\n  str x2, [x1, #264]\n");
        for r in 0..32 {
            s.push_str(&format!("  str q{r}, [x1, #{}]\n", 272 + r * 16));
        }
        s.push_str(&format!("  str xzr, [x1, #{}]\n", 272 + 32 * 16));
        // write(1, outbuf, REC_BYTES)
        s.push_str("  mov x0, #1\n");
        s.push_str(&format!("  movz x2, #{}\n", REC_BYTES));
        s.push_str("  mov x8, #64\n  svc #0\n");
    }
    // exit(0)
    s.push_str("  mov x0, #0\n  mov x8, #94\n  svc #0\n");

    // Data: per-case input states, 1024-byte records.
    s.push_str(".data\n.balign 16\n");
    for (idx, (a, _)) in cases.iter().enumerate() {
        s.push_str(&format!("in_{idx}:\n"));
        for r in 0..31 {
            s.push_str(&format!("  .quad {:#x}\n", a.x[r]));
        }
        s.push_str(&format!("  .quad {:#x}\n", a.sp)); // 248
        s.push_str(&format!("  .quad {:#x}\n", a.nzcv)); // 256
        s.push_str("  .quad 0\n"); // 264 pad
        s.push_str(&format!("  .word {:#x}\n", a.fpcr)); // 272
        s.push_str(&format!("  .word {:#x}\n", a.fpsr)); // 276
        s.push_str(&format!("  .zero {}\n", 512 - 280));
        for r in 0..32 {
            s.push_str(&format!("  .quad {:#x}\n  .quad {:#x}\n", a.v[r][0], a.v[r][1]));
        }
    }
    s.push_str(&format!(".bss\n.balign 16\noutbuf: .zero {}\n", REC_BYTES + 64));
    s
}

/// Tiny xorshift RNG (deterministic, reproducible).
pub struct Rng(pub u64);
impl Rng {
    pub fn next(&mut self) -> u64 {
        let mut x = self.0;
        x ^= x << 13;
        x ^= x >> 7;
        x ^= x << 17;
        self.0 = x;
        x
    }
    pub fn bits(&mut self, n: u32) -> u32 {
        (self.next() & ((1u64 << n) - 1)) as u32
    }
}
