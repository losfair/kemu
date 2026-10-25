// SPDX-License-Identifier: GPL-2.0
//! JIT mode for kemu-user: runs the kemu T1 JIT in user space exactly as a
//! kemu task does (translated code in ring 3, guest state page at %gs), with
//! the stubs calling into this harness instead of issuing `syscall`.
//!
//! Intended for profiling (`perf record` + the perf map written to
//! /tmp/perf-<pid>.map) and debugging the JIT without a VM.

use crate::syscalls;
use crate::HostMem;
use kemu_core::interp::{self, Exit};
use kemu_core::jit::meta;
use kemu_core::jit::regmap::{fpsr_merge, image_from_nzcv, mxcsr_from, nzcv_from_image};
use kemu_core::jit::stubs::{self, ExitMode, StubOffsets, OP_CHAIN, OP_HELPER, OP_STEP, OP_SVC, OP_TRANSLATE};
use kemu_core::jit::t1::{self, Cfg, Scratch};
use kemu_core::state::CpuState;
use std::arch::global_asm;
use std::collections::HashMap;
use std::io::Write;

const REGION: u64 = 0x6f00_0000_0000;
const CODE_SIZE: usize = 256 << 20;
const TABLE_ENTRIES: usize = 1 << 14;
const TABLE: u64 = REGION + CODE_SIZE as u64;
const STATE: u64 = TABLE + (TABLE_ENTRIES as u64) * 8;
const RSTACK_SIZE: usize = 4 << 20;
const RSTACK_TOP: u64 = STATE + 4096 + RSTACK_SIZE as u64 - 64;

extern "C" {
    fn kemu_jit_enter(rstack_top: u64, entry: u64);
    fn kemu_jit_harness();
}

global_asm!(
    ".globl kemu_jit_enter",
    "kemu_jit_enter:",
    "push rbx", "push rbp", "push r12", "push r13", "push r14", "push r15",
    "mov [rip + kemu_jit_host_rsp], rsp",
    "mov rsp, rdi",
    "jmp rsi",
    ".globl kemu_jit_harness",
    "kemu_jit_harness:",
    "mov edi, eax",
    "mov rbp, rsp",
    "and rsp, -16",
    "call kemu_jit_handle_op",
    "test rdx, rdx",
    "jnz 2f",
    "mov rsp, rbp",
    "ret",
    "2:",
    "mov rsp, [rip + kemu_jit_host_rsp]",
    "pop r15", "pop r14", "pop r13", "pop r12", "pop rbp", "pop rbx",
    "ret",
    ".data",
    "kemu_jit_host_rsp: .quad 0",
    ".text",
);

struct Jit {
    stubs: StubOffsets,
    used: usize,
    map: HashMap<u64, (u64, u64)>,
    blocks: Vec<(u64, usize)>,
    scratch: Box<Scratch>,
    env: HostMem,
    perf: Option<std::fs::File>,
    exit_code: i32,
    translations: u64,
    helpers: u64,
    hstat: HashMap<String, u64>,
    translate_ns: u64,
}

static mut JIT: Option<Jit> = None;

#[allow(static_mut_refs)]
fn jit() -> &'static mut Jit {
    unsafe { JIT.as_mut().unwrap() }
}

fn st() -> &'static mut CpuState {
    unsafe { &mut *(STATE as *mut CpuState) }
}

fn table() -> &'static mut [u64] {
    unsafe { std::slice::from_raw_parts_mut(TABLE as *mut u64, TABLE_ENTRIES) }
}

fn map(addr: u64, len: usize, prot: i32) {
    let p = unsafe {
        libc::mmap(
            addr as *mut _,
            len,
            prot,
            libc::MAP_PRIVATE | libc::MAP_ANONYMOUS | libc::MAP_FIXED_NOREPLACE,
            -1,
            0,
        )
    };
    assert_eq!(p as u64, addr, "kemu-user: cannot map JIT region");
}

fn host_crypto() -> t1::HostCrypto {
    t1::HostCrypto {
        aes: std::is_x86_feature_detected!("aes"),
        pclmul: std::is_x86_feature_detected!("pclmulqdq"),
    }
}

fn translate(pc: u64) -> Option<(u64, u64)> {
    let j = jit();
    if let Some(&(check, main)) = j.map.get(&pc) {
        table()[((pc >> 2) as usize) & (TABLE_ENTRIES - 1)] = check;
        return Some((main, check - meta::CHECK_OFF as u64));
    }
    let base = REGION + j.used as u64;
    let out = unsafe { std::slice::from_raw_parts_mut(base as *mut u8, CODE_SIZE - j.used) };
    let cfg = Cfg { stubs: j.stubs.addrs(REGION), code_uaddr: base, reloc: false, tbi: false, vector_cache: std::env::var("NO_VCACHE").is_err(), crypto: host_crypto() };
    let t0 = std::time::Instant::now();
    let res = t1::translate(&mut j.env, pc, out, &cfg, &mut j.scratch);
    j.translate_ns += t0.elapsed().as_nanos() as u64;
    match res {
        Ok(r) => {
            j.used += r.size;
            j.translations += 1;
            j.blocks.push((base, r.size));
            let check = base + r.check_off as u64;
            let main = base + r.main_off as u64;
            j.map.insert(pc, (check, main));
            table()[((pc >> 2) as usize) & (TABLE_ENTRIES - 1)] = check;
            if std::env::var("KEMU_DUMP_BLOCK").ok().and_then(|v| u64::from_str_radix(v.trim_start_matches("0x"), 16).ok()) == Some(pc) {
                let code = unsafe { std::slice::from_raw_parts(base as *const u8, r.size) };
                let _ = std::fs::write(format!("/tmp/kemu-block-{pc:x}.bin"), code);
            }
            if let Some(f) = j.perf.as_mut() {
                let _ = writeln!(f, "{:x} {:x} g_{:x}", base, r.size, pc);
            }
            Some((main, base))
        }
        Err(e) => {
            eprintln!("kemu-user: translation of {pc:#x} failed: {e:?}");
            None
        }
    }
}

#[repr(C)]
pub struct Ret {
    val: u64,
    stop: u64,
}

fn enter_kernel_state() {
    let s = st();
    s.nzcv = nzcv_from_image(s.flags_x86);
    s.fpsr = fpsr_merge(s.fpsr, s.scratch[7] as u32);
}

fn leave_kernel_state() {
    let s = st();
    s.flags_x86 = image_from_nzcv(s.nzcv);
    s.scratch[7] = mxcsr_from(s.fpcr, s.fpsr) as u64;
}

fn stop(code: i32) -> Ret {
    jit().exit_code = code;
    Ret { val: 0, stop: 1 }
}

#[no_mangle]
pub extern "C" fn kemu_jit_handle_op(op: u32) -> Ret {
    enter_kernel_state();
    let r = handle(op);
    leave_kernel_state();
    r
}

fn handle(op: u32) -> Ret {
    let s = st();
    match op {
        OP_TRANSLATE | OP_CHAIN => {
            let pc = s.pc;
            let (main, blk) = match translate(pc) {
                Some(x) => x,
                None => return stop(139),
            };
            if op == OP_CHAIN {
                let site = s.exit_info;
                if let Some(&(b, sz)) = jit().blocks.iter().find(|(b, sz)| site >= *b && site < *b + *sz as u64) {
                    let bytes = unsafe { std::slice::from_raw_parts(b as *const u8, sz) };
                    if let Some(h) = meta::Header::read(bytes) {
                        let m = &bytes[h.meta_off as usize..(h.meta_off + h.meta_len) as usize];
                        if let Some(e) = meta::find_exit_site(m, (site - b) as u32) {
                            let dest = if e.kind == meta::EXIT_IC { blk + meta::IC_OFF as u64 } else { main };
                            let rel = dest.wrapping_sub(site + 4) as i64 as i32;
                            unsafe { (site as *mut i32).write_unaligned(rel) };
                        }
                    }
                }
            }
            Ret { val: main, stop: 0 }
        }
        OP_HELPER | OP_STEP => {
            jit().helpers += 1;
            let pc = s.pc;
            if std::env::var("KEMU_JIT_STATS").is_ok() {
                let w = unsafe { (pc as *const u32).read() };
                let name = format!("{:?}", kemu_core::decode::decode(w));
                let key: String = name.chars().take(48).collect();
                *jit().hstat.entry(key).or_insert(0) += 1;
            }
            let (ex, _) = interp::run(s, &mut jit().env, 1);
            match ex {
                Exit::Budget if s.pc == pc + 4 => Ret { val: 0, stop: 0 },
                Exit::IcInvalidate(_) => {
                    // Simplest correct policy for the harness: flush all.
                    flush();
                    Ret { val: 0, stop: 0 }
                }
                e => {
                    eprintln!("kemu-user: guest stopped: {e:?} at pc={:#x}", s.pc);
                    stop(if matches!(e, Exit::Undefined(_)) { 132 } else { 139 })
                }
            }
        }
        OP_SVC => match syscalls::dispatch(s, jit().env.trace) {
            Some(code) => stop(code),
            None => Ret { val: 0, stop: 0 },
        },
        _ => {
            eprintln!("kemu-user: bad kemu op {op:#x}");
            stop(134)
        }
    }
}

fn flush() {
    // Note: a real flush must also fix up stale return addresses; the
    // harness only supports it between blocks (helper path).
    let j = jit();
    j.map.clear();
    let miss = REGION + j.stubs.miss as u64;
    for e in table().iter_mut() {
        *e = miss;
    }
}

/// Translator throughput: translate a block at every 64-byte step of
/// `span` bytes from `start` (into a throwaway buffer), 5 rounds.
fn xlat_bench(start: u64, span: u64) {
    let j = jit();
    let mut buf = vec![0u8; 256 << 10];
    let reloc = std::env::var("KEMU_RELOC").is_ok();
    let cfg = Cfg { stubs: j.stubs.addrs(REGION), code_uaddr: REGION + (1 << 20), reloc, tbi: false, vector_cache: std::env::var("NO_VCACHE").is_err(), crypto: host_crypto() };
    let (mut n, mut bytes, mut insns) = (0u64, 0u64, 0u64);
    let t0 = std::time::Instant::now();
    for _ in 0..5 {
        let mut pc = start;
        while pc < start + span {
            if let Ok(r) = t1::translate(&mut j.env, pc, &mut buf, &cfg, &mut j.scratch) {
                n += 1;
                bytes += r.size as u64;
                insns += r.ninsns as u64;
            }
            pc += 64;
        }
    }
    let ns = t0.elapsed().as_nanos() as u64;
    eprintln!(
        "xlat: {n} blocks, {:.2} us/block, {:.1} guest insns/block, {:.0} ns/insn, {} bytes/block",
        ns as f64 / 1000.0 / n.max(1) as f64,
        insns as f64 / n.max(1) as f64,
        ns as f64 / insns.max(1) as f64,
        bytes / n.max(1)
    );
}

/// Guest memory view shifted up by `d` bytes (fetch only), to translate
/// the same code as if it were mapped elsewhere.
struct Shifted<'a> {
    env: &'a mut HostMem,
    d: u64,
}

impl kemu_core::env::Env for Shifted<'_> {
    fn fetch(&mut self, pc: u64) -> Result<u32, kemu_core::env::Fault> {
        self.env.fetch(pc.wrapping_sub(self.d))
    }
    fn read_u8(&mut self, a: u64) -> Result<u8, kemu_core::env::Fault> { self.env.read_u8(a) }
    fn read_u16(&mut self, a: u64) -> Result<u16, kemu_core::env::Fault> { self.env.read_u16(a) }
    fn read_u32(&mut self, a: u64) -> Result<u32, kemu_core::env::Fault> { self.env.read_u32(a) }
    fn read_u64(&mut self, a: u64) -> Result<u64, kemu_core::env::Fault> { self.env.read_u64(a) }
    fn write_u8(&mut self, a: u64, v: u8) -> Result<(), kemu_core::env::Fault> { self.env.write_u8(a, v) }
    fn write_u16(&mut self, a: u64, v: u16) -> Result<(), kemu_core::env::Fault> { self.env.write_u16(a, v) }
    fn write_u32(&mut self, a: u64, v: u32) -> Result<(), kemu_core::env::Fault> { self.env.write_u32(a, v) }
    fn write_u64(&mut self, a: u64, v: u64) -> Result<(), kemu_core::env::Fault> { self.env.write_u64(a, v) }
    fn cmpxchg(&mut self, a: u64, s: u32, e: [u64; 2], n: [u64; 2]) -> Result<[u64; 2], kemu_core::env::Fault> {
        self.env.cmpxchg(a, s, e, n)
    }
    fn cntvct(&mut self) -> u64 { self.env.cntvct() }
    fn cntfrq(&mut self) -> u64 { self.env.cntfrq() }
    fn random(&mut self) -> Option<u64> { self.env.random() }
}

/// Shared-cache relocation check: a relocatable translation at `pc`,
/// copied and relocated to `pc + D` and another code offset, must equal a
/// fresh translation made there (and its dependencies must validate).
fn reloc_check(start: u64, span: u64) {
    use kemu_core::jit::xcache;
    let j = jit();
    let d: u64 = 0x13_5797_5000;
    let (off_a, off_b) = (1u64 << 20, (3u64 << 20) + 0x4a0);
    let mut a = vec![0u8; 256 << 10];
    let mut b = vec![0u8; 256 << 10];
    let mut blob = vec![0u8; 8192];
    let (mut n, mut bad, mut uncacheable) = (0u64, 0u64, 0u64);
    let mut pc = start;
    while pc < start + span {
        let ca = Cfg { stubs: j.stubs.addrs(REGION), code_uaddr: REGION + off_a, reloc: true, tbi: false, vector_cache: std::env::var("NO_VCACHE").is_err(), crypto: host_crypto() };
        let ra = match t1::translate(&mut j.env, pc, &mut a, &ca, &mut j.scratch) {
            Ok(r) => r,
            Err(_) => {
                pc += 4;
                continue;
            }
        };
        let blen = match j.scratch.xcache_blob(pc, off_a, &mut blob) {
            Some(l) => l,
            None => {
                uncacheable += 1;
                pc += 4;
                continue;
            }
        };
        let cb = Cfg { stubs: j.stubs.addrs(REGION), code_uaddr: REGION + off_b, reloc: true, tbi: false, vector_cache: std::env::var("NO_VCACHE").is_err(), crypto: host_crypto() };
        let rb = {
            let mut sh = Shifted { env: &mut j.env, d };
            t1::translate(&mut sh, pc + d, &mut b, &cb, &mut j.scratch)
        };
        n += 1;
        let mut copy = a[..ra.size].to_vec();
        let valid = {
            let mut sh = Shifted { env: &mut j.env, d };
            xcache::validate(&mut sh, &blob[..blen], pc + d)
        };
        let ok = match rb {
            Ok(rb) => valid && rb.size == ra.size && xcache::apply(&blob[..blen], &mut copy, pc + d, off_b) && copy == b[..rb.size],
            Err(_) => false,
        };
        if !ok {
            bad += 1;
            if bad <= 5 {
                let diffs: Vec<usize> = copy.iter().zip(b.iter()).enumerate().filter(|(_, (x, y))| x != y).map(|(i, _)| i).take(8).collect();
                eprintln!("reloc mismatch at {pc:#x}: valid={valid} size {} diffs at {:x?}", ra.size, diffs);
                if let Some(&d0) = diffs.first() {
                    let lo = d0.saturating_sub(9);
                    eprintln!("  relocated {:02x?}\n  fresh     {:02x?}", &copy[lo..(lo + 20).min(copy.len())], &b[lo..lo + 20]);
                    if let Some(h) = meta::Header::read(&copy) {
                        eprintln!("  meta_off {:#x} code_end {:#x}", h.meta_off, h.code_end);
                        let m = &copy[h.meta_off as usize..(h.meta_off + h.meta_len) as usize];
                        let (np, ne) = meta::meta_counts(m).unwrap_or((0, 0));
                        for i in 0..ne {
                            if let Some(e) = meta::read_exit(m, i) {
                                eprintln!("  exit {i}: site {:#x} kind {} target {:#x} (at {:#x})", e.site, e.kind, e.target, h.meta_off as usize + meta::META_HDR_SIZE + np * meta::POINT_SIZE + i * meta::EXIT_SIZE);
                            }
                        }
                    }
                }
            }
        }
        pc += 4;
    }
    eprintln!("reloc check: {n} blocks, {bad} mismatches, {uncacheable} uncacheable");
}

/// Run the guest from `cpu` under the JIT; returns the exit status.
pub fn run(cpu: &CpuState, env: HostMem) -> i32 {
    map(REGION, CODE_SIZE, libc::PROT_READ | libc::PROT_WRITE | libc::PROT_EXEC);
    map(TABLE, TABLE_ENTRIES * 8, libc::PROT_READ | libc::PROT_WRITE);
    map(STATE, 4096 + RSTACK_SIZE, libc::PROT_READ | libc::PROT_WRITE);
    unsafe {
        assert_eq!(libc::syscall(libc::SYS_arch_prctl, 0x1001, STATE), 0);
    }
    let stub_page = unsafe { std::slice::from_raw_parts_mut(REGION as *mut u8, 4096) };
    let so = stubs::gen_stubs(
        stub_page,
        ExitMode::Call(kemu_jit_harness as u64),
        TABLE,
        ((TABLE_ENTRIES - 1) << 3) as u32,
    )
    .expect("stubs");
    let perf = if std::env::var("KEMU_PERF_MAP").is_ok() {
        std::fs::File::create(format!("/tmp/perf-{}.map", std::process::id())).ok()
    } else {
        None
    };
    unsafe {
        JIT = Some(Jit {
            stubs: so,
            used: 4096,
            map: HashMap::new(),
            blocks: Vec::new(),
            scratch: Box::new(Scratch::new()),
            env,
            perf,
            exit_code: 0,
            translations: 0,
            helpers: 0,
            hstat: HashMap::new(),
            translate_ns: 0,
        });
    }
    flush();
    if let Some(span) = std::env::var("KEMU_XLAT_BENCH").ok().and_then(|v| v.parse::<u64>().ok()) {
        xlat_bench(cpu.pc, span);
        return 0;
    }
    if let Some(span) = std::env::var("KEMU_RELOC_CHECK").ok().and_then(|v| v.parse::<u64>().ok()) {
        reloc_check(cpu.pc, span);
        return 0;
    }
    let s = st();
    *s = *cpu;
    s.host_rsp_top = RSTACK_TOP;
    for i in 0..8 {
        unsafe { ((RSTACK_TOP + i * 8) as *mut u64).write(REGION + so.dispatch_rax as u64) };
    }
    leave_kernel_state();
    unsafe { kemu_jit_enter(RSTACK_TOP, REGION + so.dispatch as u64) };
    let j = jit();
    if std::env::var("KEMU_JIT_STATS").is_ok() {
        eprintln!(
            "kemu-user: {} translations ({} us), {} helper calls, {} KiB code",
            j.translations,
            j.translate_ns / 1000,
            j.helpers,
            j.used / 1024
        );
        let mut v: Vec<_> = j.hstat.iter().collect();
        v.sort_by(|a, b| b.1.cmp(a.1));
        for (k, n) in v.iter().take(12) {
            eprintln!("  helper {n:>10}  {k}");
        }
    }
    j.exit_code
}
