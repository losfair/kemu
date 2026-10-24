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

fn translate(pc: u64) -> Option<(u64, u64)> {
    let j = jit();
    if let Some(&(check, main)) = j.map.get(&pc) {
        table()[((pc >> 2) as usize) & (TABLE_ENTRIES - 1)] = check;
        return Some((main, check - meta::CHECK_OFF as u64));
    }
    let base = REGION + j.used as u64;
    let out = unsafe { std::slice::from_raw_parts_mut(base as *mut u8, CODE_SIZE - j.used) };
    let cfg = Cfg { stubs: j.stubs.addrs(REGION), code_uaddr: base };
    match t1::translate(&mut j.env, pc, out, &cfg, &mut j.scratch) {
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
        });
    }
    flush();
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
            "kemu-user: {} translations, {} helper calls, {} KiB code",
            j.translations,
            j.helpers,
            j.used / 1024
        );
    }
    j.exit_code
}
