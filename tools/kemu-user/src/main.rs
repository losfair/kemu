// SPDX-License-Identifier: GPL-2.0
//! kemu-user: a userspace runner for AArch64 Linux ELF binaries using the
//! kemu interpreter core. Guest virtual addresses are identity-mapped to host
//! virtual addresses, so guest memory accesses are plain host dereferences.
//!
//! This is a development/validation harness (the same structure the in-kernel
//! path and the JIT reuse). It forwards a practical subset of the arm64 Linux
//! syscall ABI to the host x86-64 kernel.

use kemu_core::env::{Access, Env, Fault};
use kemu_core::interp::{self, Exit};
use kemu_core::state::CpuState;
use kemu_core::sysregs;
use std::os::unix::ffi::OsStrExt;

mod elf;
mod jit;
mod syscalls;

/// Host-memory-backed environment: guest VA == host VA.
pub(crate) struct HostMem {
    /// Whether to trace syscalls to stderr.
    pub(crate) trace: bool,
}

macro_rules! rd {
    ($name:ident, $t:ty) => {
        fn $name(&mut self, a: u64) -> Result<$t, Fault> {
            // SAFETY: identity mapping; a fault here would be a host SIGSEGV,
            // which we convert via a signal handler in a full build. For the
            // harness we rely on valid guest mappings.
            Ok(unsafe { core::ptr::read_unaligned(a as *const $t) })
        }
    };
}
macro_rules! wr {
    ($name:ident, $t:ty) => {
        fn $name(&mut self, a: u64, v: $t) -> Result<(), Fault> {
            let w = WATCH.load(Ordering::Relaxed);
            if w != 0 && a <= w + 7 && a + core::mem::size_of::<$t>() as u64 > w {
                eprintln!("WATCH write {:#x} size {} val {:#x} at pc {:#x}", a, core::mem::size_of::<$t>(), v, CUR_PC.load(Ordering::Relaxed));
            }
            unsafe { core::ptr::write_unaligned(a as *mut $t, v) };
            Ok(())
        }
    };
}

impl Env for HostMem {
    fn fetch(&mut self, pc: u64) -> Result<u32, Fault> {
        Ok(unsafe { core::ptr::read(pc as *const u32) })
    }
    rd!(read_u8, u8);
    rd!(read_u16, u16);
    rd!(read_u32, u32);
    rd!(read_u64, u64);
    wr!(write_u8, u8);
    wr!(write_u16, u16);
    wr!(write_u32, u32);
    wr!(write_u64, u64);
    fn cmpxchg(&mut self, a: u64, size: u32, expected: [u64; 2], new: [u64; 2]) -> Result<[u64; 2], Fault> {
        // Single-threaded harness: emulate atomically enough.
        unsafe {
            match size {
                1 => {
                    let p = a as *mut u8;
                    let old = core::ptr::read(p) as u64;
                    if old == expected[0] & 0xff {
                        core::ptr::write(p, new[0] as u8);
                    }
                    Ok([old, 0])
                }
                2 => {
                    let p = a as *mut u16;
                    let old = core::ptr::read_unaligned(p) as u64;
                    if old == expected[0] & 0xffff {
                        core::ptr::write_unaligned(p, new[0] as u16);
                    }
                    Ok([old, 0])
                }
                4 => {
                    let p = a as *mut u32;
                    let old = core::ptr::read_unaligned(p) as u64;
                    if old == expected[0] & 0xffff_ffff {
                        core::ptr::write_unaligned(p, new[0] as u32);
                    }
                    Ok([old, 0])
                }
                8 => {
                    let p = a as *mut u64;
                    let old = core::ptr::read_unaligned(p);
                    if old == expected[0] {
                        core::ptr::write_unaligned(p, new[0]);
                    }
                    Ok([old, 0])
                }
                _ => {
                    let p = a as *mut u64;
                    let o0 = core::ptr::read_unaligned(p);
                    let o1 = core::ptr::read_unaligned(p.add(1));
                    if [o0, o1] == expected {
                        core::ptr::write_unaligned(p, new[0]);
                        core::ptr::write_unaligned(p.add(1), new[1]);
                    }
                    Ok([o0, o1])
                }
            }
        }
    }
    fn cntvct(&mut self) -> u64 {
        // Use the host TSC-like monotonic clock in nanoseconds, scaled to the
        // advertised frequency.
        let mut ts = libc::timespec { tv_sec: 0, tv_nsec: 0 };
        unsafe { libc::clock_gettime(libc::CLOCK_MONOTONIC, &mut ts) };
        (ts.tv_sec as u64).wrapping_mul(1_000_000_000).wrapping_add(ts.tv_nsec as u64)
    }
    fn cntfrq(&mut self) -> u64 {
        1_000_000_000
    }
    fn random(&mut self) -> Option<u64> {
        let mut v = 0u64;
        let r = unsafe { libc::getrandom(&mut v as *mut u64 as *mut _, 8, 0) };
        if r == 8 { Some(v) } else { Some(0) }
    }
}

fn main() {
    let args: Vec<String> = std::env::args().collect();
    let mut trace = false;
    let mut use_jit = false;
    let mut idx = 1;
    while idx < args.len() && args[idx].starts_with("--") {
        if args[idx] == "--trace" {
            trace = true;
        }
        if args[idx] == "--jit" {
            use_jit = true;
        }
        idx += 1;
    }
    if idx >= args.len() {
        eprintln!("usage: kemu-user [--trace] [--jit] <aarch64-elf> [args...]");
        std::process::exit(2);
    }
    let prog = &args[idx];
    let guest_args: Vec<Vec<u8>> = args[idx..]
        .iter()
        .map(|s| s.as_bytes().to_vec())
        .collect();
    let envp: Vec<Vec<u8>> = std::env::vars_os()
        .filter(|(k, _)| !k.to_string_lossy().starts_with("KEMU_"))
        .map(|(k, v)| {
            let mut b = k.as_bytes().to_vec();
            b.push(b'=');
            b.extend_from_slice(v.as_bytes());
            b
        })
        .collect();

    let loaded = match elf::load(prog, &guest_args, &envp) {
        Ok(l) => l,
        Err(e) => {
            eprintln!("kemu-user: load failed: {e}");
            std::process::exit(1);
        }
    };

    let mut cpu = CpuState::new();
    cpu.pc = loaded.entry;
    cpu.sp = loaded.sp;
    let mut env = HostMem { trace };
    let _ = sysregs::HWCAP;

    if std::env::var("KEMU_DUMP_STACK").is_ok() {
        let sp = cpu.sp;
        let argc = unsafe { core::ptr::read(sp as *const u64) };
        eprintln!("sp={:#x} argc={}", sp, argc);
        for i in 0..80u64 {
            let a = sp + i * 8;
            let v = unsafe { core::ptr::read(a as *const u64) };
            eprintln!("  [{:#x}] (+{:#x}) = {:#018x}", a, i*8, v);
        }
    }
    if use_jit {
        install_segv();
        std::process::exit(jit::run(&cpu, env));
    }
    run_loop(&mut cpu, &mut env);
}

use std::sync::atomic::{AtomicU64, Ordering};
static CUR_PC: AtomicU64 = AtomicU64::new(0);
static FAULT_ADDR: AtomicU64 = AtomicU64::new(0);
static CPU_PTR: AtomicU64 = AtomicU64::new(0);

extern "C" fn segv_handler(_sig: i32, info: *mut libc::siginfo_t, _ctx: *mut libc::c_void) {
    // si_addr is at a fixed offset; read it portably via the struct.
    let addr = unsafe { (*info).si_addr() } as u64;
    FAULT_ADDR.store(addr, Ordering::SeqCst);
    let p = CPU_PTR.load(Ordering::SeqCst);
    let pc = if p != 0 { unsafe { (*(p as *const CpuState)).pc } } else { CUR_PC.load(Ordering::SeqCst) };
    let msg = alloc_msg(pc, addr);
    unsafe { libc::write(2, msg.as_ptr() as *const _, msg.len()); }
    unsafe { libc::_exit(139); }
}

fn alloc_msg(pc: u64, addr: u64) -> String {
    format!("kemu-user: host SIGSEGV: guest pc={:#x} accessing {:#x}\n", pc, addr)
}

fn install_segv() {
    unsafe {
        let mut sa: libc::sigaction = core::mem::zeroed();
        sa.sa_sigaction = segv_handler as usize;
        sa.sa_flags = libc::SA_SIGINFO;
        libc::sigaction(libc::SIGSEGV, &sa, core::ptr::null_mut());
    }
}

static WATCH: AtomicU64 = AtomicU64::new(0);

fn trace_enabled() -> usize {
    std::env::var("KEMU_TRACE_INSN").ok().and_then(|v| v.parse().ok()).unwrap_or(0)
}

fn print_state(cpu: &CpuState) {
    let mut line = format!("PC={:016x}", cpu.pc);
    for r in 0..31 {
        line.push_str(&format!(" X{:02}={:016x}", r, cpu.x[r]));
    }
    line.push_str(&format!(" SP={:016x}", cpu.sp));
    eprintln!("{line}");
}

fn run_loop(cpu: &mut CpuState, env: &mut HostMem) {
    install_segv();
    CPU_PTR.store(cpu as *const CpuState as u64, Ordering::SeqCst);
    let mut tracen = trace_enabled();
    if let Ok(w) = std::env::var("KEMU_WATCH") {
        WATCH.store(u64::from_str_radix(w.trim_start_matches("0x"), 16).unwrap_or(0), Ordering::SeqCst);
        tracen = usize::MAX; // single-step so CUR_PC is exact
    }
    let mut traced = 0usize;
    loop {
        CUR_PC.store(cpu.pc, Ordering::SeqCst);
        let budget = if tracen != 0 && traced < tracen { 1 } else { 100_000 };
        if tracen != 0 && traced < tracen && WATCH.load(Ordering::Relaxed) == 0 {
            print_state(cpu);
            traced += 1;
        }
        let (exit, _n) = interp::run(cpu, env, budget);
        CUR_PC.store(cpu.pc, Ordering::SeqCst);
        match exit {
            Exit::Svc => {
                if let Some(code) = syscalls::dispatch(cpu, env.trace) {
                    std::process::exit(code);
                }
            }
            Exit::IcInvalidate(_) => {
                // Nothing to do for the interpreter.
            }
            Exit::Brk(imm) => {
                eprintln!("kemu-user: guest BRK #{imm} at pc={:#x}", cpu.pc);
                deliver_fatal(libc::SIGTRAP);
            }
            Exit::Undefined(w) => {
                eprintln!(
                    "kemu-user: undefined/unsupported instruction {:#010x} at pc={:#x}",
                    w, cpu.pc
                );
                deliver_fatal(libc::SIGILL);
            }
            Exit::Fault(f) => {
                eprintln!(
                    "kemu-user: fault {:?} addr={:#x} at pc={:#x}",
                    f.access, f.addr, cpu.pc
                );
                deliver_fatal(if f.align { libc::SIGBUS } else { libc::SIGSEGV });
            }
            Exit::Budget => {}
        }
    }
}

fn deliver_fatal(sig: i32) -> ! {
    unsafe {
        libc::signal(sig, libc::SIG_DFL);
        libc::raise(sig);
    }
    std::process::exit(128 + sig);
}

#[allow(dead_code)]
fn access_name(a: Access) -> &'static str {
    match a {
        Access::Read => "read",
        Access::Write => "write",
        Access::Exec => "exec",
    }
}

#[allow(dead_code)]
fn os_bytes(p: &std::path::Path) -> Vec<u8> {
    p.as_os_str().as_bytes().to_vec()
}
