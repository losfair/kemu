// SPDX-License-Identifier: GPL-2.0
//! Differential tester for the kemu T1 JIT.
//!
//! Runs translated x86 code natively in this process (user mode, exactly
//! as in a kemu task, with %gs pointing at a guest state page) and compares
//! the result against the reference interpreter for random instruction
//! sequences. Stubs reach the harness with `call` instead of `syscall`.

use kemu_core::decode::{decode, Insn};
use kemu_core::env::{Access, Env, Fault};
use kemu_core::interp::{self, Exit};
use kemu_core::jit::regmap::{fpsr_merge, image_from_nzcv, mxcsr_from, nzcv_from_image};
use kemu_core::jit::stubs::{self, ExitMode, StubOffsets, OP_CHAIN, OP_HELPER, OP_SVC, OP_TRANSLATE};
use kemu_core::jit::t1::{self, Cfg, Scratch};
use kemu_core::jit::meta;
use kemu_core::state::CpuState;
use std::collections::HashMap;
use std::arch::global_asm;

const REGION: u64 = 0x6e00_0000_0000;
const CODE_SIZE: usize = 64 << 20;
const TABLE_BITS: u32 = 14;
const TABLE_ENTRIES: usize = 1 << TABLE_BITS;
const TABLE: u64 = REGION + CODE_SIZE as u64;
const STATE: u64 = TABLE + (TABLE_ENTRIES as u64) * 8;
const RSTACK_SIZE: usize = 1 << 20;
const RSTACK_TOP: u64 = STATE + 4096 + RSTACK_SIZE as u64;
const GUEST: u64 = 0x5000_0000_0000;
const GUEST_SIZE: usize = 1 << 20;
const DATA: u64 = 0x5100_0000_0000;
const DATA_SIZE: usize = 1 << 16;

extern "C" {
    fn mmap(addr: *mut u8, len: usize, prot: i32, flags: i32, fd: i32, off: i64) -> *mut u8;
    fn arch_prctl(code: i32, addr: u64) -> i32;
    fn jt_enter(rstack_top: u64, entry: u64);
    fn jt_harness_entry();
}

global_asm!(
    ".globl jt_enter",
    "jt_enter:",
    "push rbx", "push rbp", "push r12", "push r13", "push r14", "push r15",
    "mov [rip + jt_host_rsp], rsp",
    "mov rsp, rdi",
    "jmp rsi",
    ".globl jt_harness_entry",
    "jt_harness_entry:",
    "mov edi, eax",
    "mov rbp, rsp",
    "and rsp, -16",
    "call jt_handle_op",
    "test rdx, rdx",
    "jnz 2f",
    "mov rsp, rbp",
    "ret",
    "2:",
    "mov rsp, [rip + jt_host_rsp]",
    "pop r15", "pop r14", "pop r13", "pop r12", "pop rbp", "pop rbx",
    "ret",
    ".data",
    ".globl jt_host_rsp",
    "jt_host_rsp: .quad 0",
    ".text",
);

fn map_fixed(addr: u64, len: usize, prot: i32) {
    // PROT: 1 R, 2 W, 4 X; MAP_PRIVATE|MAP_ANONYMOUS|MAP_FIXED_NOREPLACE
    let p = unsafe { mmap(addr as *mut u8, len, prot, 0x02 | 0x20 | 0x100000, -1, 0) };
    assert_eq!(p as u64, addr, "mmap at {addr:#x} failed");
}

/// Guest memory: the guest code and data windows of this process.
struct UEnv;

fn in_range(a: u64, n: u64) -> bool {
    (a >= GUEST && a + n <= GUEST + GUEST_SIZE as u64) || (a >= DATA && a + n <= DATA + DATA_SIZE as u64)
}

impl UEnv {
    fn chk(&self, a: u64, n: u64, acc: Access) -> Result<(), Fault> {
        if in_range(a, n) {
            Ok(())
        } else {
            Err(Fault { addr: a, access: acc, align: false })
        }
    }
}

impl Env for UEnv {
    fn fetch(&mut self, pc: u64) -> Result<u32, Fault> {
        if !(pc >= GUEST && pc + 4 <= GUEST + GUEST_SIZE as u64) {
            return Err(Fault { addr: pc, access: Access::Exec, align: false });
        }
        Ok(unsafe { (pc as *const u32).read_unaligned() })
    }
    fn read_u8(&mut self, a: u64) -> Result<u8, Fault> {
        self.chk(a, 1, Access::Read)?;
        Ok(unsafe { (a as *const u8).read() })
    }
    fn read_u16(&mut self, a: u64) -> Result<u16, Fault> {
        self.chk(a, 2, Access::Read)?;
        Ok(unsafe { (a as *const u16).read_unaligned() })
    }
    fn read_u32(&mut self, a: u64) -> Result<u32, Fault> {
        self.chk(a, 4, Access::Read)?;
        Ok(unsafe { (a as *const u32).read_unaligned() })
    }
    fn read_u64(&mut self, a: u64) -> Result<u64, Fault> {
        self.chk(a, 8, Access::Read)?;
        Ok(unsafe { (a as *const u64).read_unaligned() })
    }
    fn write_u8(&mut self, a: u64, v: u8) -> Result<(), Fault> {
        self.chk(a, 1, Access::Write)?;
        unsafe { (a as *mut u8).write(v) };
        Ok(())
    }
    fn write_u16(&mut self, a: u64, v: u16) -> Result<(), Fault> {
        self.chk(a, 2, Access::Write)?;
        unsafe { (a as *mut u16).write_unaligned(v) };
        Ok(())
    }
    fn write_u32(&mut self, a: u64, v: u32) -> Result<(), Fault> {
        self.chk(a, 4, Access::Write)?;
        unsafe { (a as *mut u32).write_unaligned(v) };
        Ok(())
    }
    fn write_u64(&mut self, a: u64, v: u64) -> Result<(), Fault> {
        self.chk(a, 8, Access::Write)?;
        unsafe { (a as *mut u64).write_unaligned(v) };
        Ok(())
    }
    fn cmpxchg(&mut self, a: u64, size: u32, e: [u64; 2], n: [u64; 2]) -> Result<[u64; 2], Fault> {
        if a % size as u64 != 0 {
            return Err(Fault { addr: a, access: Access::Write, align: true });
        }
        self.chk(a, size as u64, Access::Write)?;
        use std::sync::atomic::*;
        let old = unsafe {
            match size {
                1 => match (*(a as *const AtomicU8)).compare_exchange(e[0] as u8, n[0] as u8, Ordering::SeqCst, Ordering::SeqCst) {
                    Ok(v) | Err(v) => v as u64,
                },
                2 => match (*(a as *const AtomicU16)).compare_exchange(e[0] as u16, n[0] as u16, Ordering::SeqCst, Ordering::SeqCst) {
                    Ok(v) | Err(v) => v as u64,
                },
                4 => match (*(a as *const AtomicU32)).compare_exchange(e[0] as u32, n[0] as u32, Ordering::SeqCst, Ordering::SeqCst) {
                    Ok(v) | Err(v) => v as u64,
                },
                8 => match (*(a as *const AtomicU64)).compare_exchange(e[0], n[0], Ordering::SeqCst, Ordering::SeqCst) {
                    Ok(v) | Err(v) => v,
                },
                _ => {
                    let p = a as *mut u64;
                    let (lo, hi) = (p.read(), p.add(1).read());
                    if lo == e[0] && hi == e[1] {
                        p.write(n[0]);
                        p.add(1).write(n[1]);
                    }
                    return Ok([lo, hi]);
                }
            }
        };
        Ok([old, 0])
    }
    fn cntvct(&mut self) -> u64 {
        0
    }
    fn cntfrq(&mut self) -> u64 {
        1_000_000_000
    }
    fn random(&mut self) -> Option<u64> {
        Some(4)
    }
}

struct Harness {
    stubs: StubOffsets,
    code_used: usize,
    map: HashMap<u64, (u64, u64)>,
    blocks: Vec<(u64, usize)>,
    scratch: Box<Scratch>,
    stop: Option<Exit>,
    translations: usize,
    helpers: usize,
}

static mut H: Option<Harness> = None;

fn state() -> &'static mut CpuState {
    unsafe { &mut *(STATE as *mut CpuState) }
}

fn table() -> &'static mut [u64] {
    unsafe { std::slice::from_raw_parts_mut(TABLE as *mut u64, TABLE_ENTRIES) }
}

#[allow(static_mut_refs)]
fn h() -> &'static mut Harness {
    unsafe { H.as_mut().unwrap() }
}

fn lookup_or_translate(pc: u64) -> Result<u64, Fault> {
    let hh = h();
    if let Some(&(check, main)) = hh.map.get(&pc) {
        table()[((pc >> 2) as usize) & (TABLE_ENTRIES - 1)] = check;
        return Ok(main);
    }
    let base = REGION + hh.code_used as u64;
    let out = unsafe { std::slice::from_raw_parts_mut(base as *mut u8, CODE_SIZE - hh.code_used) };
    let cfg = Cfg { stubs: hh.stubs.addrs(REGION), code_uaddr: base, reloc: std::env::var("RELOC").is_ok() };
    match t1::translate(&mut UEnv, pc, out, &cfg, &mut hh.scratch) {
        Ok(r) => {
            hh.blocks.push((base, r.size));
            hh.code_used += r.size;
            hh.translations += 1;
            let check = base + r.check_off as u64;
            let main = base + r.main_off as u64;
            hh.map.insert(pc, (check, main));
            table()[((pc >> 2) as usize) & (TABLE_ENTRIES - 1)] = check;
            Ok(main)
        }
        Err(t1::TErr::Fault(f)) => Err(f),
        Err(e) => panic!("translate failed: {e:?}"),
    }
}

/// Offset of `main` from its block start.
fn main_off_of(main: u64) -> u64 {
    let hh = h();
    let &(b, _) = hh.blocks.iter().find(|(b, sz)| main >= *b && main < *b + *sz as u64).unwrap();
    main - b
}

#[repr(C)]
pub struct Ret {
    val: u64,
    stop: u64,
}

static HELP: std::sync::Mutex<std::collections::BTreeMap<String, u64>> = std::sync::Mutex::new(std::collections::BTreeMap::new());
static IN_RUN: std::sync::atomic::AtomicBool = std::sync::atomic::AtomicBool::new(false);
static IN_OP: std::sync::atomic::AtomicBool = std::sync::atomic::AtomicBool::new(false);
static INTERRUPTS: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);

/// Asynchronous interruption: recover the guest state exactly as the kernel
/// does (kemu_materialize) and resume through the dispatcher.
extern "C" fn on_alarm(_sig: i32, _info: *mut libc::siginfo_t, ucv: *mut libc::c_void) {
    use std::sync::atomic::Ordering::SeqCst;
    if !IN_RUN.load(SeqCst) || IN_OP.load(SeqCst) {
        return;
    }
    let uc = unsafe { &mut *(ucv as *mut libc::ucontext_t) };
    let g = &mut uc.uc_mcontext.gregs;
    let rip = g[libc::REG_RIP as usize] as u64;
    let hregs = meta::HostRegs {
        gpr: [
            g[libc::REG_RAX as usize] as u64, g[libc::REG_RCX as usize] as u64,
            g[libc::REG_RDX as usize] as u64, g[libc::REG_RBX as usize] as u64,
            g[libc::REG_RSP as usize] as u64, g[libc::REG_RBP as usize] as u64,
            g[libc::REG_RSI as usize] as u64, g[libc::REG_RDI as usize] as u64,
            g[libc::REG_R8 as usize] as u64, g[libc::REG_R9 as usize] as u64,
            g[libc::REG_R10 as usize] as u64, g[libc::REG_R11 as usize] as u64,
            g[libc::REG_R12 as usize] as u64, g[libc::REG_R13 as usize] as u64,
            g[libc::REG_R14 as usize] as u64, g[libc::REG_R15 as usize] as u64,
        ],
        rflags: g[libc::REG_EFL as usize] as u64,
    };
    let st = state();
    let hh = h();
    if rip >= REGION && rip < REGION + 4096 {
        let info = hh.stubs.info((rip - REGION) as u32);
        if info != stubs::STUB_PAGE_STATE {
            if info == stubs::STUB_PINNED_LIVE_PC_RAX {
                st.pc = hregs.gpr[0];
            }
            meta::pinned_from_host(st, &hregs);
        }
        st.nzcv = nzcv_from_image(st.flags_x86);
    } else if let Some(&(b, sz)) = hh.blocks.iter().find(|(b, sz)| rip >= *b && rip < *b + *sz as u64) {
        let blk = unsafe { std::slice::from_raw_parts(b as *const u8, sz) };
        if !meta::recover(blk, (rip - b) as u32, &hregs, st) {
            let msg = b"recover failed\n";
            unsafe { libc::write(2, msg.as_ptr() as *const _, msg.len()) };
            unsafe { libc::abort() };
        }
    } else {
        return;
    }
    st.flags_x86 = image_from_nzcv(st.nzcv);
    INTERRUPTS.fetch_add(1, SeqCst);
    g[libc::REG_RIP as usize] = (REGION + hh.stubs.dispatch as u64) as i64;
    g[libc::REG_RSP as usize] = (RSTACK_TOP - 64) as i64;
}

fn install_alarm(us: i64) {
    unsafe {
        let mut sa: libc::sigaction = std::mem::zeroed();
        sa.sa_sigaction = on_alarm as usize;
        sa.sa_flags = libc::SA_SIGINFO | libc::SA_RESTART;
        libc::sigaction(libc::SIGALRM, &sa, std::ptr::null_mut());
        let it = libc::itimerval {
            it_interval: libc::timeval { tv_sec: 0, tv_usec: us },
            it_value: libc::timeval { tv_sec: 0, tv_usec: us },
        };
        libc::setitimer(libc::ITIMER_REAL, &it, std::ptr::null_mut());
    }
}

#[no_mangle]
pub extern "C" fn jt_handle_op(op: u32) -> Ret {
    IN_OP.store(true, std::sync::atomic::Ordering::SeqCst);
    let r = jt_handle_op_inner(op);
    IN_OP.store(false, std::sync::atomic::Ordering::SeqCst);
    r
}

fn jt_handle_op_inner(op: u32) -> Ret {
    let st = state();
    match op {
        OP_TRANSLATE | OP_CHAIN => match lookup_or_translate(st.pc) {
            Ok(main) => {
                if op == OP_CHAIN {
                    let site = st.exit_info;
                    let hh = h();
                    if let Some(&(b, sz)) = hh.blocks.iter().find(|(b, sz)| site >= *b && site < *b + *sz as u64) {
                        let blk = unsafe { std::slice::from_raw_parts(b as *const u8, sz) };
                        let hdr = meta::Header::read(blk).unwrap();
                        let m = &blk[hdr.meta_off as usize..(hdr.meta_off + hdr.meta_len) as usize];
                        if let Some(e) = meta::find_exit_site(m, (site - b) as u32) {
                            let dest = if e.kind == meta::EXIT_IC { main - main_off_of(main) + meta::IC_OFF as u64 } else { main };
                            let rel = dest.wrapping_sub(site + 4) as i64 as i32;
                            unsafe { (site as *mut i32).write_unaligned(rel) };
                        } else {
                            panic!("chain: unknown exit site {site:#x}");
                        }
                    } else {
                        panic!("chain: site {site:#x} not in a block");
                    }
                }
                Ret { val: main, stop: 0 }
            }
            Err(f) => {
                h().stop = Some(Exit::Fault(f));
                Ret { val: 0, stop: 1 }
            }
        },
        OP_HELPER => {
            h().helpers += 1;
            if std::env::var("HELPSTAT").is_ok() {
                let w = unsafe { (st.pc as *const u32).read() };
                let name = format!("{:?}", decode(w));
                let key = name.split(|c: char| c == ' ' || c == '{').next().unwrap_or("").to_string();
                let key = if key == "Dp1" || key == "Dp2" || key == "Mul" { name.split(", rd").next().unwrap_or("").to_string() } else { key };
                *HELP.lock().unwrap().entry(key).or_insert(0) += 1;
            }
            st.nzcv = nzcv_from_image(st.flags_x86);
            st.fpsr = fpsr_merge(st.fpsr, st.scratch[7] as u32);
            let pc = st.pc;
            let (ex, _) = interp::run(st, &mut UEnv, 1);
            st.flags_x86 = image_from_nzcv(st.nzcv);
            st.scratch[7] = mxcsr_from(st.fpcr, st.fpsr) as u64;
            match ex {
                Exit::Budget | Exit::IcInvalidate(_) if st.pc == pc + 4 => Ret { val: 0, stop: 0 },
                e => {
                    h().stop = Some(e);
                    Ret { val: 0, stop: 1 }
                }
            }
        }
        OP_SVC => {
            h().stop = Some(Exit::Svc);
            Ret { val: 0, stop: 1 }
        }
        _ => panic!("bad op {op:#x}"),
    }
}

fn reset_cache() {
    let hh = h();
    hh.map.clear();
    hh.blocks.clear();
    hh.code_used = 4096;
    let miss = REGION + hh.stubs.miss as u64;
    for e in table().iter_mut() {
        *e = miss;
    }
}

/// Run guest code at GUEST from `init` under the JIT until it stops.
fn run_jit(init: &CpuState) -> (CpuState, Option<Exit>) {
    let st = state();
    *st = *init;
    st.pc = GUEST;
    st.flags_x86 = image_from_nzcv(init.nzcv);
    st.scratch[7] = mxcsr_from(init.fpcr, init.fpsr) as u64;
    st.host_rsp_top = RSTACK_TOP - 64;
    // Return-stack underflow sentinels.
    for i in 0..8 {
        unsafe { ((RSTACK_TOP - 64 + i * 8) as *mut u64).write(REGION + h().stubs.dispatch_rax as u64) };
    }
    h().stop = None;
    IN_RUN.store(true, std::sync::atomic::Ordering::SeqCst);
    unsafe { jt_enter(RSTACK_TOP - 64, REGION + h().stubs.dispatch as u64) };
    IN_RUN.store(false, std::sync::atomic::Ordering::SeqCst);
    let mut out = *st;
    out.fpsr = fpsr_merge(out.fpsr, out.scratch[7] as u32);
    // After a helper stop, nzcv is authoritative; otherwise the image is.
    if !matches!(h().stop, Some(Exit::Brk(_)) | Some(Exit::Undefined(_)) | Some(Exit::Fault(_))) {
        out.nzcv = nzcv_from_image(out.flags_x86);
    }
    (out, h().stop)
}

fn run_interp(init: &CpuState) -> (CpuState, Exit) {
    let mut st = *init;
    st.pc = GUEST;
    loop {
        let (ex, _) = interp::run(&mut st, &mut UEnv, 10_000_000);
        match ex {
            Exit::Budget => panic!("interp ran away"),
            e => return (st, e),
        }
    }
}

// ---- random generation ----

struct Rng(u64);
impl Rng {
    fn next(&mut self) -> u64 {
        self.0 ^= self.0 << 13;
        self.0 ^= self.0 >> 7;
        self.0 ^= self.0 << 17;
        self.0
    }
    fn below(&mut self, n: u64) -> u64 {
        self.next() % n
    }
    fn val(&mut self) -> u64 {
        match self.below(8) {
            0 => 0,
            1 => u64::MAX,
            2 => 0x8000_0000_0000_0000,
            3 => 0x7fff_ffff_ffff_ffff,
            4 => self.below(256),
            5 => 0xffff_ffff,
            6 => 0x8000_0000 + self.below(3),
            _ => self.next(),
        }
    }
}

fn is_alu(i: &Insn) -> bool {
    matches!(
        i,
        Insn::AddSubImm { .. }
            | Insn::LogicImm { .. }
            | Insn::MovN { .. }
            | Insn::MovZ { .. }
            | Insn::MovK { .. }
            | Insn::Bitfield { .. }
            | Insn::Extr { .. }
            | Insn::AddSubShift { .. }
            | Insn::AddSubExt { .. }
            | Insn::LogicShift { .. }
            | Insn::AddSubCarry { .. }
            | Insn::CondCmp { .. }
            | Insn::CondSel { .. }
            | Insn::Dp1 { .. }
            | Insn::Dp2 { .. }
            | Insn::Mul { .. }
            | Insn::Adr { .. }
            | Insn::Adrp { .. }
    )
}

fn gen_alu(r: &mut Rng) -> u32 {
    loop {
        let op0 = [0b1000u32, 0b1001, 0b0101, 0b1101][r.below(4) as usize];
        let w = (r.next() as u32 & !(0xf << 25)) | (op0 << 25);
        if is_alu(&decode(w)) {
            return w;
        }
    }
}

/// Memory op with base in {x20, x22, sp}; offsets keep accesses in DATA.
fn gen_mem(r: &mut Rng) -> u32 {
    loop {
        let op0 = [0b0100u32, 0b0110, 0b1100, 0b1110][r.below(4) as usize];
        let mut w = (r.next() as u32 & !(0xf << 25)) | (op0 << 25);
        let base = [20u32, 22, 31][r.below(3) as usize];
        w = (w & !(31 << 5)) | (base << 5);
        let i = decode(w);
        let off_ok = match i {
            Insn::LdSt { offset, .. } | Insn::LdStPair { offset, .. } => offset.abs() < 0x7000,
            _ => true,
        };
        if !off_ok {
            continue;
        }
        let ok = match i {
            Insn::LdSt { fp: false, rt, rn, index, .. } => {
                !(matches!(index, kemu_core::decode::Index::Pre | kemu_core::decode::Index::Post) && rt == rn)
            }
            Insn::LdStPair { fp: false, rt, rt2, rn, index, load, .. } => {
                rt != rn && rt2 != rn && !(load && rt == rt2) && {
                    let _ = index;
                    true
                }
            }
            Insn::LdStReg { fp: false, .. } => {
                // index register forced to x23 (small value)
                w = (w & !(31 << 16)) | (23 << 16);
                true
            }
            Insn::LdSt { fp: true, .. } | Insn::LdStPair { fp: true, .. } => true,
            Insn::Atomic { rs, rt, rn, .. } => rs != rn && rt != rn,
            Insn::Cas { pair: false, rs, rt, rn, .. } => rs != rn && rt != rn,
            Insn::LdStExcl { pair: false, rs, rt, rn, load, .. } => rt != rn && (load || (rs != rn && rs != rt)),
            Insn::SimdLdSt { single, replicate, rm, .. } => (!single || replicate) && (rm == 31 || rm == 23),
            _ => false,
        };
        if ok {
            // Re-decode in case we patched rm.
            let i2 = decode(w);
            if matches!(i2, Insn::Undefined) {
                continue;
            }
            // Writes to the base registers would break later accesses.
            let writes_base = match i2 {
                Insn::LdSt { load: true, rt, fp: false, .. } => rt == 20 || rt == 22 || rt == 23,
                Insn::LdStReg { load: true, rt, fp: false, .. } => rt == 20 || rt == 22 || rt == 23,
                Insn::LdStPair { load: true, rt, rt2, fp: false, .. } => [rt, rt2].iter().any(|x| *x == 20 || *x == 22 || *x == 23),
                Insn::Atomic { rt, .. } => rt == 20 || rt == 22 || rt == 23,
                Insn::Cas { rs, .. } => rs == 20 || rs == 22 || rs == 23,
                Insn::LdStExcl { load, rt, rs, .. } => {
                    (load && (rt == 20 || rt == 22 || rt == 23)) || (!load && (rs == 20 || rs == 22 || rs == 23))
                }
                _ => false,
            };
            if !writes_base {
                return w;
            }
        }
    }
}

static mut MAXLEN: u64 = 24;

fn alu_safe(r: &mut Rng) -> u32 {
    loop {
        let w = gen_alu(r);
        let rd = w & 31;
        if ![16, 17, 30, 31].contains(&rd) {
            return w;
        }
    }
}

/// Calls, returns and indirect branches with a known layout.
fn gen_calls(r: &mut Rng) -> Vec<u32> {
    let mut v: Vec<u32> = Vec::new();
    let mut fix: Vec<(usize, &'static str)> = Vec::new();
    let mut alu = |v: &mut Vec<u32>, r: &mut Rng, n: u64| {
        for _ in 0..r.below(n + 1) {
            v.push(alu_safe(r));
        }
    };
    alu(&mut v, r, 4);
    fix.push((v.len(), "bl_f"));
    v.push(0);
    alu(&mut v, r, 3);
    fix.push((v.len(), "adr16_f"));
    v.push(0);
    v.push(0xd63f0200); // blr x16
    alu(&mut v, r, 3);
    fix.push((v.len(), "adr17_after"));
    v.push(0);
    v.push(0xd61f0220); // br x17
    let after = v.len();
    alu(&mut v, r, 3);
    fix.push((v.len(), "bl_f"));
    v.push(0);
    fix.push((v.len(), "b_end"));
    v.push(0);
    let f = v.len();
    alu(&mut v, r, 5);
    v.push(0xd65f03c0); // ret
    let end = v.len();
    v.push(0xd420_0000);
    for (at, what) in fix {
        let off = |t: usize| (t as i64 - at as i64) as i32;
        v[at] = match what {
            "bl_f" => 0x9400_0000 | (off(f) as u32 & 0x3ff_ffff),
            "b_end" => 0x1400_0000 | (off(end) as u32 & 0x3ff_ffff),
            "adr16_f" | "adr17_after" => {
                let (rd, t) = if what == "adr16_f" { (16, f) } else { (17, after) };
                let b = off(t) * 4;
                0x1000_0000 | (((b & 3) as u32) << 29) | ((((b >> 2) as u32) & 0x7ffff) << 5) | rd
            }
            _ => unreachable!(),
        };
    }
    v
}

/// A counted loop around random ALU/memory ops (x24 = counter).
fn gen_loop(r: &mut Rng) -> Vec<u32> {
    let mut v = vec![0xd280_fa18u32]; // mov x24, #2000
    let body = 1 + r.below(12) as usize;
    for _ in 0..body {
        let w = loop {
            let w = if r.below(3) == 0 { gen_mem(r) } else { gen_alu(r) };
            let i = decode(w);
            let rd = w & 31;
            let bad_rd = [20, 22, 23, 24, 31].contains(&rd);
            let writes_rt = matches!(i, Insn::LdSt { load: true, .. } | Insn::LdStPair { load: true, .. } | Insn::LdStReg { load: true, .. } | Insn::Atomic { .. } | Insn::Cas { .. });
            let touches24 = [w & 31, (w >> 10) & 31, (w >> 16) & 31].contains(&24);
            if !bad_rd && !(writes_rt && rd == 24) && !touches24 {
                // memory ops with writeback walk the base; keep them in bounds
                let wb = matches!(i, Insn::LdSt { index: kemu_core::decode::Index::Pre | kemu_core::decode::Index::Post, .. } | Insn::LdStPair { index: kemu_core::decode::Index::Pre | kemu_core::decode::Index::Post, .. } | Insn::SimdLdSt { post: true, .. });
                if !wb {
                    break w;
                }
            }
        };
        v.push(w);
    }
    v.push(0xf100_0718); // subs x24, x24, #1
    let off = -(body as i32 + 1);
    v.push(0x5400_0001 | (((off as u32) & 0x7ffff) << 5)); // b.ne loop
    v.push(0xd420_0000);
    v
}

fn gen_case(r: &mut Rng, mode: u32) -> Vec<u32> {
    if mode == 4 {
        return gen_calls(r);
    }
    if mode == 5 {
        return gen_loop(r);
    }
    let n = 1 + r.below(unsafe { MAXLEN }) as usize;
    let mut v = Vec::new();
    if mode == 6 {
        v.push(0xeb01_001f); // cmp x0, x1: keep live host flags across SHA256
    }
    for k in 0..n {
        let w = match mode {
            0 => gen_alu(r),
            1 => gen_mem(r),
            3 => gen_fp(r),
            6 => gen_sha256(r),
            _ => {
                // mixed with forward branches
                match r.below(6) {
                    0 if k + 2 < n => {
                        // b.cond / cbz / tbz forward by 1..=(n-k-1)
                        let off = 1 + r.below((n - k - 1) as u64) as i32;
                        match r.below(3) {
                            0 => 0x5400_0000 | (((off as u32) & 0x7ffff) << 5) | r.below(15) as u32,
                            1 => 0x3400_0000 | (r.below(2) as u32) << 31 | (r.below(2) as u32) << 24 | (((off as u32) & 0x7ffff) << 5) | r.below(31) as u32,
                            _ => 0x3600_0000 | (r.below(2) as u32) << 31 | (r.below(2) as u32) << 24 | (r.below(32) as u32) << 19 | (((off as u32) & 0x3fff) << 5) | r.below(31) as u32,
                        }
                    }
                    1 => gen_mem(r),
                    _ => {
                        // keep the memory base registers (x20, x22, x23, sp) intact
                        let mut w;
                        loop {
                            w = gen_alu(r);
                            let rd = w & 31;
                            if ![20, 22, 23, 31].contains(&rd) {
                                break;
                            }
                        }
                        w
                    }
                }
            }
        };
        v.push(w);
    }
    if mode == 6 {
        v.push(0x9a88_00e6 | ((r.below(14) as u32) << 12)); // csel x6,x7,x8,cond
    }
    v.push(0xd420_0000); // brk #0
    v
}

fn is_fp(i: &Insn) -> bool {
    matches!(
        i,
        Insn::FpImm { .. }
            | Insn::Fp1 { .. }
            | Insn::Fp2 { .. }
            | Insn::Fp3 { .. }
            | Insn::FpCmp { .. }
            | Insn::FpCSel { .. }
            | Insn::FpCvt { .. }
            | Insn::SimdThree { .. }
            | Insn::SimdMisc { .. }
            | Insn::SimdDup { .. }
            | Insn::SimdModImm { .. }
            | Insn::SimdShift { .. }
            | Insn::SimdExt { .. }
            | Insn::SimdUmov { .. }
            | Insn::SimdInsGpr { .. }
            | Insn::SimdInsElt { .. }
            | Insn::SimdPermute { .. }
    )
}

fn gen_fp(r: &mut Rng) -> u32 {
    loop {
        let w = (r.next() as u32 & !(0x7 << 25)) | (0x7 << 25);
        let i = decode(w);
        if is_fp(&i) {
            return w;
        }
    }
}

/// SHA256H/H2/SU0/SU1 and vector byte-order reversal, including aliased
/// operands and V31. Mode 6 also
/// requires native lowering: interpreter fallbacks make hashing large
/// files spend millions of kernel entries on individual instructions.
fn gen_sha256(r: &mut Rng) -> u32 {
    let rd = r.below(32) as u32;
    let rn = if r.below(3) == 0 { rd } else { r.below(32) as u32 };
    let rm = if r.below(3) == 0 { rn } else { r.below(32) as u32 };
    match r.below(10) {
        0 => 0x5e00_4000 | (rm << 16) | (rn << 5) | rd,
        1 => 0x5e00_5000 | (rm << 16) | (rn << 5) | rd,
        2 => 0x5e28_2800 | (rn << 5) | rd,
        3 => 0x5e00_6000 | (rm << 16) | (rn << 5) | rd,
        i => {
            // REV64 .8B/.4H/.2S, REV32 .8B/.4H, REV16 .8B, and
            // their Q=1 forms. Q=0 must clear the upper 64 bits.
            let base = [0x0e20_0800, 0x0e60_0800, 0x0ea0_0800,
                        0x2e20_0800, 0x2e60_0800, 0x0e20_1800][(i - 4) as usize];
            base | ((r.below(2) as u32) << 30) | (rn << 5) | rd
        }
    }
}

fn fpval(r: &mut Rng) -> u64 {
    let d: [u64; 12] = [
        0x3ff0000000000000, 0xbff8000000000000, 0x7ff0000000000000, 0xfff0000000000000,
        0x7ff8000000000001, 0x7ff4000000000000, 0x0000000000000001, 0x8000000000000000,
        0x4059000000000000, 0x41dfffffffc00000, 0x43e0000000000000, 0xc1e0000000200000,
    ];
    let s: [u64; 8] = [0x3f800000, 0xbfc00000, 0x7f800000, 0x7fc00001, 0x7fa00000, 0x00000001, 0x80000000, 0x4f000000];
    match r.below(4) {
        0 => d[r.below(12) as usize],
        1 => s[r.below(8) as usize] | (s[r.below(8) as usize] << 32),
        2 => r.next(),
        _ => (r.next() & 0x800f_ffff_ffff_ffff) | (0x3fe0u64 + r.below(0x40)) << 52,
    }
}

fn init_state(r: &mut Rng) -> CpuState {
    let mut s = CpuState::new();
    for i in 0..31 {
        s.x[i] = r.val();
    }
    s.x[20] = DATA + 0x8000;
    s.x[22] = DATA + 0x8000 + 8 * r.below(16);
    s.x[23] = 8 * r.below(8);
    s.sp = DATA + 0x8000;
    s.nzcv = (r.below(16)) << 28;
    for i in 0..32 {
        s.v[i] = [fpval(r), fpval(r)];
    }
    s.fpcr = (r.below(4) as u32) << 22;
    s
}

fn main() {
    let args: Vec<String> = std::env::args().collect();
    let iters: u64 = args.get(1).and_then(|s| s.parse().ok()).unwrap_or(100_000);
    let seed: u64 = args.get(2).and_then(|s| s.parse().ok()).unwrap_or(0x1234_5678_9abc_def1);
    let only_mode: Option<u32> = args.get(3).and_then(|s| s.parse().ok());
    let maxlen: u64 = args.get(4).and_then(|s| s.parse().ok()).unwrap_or(24);
    unsafe { MAXLEN = maxlen };

    map_fixed(REGION, CODE_SIZE, 7);
    map_fixed(TABLE, TABLE_ENTRIES * 8, 3);
    map_fixed(STATE, 4096 + RSTACK_SIZE, 3);
    map_fixed(GUEST, GUEST_SIZE, 3);
    map_fixed(DATA, DATA_SIZE, 3);
    unsafe {
        assert_eq!(arch_prctl(0x1001 /* ARCH_SET_GS */, STATE), 0);
    }
    let t = kemu_core::jit::regmap::crc32_table();
    for (i, v) in t.iter().enumerate() {
        unsafe { ((STATE + 2048 + 4 * i as u64) as *mut u32).write(*v) };
    }
    let stub_buf = unsafe { std::slice::from_raw_parts_mut(REGION as *mut u8, 4096) };
    let so = stubs::gen_stubs(stub_buf, ExitMode::Call(jt_harness_entry as u64), TABLE, ((TABLE_ENTRIES - 1) << 3) as u32).unwrap();
    unsafe {
        H = Some(Harness {
            stubs: so,
            code_used: 4096,
            map: HashMap::new(),
            blocks: Vec::new(),
            scratch: Box::new(Scratch::new()),
            stop: None,
            translations: 0,
            helpers: 0,
        });
    }

    if let Some(us) = std::env::var("INTR").ok().and_then(|v| v.parse().ok()) {
        install_alarm(us);
    }
    let mut rng = Rng(seed);
    let mut data_init = vec![0u8; DATA_SIZE];
    let mut fails = 0;
    let mut shown = 0;
    let mut fpsr_diffs = 0;
    let mut classes: HashMap<String, usize> = HashMap::new();
    for it in 0..iters {
        let mode = only_mode.unwrap_or((it % 3) as u32);
        let code = gen_case(&mut rng, mode);
        let init = init_state(&mut rng);
        for b in data_init.iter_mut() {
            *b = rng.next() as u8;
        }
        if let Some(only) = std::env::var("ONLY").ok().and_then(|v| v.parse::<u64>().ok()) {
            if it != only {
                continue;
            }
        }
        let data = unsafe { std::slice::from_raw_parts_mut(DATA as *mut u8, DATA_SIZE) };
        let gcode = unsafe { std::slice::from_raw_parts_mut(GUEST as *mut u32, code.len()) };
        gcode.copy_from_slice(&code);

        data.copy_from_slice(&data_init);
        let (ref_st, ref_ex) = run_interp(&init);
        let ref_data = data.to_vec();

        data.copy_from_slice(&data_init);
        reset_cache();
        let helpers_before = h().helpers;
        let (jit_st, jit_ex) = run_jit(&init);
        if std::env::var("ONLY").is_ok() {
            for (k, &(b, sz)) in h().blocks.iter().enumerate() {
                let code = unsafe { std::slice::from_raw_parts(b as *const u8, sz) };
                std::fs::write(format!("/tmp/claude-1000/blk{k}.bin"), code).unwrap();
            }
            println!("init x: {:x?} sp {:x} nzcv {:x}", init.x, init.sp, init.nzcv);
        }

        let mut bad = Vec::new();
        if mode == 6 && h().helpers - helpers_before != 1 {
            // The terminating BRK is the only expected helper.
            bad.push(format!("SHA256 fallback: {} helper calls", h().helpers - helpers_before));
        }
        for i in 0..31 {
            if ref_st.x[i] != jit_st.x[i] {
                bad.push(format!("x{i}: ref {:#x} jit {:#x}", ref_st.x[i], jit_st.x[i]));
            }
        }
        if ref_st.sp != jit_st.sp {
            bad.push(format!("sp: ref {:#x} jit {:#x}", ref_st.sp, jit_st.sp));
        }
        if ref_st.pc != jit_st.pc {
            bad.push(format!("pc: ref {:#x} jit {:#x}", ref_st.pc, jit_st.pc));
        }
        // NZCV is only exact at a fault if the flags are live there
        // (dead flags are not materialized; documented deviation).
        let faulted = matches!(ref_ex, Exit::Fault(_));
        if ref_st.nzcv != jit_st.nzcv && !faulted {
            bad.push(format!("nzcv: ref {:#x} jit {:#x}", ref_st.nzcv, jit_st.nzcv));
        }
        for i in 0..32 {
            if ref_st.v[i] != jit_st.v[i] {
                bad.push(format!("v{i}: ref {:x?} jit {:x?}", ref_st.v[i], jit_st.v[i]));
            }
        }
        if ref_data != data {
            let k = (0..DATA_SIZE).find(|&k| ref_data[k] != data[k]).unwrap();
            bad.push(format!("mem differs at +{k:#x}"));
        }
        if format!("{:?}", Some(ref_ex)) != format!("{:?}", jit_ex) {
            bad.push(format!("exit: ref {ref_ex:?} jit {jit_ex:?}"));
        }
        if ref_st.fpsr != jit_st.fpsr {
            fpsr_diffs += 1;
            if mode == 6 {
                bad.push(format!("SHA256 changed FPSR: ref {:#x} jit {:#x}", ref_st.fpsr, jit_st.fpsr));
            }
        }
        if mode == 6 && ref_st.fpcr != jit_st.fpcr {
            bad.push(format!("SHA256 changed FPCR: ref {:#x} jit {:#x}", ref_st.fpcr, jit_st.fpcr));
        }
        if !bad.is_empty() {
            for w in &code {
                let name = format!("{:?}", decode(*w));
                let key = name.split(|c: char| c == ' ' || c == '{').next().unwrap_or("").to_string();
                *classes.entry(key).or_insert(0usize) += 1;
            }
            fails += 1;
            let show = std::env::var("SHOW").ok();
            let matches = match &show {
                Some(c) => code.iter().any(|w| format!("{:?}", decode(*w)).starts_with(c.as_str())),
                None => true,
            };
            if matches && { shown += 1; shown } <= 10 {
                println!("FAIL case {it} (mode {mode}):");
                for w in &code {
                    println!("  {:08x}  {:?}", w, decode(*w));
                }
                println!("  init nzcv {:#x}", init.nzcv);
                for b in &bad {
                    println!("  {b}");
                }
            }
        }
    }
    let mut cv: Vec<_> = classes.into_iter().collect();
    cv.sort_by(|a, b| b.1.cmp(&a.1));
    println!("classes in failing cases: {:?}", cv);
    println!("fpsr differences (not counted as failures): {fpsr_diffs}");
    if std::env::var("HELPSTAT").is_ok() {
        let mut v: Vec<_> = HELP.lock().unwrap().clone().into_iter().collect();
        v.sort_by(|a, b| b.1.cmp(&a.1));
        println!("helper instructions: {:?}", &v[..v.len().min(15)]);
    }
    println!("async interruptions recovered: {}", INTERRUPTS.load(std::sync::atomic::Ordering::SeqCst));
    let hh = h();
    println!(
        "{iters} cases, {fails} failures; {} translations, {} helper calls",
        hh.translations, hh.helpers
    );
    std::process::exit(if fails == 0 { 0 } else { 1 });
}
