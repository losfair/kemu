// SPDX-License-Identifier: GPL-2.0
//! arm64 -> host (x86-64) syscall forwarding for the interpreter harness.
//!
//! Returns `Some(exit_code)` to terminate the process, else `None`.

use kemu_core::state::CpuState;
use std::cell::RefCell;
use std::ffi::CString;

thread_local! {
    static SYSROOT: RefCell<Option<String>> = RefCell::new(std::env::var("KEMU_SYSROOT").ok());
    // Keep rewritten CStrings alive for the duration of the syscall.
    static REWRITE_BUF: RefCell<Vec<CString>> = RefCell::new(Vec::new());
}

/// If `KEMU_SYSROOT` is set and `pathptr` is an absolute path whose
/// sysroot-prefixed form exists, return a pointer to a rewritten C string;
/// otherwise return the original pointer. The rewritten string is kept alive
/// in a thread-local until the next rewrite.
fn rewrite_path(pathptr: u64) -> u64 {
    if pathptr == 0 {
        return pathptr;
    }
    let root = match SYSROOT.with(|r| r.borrow().clone()) {
        Some(r) => r,
        None => return pathptr,
    };
    // Read the guest C string.
    let cstr = unsafe { std::ffi::CStr::from_ptr(pathptr as *const libc::c_char) };
    let bytes = cstr.to_bytes();
    if bytes.first() != Some(&b'/') {
        return pathptr; // only rewrite absolute paths
    }
    // Don't rewrite /proc, /sys, /dev (host runtime interfaces the guest shares).
    for pfx in [b"/proc".as_slice(), b"/sys", b"/dev"] {
        if bytes.starts_with(pfx) {
            return pathptr;
        }
    }
    let joined = format!("{}{}", root.trim_end_matches('/'), String::from_utf8_lossy(bytes));
    if !std::path::Path::new(&joined).exists() {
        return pathptr;
    }
    match CString::new(joined) {
        Ok(c) => {
            let ptr = c.as_ptr() as u64;
            REWRITE_BUF.with(|b| {
                let mut v = b.borrow_mut();
                v.clear();
                v.push(c);
            });
            ptr
        }
        Err(_) => pathptr,
    }
}

// arm64 (asm-generic) syscall numbers we handle.
mod nr {
    pub const GETCWD: u64 = 17;
    pub const DUP: u64 = 23;
    pub const DUP3: u64 = 24;
    pub const FCNTL: u64 = 25;
    pub const IOCTL: u64 = 29;
    pub const FACCESSAT: u64 = 48;
    pub const OPENAT: u64 = 56;
    pub const CLOSE: u64 = 57;
    pub const PIPE2: u64 = 59;
    pub const GETDENTS64: u64 = 61;
    pub const LSEEK: u64 = 62;
    pub const READ: u64 = 63;
    pub const WRITE: u64 = 64;
    pub const READV: u64 = 65;
    pub const WRITEV: u64 = 66;
    pub const PREAD64: u64 = 67;
    pub const PWRITE64: u64 = 68;
    pub const READLINKAT: u64 = 78;
    pub const NEWFSTATAT: u64 = 79;
    pub const FSTAT: u64 = 80;
    pub const EXIT: u64 = 93;
    pub const EXIT_GROUP: u64 = 94;
    pub const SET_TID_ADDRESS: u64 = 96;
    pub const FUTEX: u64 = 98;
    pub const SET_ROBUST_LIST: u64 = 99;
    pub const NANOSLEEP: u64 = 101;
    pub const CLOCK_GETTIME: u64 = 113;
    pub const CLOCK_GETRES: u64 = 114;
    pub const CLOCK_NANOSLEEP: u64 = 115;
    pub const SCHED_YIELD: u64 = 124;
    pub const RT_SIGACTION: u64 = 134;
    pub const RT_SIGPROCMASK: u64 = 135;
    pub const RT_SIGRETURN: u64 = 139;
    pub const UNAME: u64 = 160;
    pub const GETPID: u64 = 172;
    pub const GETPPID: u64 = 173;
    pub const GETUID: u64 = 174;
    pub const GETEUID: u64 = 175;
    pub const GETGID: u64 = 176;
    pub const GETEGID: u64 = 177;
    pub const GETTID: u64 = 178;
    pub const SYSINFO: u64 = 179;
    pub const BRK: u64 = 214;
    pub const MUNMAP: u64 = 215;
    pub const MREMAP: u64 = 216;
    pub const MMAP: u64 = 222;
    pub const MPROTECT: u64 = 226;
    pub const MADVISE: u64 = 233;
    pub const PRLIMIT64: u64 = 261;
    pub const GETRANDOM: u64 = 278;
    pub const STATX: u64 = 291;
    pub const RSEQ: u64 = 293;
    pub const FACCESSAT2: u64 = 439;
}

// host x86-64 numbers.
mod hx {
    pub const READ: i64 = 0;
    pub const WRITE: i64 = 1;
    pub const CLOSE: i64 = 3;
    pub const FSTAT: i64 = 5;
    pub const LSEEK: i64 = 8;
    pub const MMAP: i64 = 9;
    pub const MPROTECT: i64 = 10;
    pub const MUNMAP: i64 = 11;
    pub const BRK: i64 = 12;
    pub const RT_SIGACTION: i64 = 13;
    pub const RT_SIGPROCMASK: i64 = 14;
    pub const IOCTL: i64 = 16;
    pub const PREAD64: i64 = 17;
    pub const PWRITE64: i64 = 18;
    pub const READV: i64 = 19;
    pub const WRITEV: i64 = 20;
    pub const DUP: i64 = 32;
    pub const NANOSLEEP: i64 = 35;
    pub const GETPID: i64 = 39;
    pub const EXIT: i64 = 60;
    pub const SCHED_YIELD: i64 = 24;
    pub const MREMAP: i64 = 25;
    pub const MADVISE: i64 = 28;
    pub const FCNTL: i64 = 72;
    pub const GETCWD: i64 = 79;
    pub const GETUID: i64 = 102;
    pub const GETGID: i64 = 104;
    pub const GETEUID: i64 = 107;
    pub const GETEGID: i64 = 108;
    pub const GETPPID: i64 = 110;
    pub const SYSINFO: i64 = 99;
    pub const FUTEX: i64 = 202;
    pub const GETTID: i64 = 186;
    pub const GETDENTS64: i64 = 217;
    pub const SET_TID_ADDRESS: i64 = 218;
    pub const CLOCK_GETTIME: i64 = 228;
    pub const CLOCK_GETRES: i64 = 229;
    pub const CLOCK_NANOSLEEP: i64 = 230;
    pub const EXIT_GROUP: i64 = 231;
    pub const SET_ROBUST_LIST: i64 = 273;
    pub const DUP3: i64 = 292;
    pub const PIPE2: i64 = 293;
    pub const PRLIMIT64: i64 = 302;
    pub const GETRANDOM: i64 = 318;
    pub const STATX: i64 = 332;
    pub const RSEQ: i64 = 334;
    pub const OPENAT: i64 = 257;
    pub const NEWFSTATAT: i64 = 262;
    pub const READLINKAT: i64 = 267;
    pub const FACCESSAT: i64 = 269;
    pub const FACCESSAT2: i64 = 439;
    pub const RT_SIGPROCMASK_UNUSED: i64 = -1;
}

#[inline]
unsafe fn host(nr: i64, a: [u64; 6]) -> i64 {
    libc::syscall(nr as libc::c_long, a[0], a[1], a[2], a[3], a[4], a[5]) as i64
}

/// Returns Some(code) if the process should exit.
pub fn dispatch(cpu: &mut CpuState, trace: bool) -> Option<i32> {
    let nr = cpu.x[8];
    let a = [cpu.x[0], cpu.x[1], cpu.x[2], cpu.x[3], cpu.x[4], cpu.x[5]];

    if trace {
        eprintln!("[kemu] svc nr={} args={:#x?}", nr, &a);
    }

    // Terminations.
    match nr {
        nr::EXIT | nr::EXIT_GROUP => return Some((a[0] & 0xff) as i32),
        nr::RT_SIGRETURN => {
            // No signal-frame support in the harness.
            cpu.x[0] = (-libc::ENOSYS as i64) as u64;
            return None;
        }
        _ => {}
    }

    let ret: i64 = match nr {
        // Identical-semantics pass-throughs (number translation only).
        nr::READ => unsafe { host(hx::READ, a) },
        nr::WRITE => unsafe { host(hx::WRITE, a) },
        nr::READV => unsafe { host(hx::READV, a) },
        nr::WRITEV => unsafe { host(hx::WRITEV, a) },
        nr::PREAD64 => unsafe { host(hx::PREAD64, a) },
        nr::PWRITE64 => unsafe { host(hx::PWRITE64, a) },
        nr::CLOSE => unsafe { host(hx::CLOSE, a) },
        nr::LSEEK => unsafe { host(hx::LSEEK, a) },
        nr::OPENAT => { let mut a = a; a[1] = rewrite_path(a[1]); unsafe { host(hx::OPENAT, a) } }
        nr::IOCTL => unsafe { host(hx::IOCTL, a) },
        nr::FCNTL => unsafe { host(hx::FCNTL, a) },
        nr::DUP => unsafe { host(hx::DUP, a) },
        nr::DUP3 => unsafe { host(hx::DUP3, a) },
        nr::PIPE2 => unsafe { host(hx::PIPE2, a) },
        nr::GETCWD => unsafe { host(hx::GETCWD, a) },
        nr::GETDENTS64 => unsafe { host(hx::GETDENTS64, a) },
        nr::READLINKAT => { let mut a = a; a[1] = rewrite_path(a[1]); unsafe { host(hx::READLINKAT, a) } }
        nr::FACCESSAT => { let mut a = a; a[1] = rewrite_path(a[1]); unsafe { host(hx::FACCESSAT, a) } }
        nr::FACCESSAT2 => { let mut a = a; a[1] = rewrite_path(a[1]); unsafe { host(hx::FACCESSAT2, a) } }
        nr::BRK => unsafe { host(hx::BRK, a) },
        nr::MMAP => unsafe { host(hx::MMAP, a) },
        nr::MUNMAP => unsafe { host(hx::MUNMAP, a) },
        nr::MPROTECT => unsafe { host(hx::MPROTECT, a) },
        nr::MREMAP => unsafe { host(hx::MREMAP, a) },
        nr::MADVISE => unsafe { host(hx::MADVISE, a) },
        nr::GETPID => unsafe { host(hx::GETPID, a) },
        nr::GETPPID => unsafe { host(hx::GETPPID, a) },
        nr::GETTID => unsafe { host(hx::GETTID, a) },
        nr::GETUID => unsafe { host(hx::GETUID, a) },
        nr::GETEUID => unsafe { host(hx::GETEUID, a) },
        nr::GETGID => unsafe { host(hx::GETGID, a) },
        nr::GETEGID => unsafe { host(hx::GETEGID, a) },
        nr::SYSINFO => unsafe { host(hx::SYSINFO, a) },
        nr::SET_TID_ADDRESS => unsafe { host(hx::SET_TID_ADDRESS, a) },
        nr::SET_ROBUST_LIST => unsafe { host(hx::SET_ROBUST_LIST, a) },
        nr::FUTEX => unsafe { host(hx::FUTEX, a) },
        nr::SCHED_YIELD => unsafe { host(hx::SCHED_YIELD, a) },
        nr::NANOSLEEP => unsafe { host(hx::NANOSLEEP, a) },
        nr::CLOCK_GETTIME => unsafe { host(hx::CLOCK_GETTIME, a) },
        nr::CLOCK_GETRES => unsafe { host(hx::CLOCK_GETRES, a) },
        nr::CLOCK_NANOSLEEP => unsafe { host(hx::CLOCK_NANOSLEEP, a) },
        nr::GETRANDOM => unsafe { host(hx::GETRANDOM, a) },
        nr::STATX => { let mut a = a; a[1] = rewrite_path(a[1]); unsafe { host(hx::STATX, a) } }
        nr::PRLIMIT64 => unsafe { host(hx::PRLIMIT64, a) },
        nr::RSEQ => unsafe { host(hx::RSEQ, a) },
        nr::RT_SIGACTION => unsafe { host(hx::RT_SIGACTION, a) },
        nr::RT_SIGPROCMASK => unsafe { host(hx::RT_SIGPROCMASK, a) },

        // Structure-translating syscalls.
        nr::FSTAT => do_fstat(a[0], a[1]),
        nr::NEWFSTATAT => do_fstatat(a[0], rewrite_path(a[1]), a[2], a[3]),

        // Semantically-emulated.
        nr::UNAME => do_uname(a[0]),

        other => {
            if trace {
                eprintln!("[kemu] unimplemented syscall {other}");
            }
            -libc::ENOSYS as i64
        }
    };

    cpu.x[0] = ret as u64;
    None
}

/// arm64 asm-generic `struct stat` is 128 bytes with a different field order
/// than x86-64. Fill it from a host `libc::stat`.
fn write_arm64_stat(st: &libc::stat, dst: u64) {
    // Layout (offsets): dev(0,u64) ino(8,u64) mode(16,u32) nlink(20,u32)
    // uid(24,u32) gid(28,u32) rdev(32,u64) __pad1(40,u64) size(48,i64)
    // blksize(56,i32) __pad2(60) blocks(64,i64) atime(72) atime_ns(80)
    // mtime(88) mtime_ns(96) ctime(104) ctime_ns(112) __unused(120..128)
    unsafe {
        let p = dst as *mut u8;
        core::ptr::write_bytes(p, 0, 128);
        let w64 = |off: usize, v: u64| core::ptr::write_unaligned(p.add(off) as *mut u64, v);
        let w32 = |off: usize, v: u32| core::ptr::write_unaligned(p.add(off) as *mut u32, v);
        w64(0, st.st_dev);
        w64(8, st.st_ino);
        w32(16, st.st_mode);
        w32(20, st.st_nlink as u32);
        w32(24, st.st_uid);
        w32(28, st.st_gid);
        w64(32, st.st_rdev);
        w64(48, st.st_size as u64);
        w32(56, st.st_blksize as u32);
        w64(64, st.st_blocks as u64);
        w64(72, st.st_atime as u64);
        w64(80, st.st_atime_nsec as u64);
        w64(88, st.st_mtime as u64);
        w64(96, st.st_mtime_nsec as u64);
        w64(104, st.st_ctime as u64);
        w64(112, st.st_ctime_nsec as u64);
    }
}

fn do_fstat(fd: u64, dst: u64) -> i64 {
    let mut st: libc::stat = unsafe { core::mem::zeroed() };
    let r = unsafe { libc::syscall(hx::FSTAT, fd, &mut st as *mut _) };
    if r == 0 {
        write_arm64_stat(&st, dst);
    }
    r as i64
}

fn do_fstatat(dirfd: u64, path: u64, dst: u64, flags: u64) -> i64 {
    let mut st: libc::stat = unsafe { core::mem::zeroed() };
    let r = unsafe { libc::syscall(hx::NEWFSTATAT, dirfd, path, &mut st as *mut _, flags) };
    if r == 0 {
        write_arm64_stat(&st, dst);
    }
    r as i64
}

fn do_uname(dst: u64) -> i64 {
    // struct utsname: 6 fields x 65 bytes = 390 (SYSNAME..DOMAINNAME).
    let fields: [&[u8]; 6] = [
        b"Linux",
        b"kemu-guest",
        b"6.18.0-kemu",
        b"#1 SMP kemu",
        b"aarch64",
        b"(none)",
    ];
    unsafe {
        let p = dst as *mut u8;
        core::ptr::write_bytes(p, 0, 6 * 65);
        for (i, f) in fields.iter().enumerate() {
            let off = i * 65;
            let n = f.len().min(64);
            core::ptr::copy_nonoverlapping(f.as_ptr(), p.add(off), n);
        }
    }
    0
}
