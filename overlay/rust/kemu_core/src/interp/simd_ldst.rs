// SPDX-License-Identifier: GPL-2.0
// Advanced SIMD structure loads/stores (LD1-4/ST1-4). Included by simd.rs.

fn ldst_struct<E: Env>(cpu: &mut CpuState, env: &mut E, insn: Insn) -> Step {
    if let Insn::SimdLdSt { load, q, size, opcode, rt, rn, rm, single, index, replicate, selem, post } = insn {
        let base = cpu.xsp(rn);
        let mut addr = base;
        let esize = size;
        let ebytes = 1u64 << esize;
        let mut total: u64 = 0;

        if !single {
            // Multiple structures: `selem` consecutive registers, full vectors.
            let lanes = vbytes(q) >> esize;
            // LD1/ST1 with 2-4 registers: rpt registers, one element each
            // (no interleave); LD2-4/ST2-4: rpt=1, selem interleaved.
            let (rpt, selem) = match opcode {
                0b0010 => (4u32, 1u32),
                0b0110 => (3, 1),
                0b1010 => (2, 1),
                _ => (1, selem as u32),
            };
            for r in 0..rpt {
            for i in 0..lanes {
                for s in 0..selem {
                    let reg = (rt + r + s) & 31;
                    if load {
                        let v = match load_elem(env, addr, esize) {
                            Ok(v) => v,
                            Err(f) => return Step::Exit(Exit::Fault(f)),
                        };
                        let mut vr = cpu.vreg(reg);
                        put_lane(&mut vr, esize, i, v);
                        if i == 0 && !q {
                            vr[1] = 0;
                        }
                        cpu.set_vreg(reg, vr);
                    } else {
                        let v = get_lane(cpu, reg, esize, i);
                        if let Err(f) = store_elem(env, addr, esize, v) {
                            return Step::Exit(Exit::Fault(f));
                        }
                    }
                    addr = addr.wrapping_add(ebytes);
                    total += ebytes;
                }
            }
            }
        } else if replicate {
            // LD1R/LD2R..: load one element and replicate across all lanes.
            let lanes = vbytes(q) >> esize;
            for s in 0..selem as u32 {
                let reg = (rt + s) & 31;
                let v = match load_elem(env, addr, esize) {
                    Ok(v) => v,
                    Err(f) => return Step::Exit(Exit::Fault(f)),
                };
                let mut vr = [0u64; 2];
                for i in 0..lanes {
                    put_lane(&mut vr, esize, i, v);
                }
                cpu.set_vreg(reg, vr);
                addr = addr.wrapping_add(ebytes);
                total += ebytes;
            }
        } else {
            // Single structure: one lane `index` of `selem` registers.
            for s in 0..selem as u32 {
                let reg = (rt + s) & 31;
                if load {
                    let v = match load_elem(env, addr, esize) {
                        Ok(v) => v,
                        Err(f) => return Step::Exit(Exit::Fault(f)),
                    };
                    let mut vr = cpu.vreg(reg);
                    put_lane(&mut vr, esize, index, v);
                    cpu.set_vreg(reg, vr);
                } else {
                    let v = get_lane(cpu, reg, esize, index);
                    if let Err(f) = store_elem(env, addr, esize, v) {
                        return Step::Exit(Exit::Fault(f));
                    }
                }
                addr = addr.wrapping_add(ebytes);
                total += ebytes;
            }
        }

        if post {
            let incr = if rm == 31 { total } else { cpu.xr(rm) };
            cpu.set_xsp(rn, base.wrapping_add(incr));
        }
        Step::Next
    } else {
        Step::Exit(Exit::Undefined(0))
    }
}

fn load_elem<E: Env>(env: &mut E, addr: u64, esize: u8) -> Result<u64, Fault> {
    Ok(match esize {
        0 => env.read_u8(addr)? as u64,
        1 => env.read_u16(addr)? as u64,
        2 => env.read_u32(addr)? as u64,
        _ => env.read_u64(addr)?,
    })
}
fn store_elem<E: Env>(env: &mut E, addr: u64, esize: u8, v: u64) -> Result<(), Fault> {
    match esize {
        0 => env.write_u8(addr, v as u8),
        1 => env.write_u16(addr, v as u16),
        2 => env.write_u32(addr, v as u32),
        _ => env.write_u64(addr, v),
    }
}
