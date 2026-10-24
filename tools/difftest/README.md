# difftest — AArch64 interpreter differential tester

Compares the `kemu_core` interpreter against `qemu-aarch64` (the oracle) on
randomly generated instructions. For each case it builds a random architectural
state, runs one instruction in the interpreter and natively under QEMU (by
assembling a tiny program that loads the state, executes the instruction, and
dumps the result), and compares X/SP/NZCV/FPSR/V bit-for-bit. Trapping
encodings are isolated per-case.

Usage:
    ./run.sh -n <cases> -b <batch> -c <class> [-c <class> ...]
    ./run.sh -i 0x<insn> -n <cases>     # test one fixed encoding

Classes: addsub_{imm,shift,ext}, logical_{imm,shift}, movewide, bitfield,
extract, condsel, condcmp, dp1, dp2, dp3, fp2src, fp1src, fpcvtint, fpcmp,
fpcsel, simd_{three,misc,dup,shift,modimm}, ldr_{imm,pair,reg}.

Requires: aarch64-linux-gnu-gcc, qemu-aarch64, rust 1.88.
