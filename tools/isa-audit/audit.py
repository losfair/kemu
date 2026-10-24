#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-2.0
"""Encoding-coverage audit of kemu's A64 decoder against the Arm A64 ISA XML.

Usage: audit.py <spec.json> [--per-enc N] [--random N] [--seed S] [--out DIR]

Generates concrete instruction words for every encoding in the spec (random
operand fields plus all-zero/all-one edge values per field), words that are
one fixed-bit flip away from each encoding, and uniformly random words. Each
word is classified by the spec (allocated / UNDEFINED / NOP / unknown, given
kemu's advertised feature set and the ASL decode-time checks), decoded by
kemu (via target/release/decode-words) and compared.

Outputs:
  <out>/mismatch.txt   one line per mismatching word (grouped by encoding)
  <out>/unknown.txt    words whose spec status could not be decided (ASL too
                       complex): to be confirmed under qemu
  <out>/words_<grp>.txt  allocated+advertised words per class (for difftest)
"""
import argparse
import collections
import json
import os
import random
import re
import subprocess
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import asl  # noqa: E402

ADVERTISED = {
    "FEAT_FP", "FEAT_AdvSIMD", "FEAT_AES", "FEAT_PMULL", "FEAT_SHA1",
    "FEAT_SHA256", "FEAT_CRC32", "FEAT_LSE", "FEAT_RDM", "FEAT_JSCVT",
    "FEAT_LRCPC", "FEAT_LRCPC2", "FEAT_DPB", "FEAT_DPB2", "FEAT_DotProd",
    "FEAT_FlagM", "FEAT_FlagM2", "FEAT_SB", "FEAT_FRINTTS", "FEAT_RNG",
}

# Encodings whose EL0 behaviour depends on the system-register / operation
# selector rather than on allocation (checked by hand in sys_check()).
SYSTEM = {"SYS_CR_systeminstrs", "SYSL_RC_systeminstrs", "MRS_RS_systemmove",
          "MSR_SR_systemmove", "MSR_SI_pstate"}
# Allocated, but UNDEFINED when executed at EL0 under Linux.
EL1_ONLY_FILES = {"hvc.xml", "smc.xml", "eret.xml", "eretaa.xml", "dcps1.xml",
                  "dcps2.xml", "dcps3.xml", "drps.xml", "hlt.xml"}
HINT = "HINT_HM_hints"


def group_of(e):
    ps = e["psname"] or ""
    parts = ps.split(".")
    return ".".join(parts[1:3]) if len(parts) >= 3 else ps


def cons_ok(e, w):
    for hi, lo, c in e["constraints"]:
        width = hi - lo + 1
        v = (w >> lo) & ((1 << width) - 1)
        c = c.strip()
        if c.startswith("!="):
            pat = c[2:].strip()
            if len(pat) != width:
                continue
            if asl.Pat(pat).match(asl.Bits(v, width)):
                return False
        elif c.startswith("IN"):
            items = re.findall(r"[01x]+", c)
            if not any(asl.Pat(p).match(asl.Bits(v, width)) for p in items if len(p) == width):
                return False
    return True


class Spec:
    def __init__(self, encs):
        self.encs = encs
        self.buckets = collections.defaultdict(list)
        for idx, e in enumerate(encs):
            mh = (e["mask"] >> 21) & 0x7FF
            vh = (e["value"] >> 21) & 0x7FF
            free = [b for b in range(11) if not (mh >> b) & 1]
            for k in range(1 << len(free)):
                key = vh
                for j, b in enumerate(free):
                    if (k >> j) & 1:
                        key |= 1 << b
                self.buckets[key].append(idx)
        self.cache = {}

    def matches(self, w):
        out = []
        for idx in self.buckets.get((w >> 21) & 0x7FF, ()):
            e = self.encs[idx]
            if (w & e["mask"]) == e["value"] and cons_ok(e, w):
                out.append(idx)
        return out

    def enc_status(self, idx, w):
        e = self.encs[idx]
        st = asl.evaluate(e["decode"], e["fields"], w, ADVERTISED)
        if st == "OK":
            for fx in e["features"]:
                t = asl.eval_feature_expr(fx, ADVERTISED)
                if t is False:
                    return "UNDEF"
                if t is asl.UNKNOWN:
                    return "UNKNOWN"
        return st

    def classify(self, w):
        """Return (status, [matching encoding idx], special)."""
        ms = self.matches(w)
        if not ms:
            return "UNALLOC", ms, None
        sts = {}
        for i in ms:
            sts[i] = self.enc_status(i, w)
        for i in ms:
            if self.encs[i]["name"] in SYSTEM:
                return "SYSTEM", ms, i
        for i in ms:
            if self.encs[i]["name"] == HINT:
                return "NOP", ms, i
        vals = set(sts.values())
        if "OK" in vals:
            ok = [i for i in ms if sts[i] == "OK"]
            if any(self.encs[i]["file"] in EL1_ONLY_FILES for i in ok):
                return "UNDEF", ms, None
            return "OK", ok, None
        if "NOP" in vals:
            return "NOP", ms, None
        if "UNKNOWN" in vals:
            return "UNKNOWN", ms, None
        return "UNDEF", ms, None


def gen_words(e, rng, n):
    free = (~e["mask"] & ~e["sbmask"]) & 0xFFFFFFFF
    base = e["value"] | e["sbvalue"]
    out = set()
    fields = e["fields"]
    tries = 0
    target = n
    # edge values: each field all-0 / all-1 with other bits random
    specials = []
    for name, (hi, lo) in fields.items():
        fm = ((1 << (hi - lo + 1)) - 1) << lo
        fm &= free
        if not fm:
            continue
        specials.append((fm, 0))
        specials.append((fm, fm))
    for fm, fv in specials:
        for _ in range(4):
            w = base | (rng.getrandbits(32) & free & ~fm) | fv
            if cons_ok(e, w):
                out.add(w)
                break
    while len(out) < target + len(specials) and tries < target * 20:
        tries += 1
        w = base | (rng.getrandbits(32) & free)
        if cons_ok(e, w):
            out.add(w)
    if free == 0:
        out.add(base)
    return out


def neighbours(e, rng, n):
    out = set()
    fixed = [b for b in range(32) if (e["mask"] >> b) & 1]
    free = (~e["mask"]) & 0xFFFFFFFF
    for _ in range(n):
        if not fixed:
            break
        b = rng.choice(fixed)
        w = (e["value"] | (rng.getrandbits(32) & free)) ^ (1 << b)
        out.add(w)
    return out


def run_decoder(words, exe):
    p = subprocess.run([exe], input="\n".join("%08x" % w for w in words), capture_output=True, text=True, check=True)
    res = {}
    for line in p.stdout.splitlines():
        a, b = line.split("\t", 1)
        res[int(a, 16)] = b
    return res


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("spec")
    ap.add_argument("--per-enc", type=int, default=24)
    ap.add_argument("--neigh", type=int, default=24)
    ap.add_argument("--random", type=int, default=100000)
    ap.add_argument("--seed", type=int, default=1)
    ap.add_argument("--out", default="out")
    ap.add_argument("--exe", default=os.path.join(os.path.dirname(os.path.abspath(__file__)), "target/release/decode-words"))
    a = ap.parse_args()
    rng = random.Random(a.seed)
    encs = json.load(open(a.spec))
    spec = Spec(encs)
    words = set()
    per_enc = collections.defaultdict(set)
    for i, e in enumerate(encs):
        ws = gen_words(e, rng, a.per_enc)
        per_enc[i] |= ws
        words |= ws
        words |= neighbours(e, rng, a.neigh)
    for _ in range(a.random):
        words.add(rng.getrandbits(32))
    words = sorted(words)
    print("words: %d" % len(words), file=sys.stderr)
    dec = run_decoder(words, a.exe)
    os.makedirs(a.out, exist_ok=True)
    mism = collections.defaultdict(list)
    unknown = []
    sysw = []
    stats = collections.Counter()
    alloc_words = collections.defaultdict(list)
    enc_checked = collections.Counter()
    for w in words:
        st, ms, sp = spec.classify(w)
        d = dec[w]
        is_undef = d == "Undefined"
        stats[st] += 1
        if st == "OK":
            names = ",".join(sorted({encs[i]["name"] for i in ms}))
            for i in ms:
                enc_checked[i] += 1
            if is_undef:
                mism[names].append((w, "spec allocated, kemu Undefined", d))
            else:
                alloc_words[group_of(encs[ms[0]])].append((w, names, d))
        elif st in ("UNDEF", "UNALLOC"):
            if not is_undef:
                names = ",".join(sorted({encs[i]["name"] for i in ms})) or "<unallocated>"
                mism[names].append((w, "spec %s, kemu decodes" % st, d))
        elif st == "NOP":
            if d != "Nop":
                names = ",".join(sorted({encs[i]["name"] for i in ms}))
                mism[names].append((w, "spec NOP, kemu", d))
        elif st == "SYSTEM":
            sysw.append((w, encs[sp]["name"], d))
        else:
            names = ",".join(sorted({encs[i]["name"] for i in ms}))
            unknown.append((w, names, d))
    with open(os.path.join(a.out, "mismatch.txt"), "w") as f:
        for names in sorted(mism, key=lambda k: -len(mism[k])):
            lst = mism[names]
            f.write("== %s (%d)\n" % (names, len(lst)))
            for w, why, d in lst[:6]:
                f.write("  %08x %s: %s\n" % (w, why, d))
    with open(os.path.join(a.out, "unknown.txt"), "w") as f:
        for w, names, d in unknown:
            f.write("%08x\t%s\t%s\n" % (w, names, d))
    with open(os.path.join(a.out, "system.txt"), "w") as f:
        for w, names, d in sysw:
            f.write("%08x\t%s\t%s\n" % (w, names, d))
    with open(os.path.join(a.out, "alloc.txt"), "w") as f:
        for g in sorted(alloc_words):
            for w, names, d in alloc_words[g]:
                f.write("%08x\t%s\t%s\t%s\n" % (w, g, names, d))
    # per-encoding coverage of advertised encodings
    with open(os.path.join(a.out, "coverage.txt"), "w") as f:
        for i, e in enumerate(encs):
            f.write("%s\t%s\t%d\n" % (e["name"], group_of(e), enc_checked[i]))
    print("status counts:", dict(stats), file=sys.stderr)
    print("mismatch groups: %d, words: %d" % (len(mism), sum(len(v) for v in mism.values())), file=sys.stderr)
    print("unknown: %d" % len(unknown), file=sys.stderr)


if __name__ == "__main__":
    main()
