#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-2.0
"""Print decode-time UNDEF/NOP conditions per encoding of the given classes."""
import json
import re
import sys

encs = json.load(open(sys.argv[1]))
seen = set()
for grp in sys.argv[2:]:
    for e in encs:
        ps = (e["psname"] or "").split(".")
        if ".".join(ps[1:3]) != grp or e["psname"] in seen:
            continue
        seen.add(e["psname"])
        if any(k in ",".join(e["features"]) for k in ("FP16", "SVE", "SME", "FP8", "BF16", "I8MM", "FHM", "FCMA", "FAMINMAX", "MM", "LUT")):
            continue
        d = re.sub(r"\n\s*EndOfDecode", " EndOfDecode", e["decode"])
        d = re.sub(r"then\n\s*", "then ", d)
        conds = [l.strip() for l in d.split("\n") if "EndOfDecode" in l and "FEAT_AdvSIMD)" not in l and "FEAT_FP)" not in l]
        print("%-28s %s" % (e["name"], " | ".join(conds)))
