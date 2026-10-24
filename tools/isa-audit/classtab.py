#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-2.0
"""Print the encodings of one or more spec classes (psname group) as bit
patterns, with mnemonic and feature, for writing/reviewing decoders."""
import json
import sys

encs = json.load(open(sys.argv[1]))
for grp in sys.argv[2:]:
    print("=====", grp)
    rows = []
    for e in encs:
        ps = (e["psname"] or "").split(".")
        if ".".join(ps[1:3]) != grp:
            continue
        pat = ""
        for b in range(31, -1, -1):
            if (e["mask"] >> b) & 1:
                pat += "1" if (e["value"] >> b) & 1 else "0"
            elif (e["sbmask"] >> b) & 1:
                pat += "(" + ("1" if (e["sbvalue"] >> b) & 1 else "0") + ")"
            else:
                pat += "."
            if b in (31, 29, 24, 21, 16, 10, 5):
                pat += " "
        cons = " ".join("%d:%d%s" % (h, l, c) for h, l, c in e["constraints"])
        rows.append((pat, e["name"], ",".join(e["features"]), cons))
    for r in sorted(rows):
        print("%s  %-32s %-30s %s" % r)
