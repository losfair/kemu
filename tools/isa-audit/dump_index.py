#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-2.0
"""Print the encodingindex.xml decode hierarchy (optionally one group)."""
import sys
import xml.etree.ElementTree as ET

root = ET.parse(sys.argv[1]).getroot()
want = sys.argv[2] if len(sys.argv) > 2 else None


def boxes(dec):
    out = []
    if dec is None:
        return ""
    for b in dec.findall("box"):
        hi = int(b.get("hibit"))
        w = int(b.get("width", "1"))
        val = "".join((c.text or "") for c in b.findall("c"))
        out.append("%s[%d:%d]=%s" % (b.get("name"), hi, hi - w + 1, val))
    return " ".join(out)


def walk(n, depth, show):
    tag = n.get("groupname") or n.get("iclass")
    hdr = n.find("header")
    s = show or (want is not None and n.get("groupname") == want) or want is None
    if s:
        print("  " * depth + "%s%s: %s  {%s}" % ("(U) " if n.get("unallocated") else "", tag, hdr.text if hdr is not None else "", boxes(n.find("decode"))))
    for c in n.findall("node"):
        walk(c, depth + 1, s)


for top in root.find("hierarchy").findall("node"):
    walk(top, 0, False)
