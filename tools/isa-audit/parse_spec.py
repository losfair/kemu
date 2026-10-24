#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-2.0
"""Parse Arm's machine-readable A64 ISA XML into a flat JSON encoding list.

Usage: parse_spec.py <ISA_A64_xml dir> <out.json>

For every instruction (type="instruction", not aliases) and every encoding
it records: name, mnemonic, file, psname (class path), arch_variant feature
expression, fixed mask/value (from the iclass diagram refined by the
encoding's own boxes), should-be bits ((0)/(1)), per-field positions,
field constraints ("!= 000", "IN {..}") and the ASL decode text.
"""
import html
import json
import os
import re
import sys
import xml.etree.ElementTree as ET


def text_of(el):
    return html.unescape("".join(el.itertext()))


def parse_boxes(diag):
    """Return (mask, value, sbmask, sbval, fields{name:(hi,lo)}, constraints[])."""
    mask = val = sbm = sbv = 0
    fields = {}
    cons = []
    for box in diag.findall("box"):
        hi = int(box.get("hibit"))
        width = int(box.get("width", "1"))
        lo = hi - width + 1
        name = box.get("name")
        if name and box.get("usename") == "1":
            fields[name] = (hi, lo)
        c = box.get("constraint")
        if c:
            cons.append((hi, lo, c.strip()))
        bit = hi
        for cell in box.findall("c"):
            span = int(cell.get("colspan", "1"))
            t = (cell.text or "").strip()
            if span == 1 or (span == width and len(t) == span and re.fullmatch(r"[01x]+", t)):
                if span == 1 and t.startswith("!="):
                    cons.append((bit, bit, t))
                elif span == 1:
                    chars = [t] if t else [""]
                    for ch in chars:
                        if ch == "0":
                            mask |= 1 << bit
                        elif ch == "1":
                            mask |= 1 << bit
                            val |= 1 << bit
                        elif ch == "(0)":
                            sbm |= 1 << bit
                        elif ch == "(1)":
                            sbm |= 1 << bit
                            sbv |= 1 << bit
                else:
                    for i, ch in enumerate(t):
                        b = bit - i
                        if ch == "0":
                            mask |= 1 << b
                        elif ch == "1":
                            mask |= 1 << b
                            val |= 1 << b
            else:
                if t.startswith("!=") or t.startswith("IN"):
                    cons.append((bit, bit - span + 1, t))
                elif re.fullmatch(r"[01x]+", t) and len(t) == span:
                    for i, ch in enumerate(t):
                        b = bit - i
                        if ch == "0":
                            mask |= 1 << b
                        elif ch == "1":
                            mask |= 1 << b
                            val |= 1 << b
            bit -= span
    return mask, val, sbm, sbv, fields, cons


def pstext(ps_el, section):
    out = []
    for pt in ps_el.iter("pstext"):
        if pt.get("section") == section:
            out.append(text_of(pt))
    return "\n".join(out)


def main():
    d, outp = sys.argv[1], sys.argv[2]
    encs = []
    for fn in sorted(os.listdir(d)):
        if not fn.endswith(".xml"):
            continue
        path = os.path.join(d, fn)
        with open(path, "rb") as f:
            head = f.read(3000)
        if b'type="instruction"' not in head:
            continue
        root = ET.parse(path).getroot()
        if root.tag != "instructionsection" or root.get("type") != "instruction":
            continue
        # Operation (execute) pseudocode for the whole file.
        execute = ""
        for ps in root.iter("ps"):
            if ps.get("secttype") == "Operation":
                execute += pstext(ps, "Execute") + "\n"
        for ic in root.iter("iclass"):
            diag = ic.find("regdiagram")
            if diag is None or diag.get("form") != "32":
                continue
            m0, v0, sbm, sbv, fields, cons = parse_boxes(diag)
            feat = []
            av = ic.find("arch_variants")
            if av is not None:
                for a in av.findall("arch_variant"):
                    if a.get("feature"):
                        feat.append(a.get("feature"))
            decode = ""
            for ps in ic.iter("ps"):
                decode += pstext(ps, "Decode") + "\n"
            for enc in ic.findall("encoding"):
                m, v = m0, v0
                em, ev, _, _, efields, econs = parse_boxes(enc)
                m |= em
                v = (v & ~em) | ev
                mn = None
                for dv in enc.iter("docvar"):
                    if dv.get("key") == "mnemonic":
                        mn = dv.get("value")
                encs.append({
                    "file": fn,
                    "id": root.get("id"),
                    "title": root.get("title"),
                    "iclass": ic.get("name"),
                    "psname": diag.get("psname"),
                    "name": enc.get("name"),
                    "mnemonic": mn,
                    "features": feat,
                    "mask": m,
                    "value": v,
                    "imask": m0,
                    "ivalue": v0,
                    "sbmask": sbm & ~m,
                    "sbvalue": sbv & ~m,
                    "fields": fields,
                    "constraints": cons + econs,
                    "decode": decode,
                })
        # attach execute text once per file (index by file)
        if encs and encs[-1]["file"] == fn:
            encs[-1]["execute_file"] = execute
    with open(outp, "w") as f:
        json.dump(encs, f, indent=0)
    print(f"{len(encs)} encodings", file=sys.stderr)


if __name__ == "__main__":
    main()
