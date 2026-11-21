"""
sha_match.py -- match each aux command against the SHA-256 round primitives.

SHA-256 (FIPS 180-4) uses four shift/rotate patterns:
    sigma0(x) = ROTR7(x)  ^ ROTR18(x) ^ SHR3(x)
    sigma1(x) = ROTR17(x) ^ ROTR19(x) ^ SHR10(x)
    Sigma0(x) = ROTR2(x)  ^ ROTR13(x) ^ ROTR22(x)
    Sigma1(x) = ROTR6(x)  ^ ROTR11(x) ^ ROTR25(x)
plus Ch / Maj which use and/xor/or only.

The tool collects the shift amounts used in each aux handler and reports which
primitive the set matches.
"""
from __future__ import annotations

import json
import os
import re
import sys
from collections import Counter

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import trace as tracer  # noqa: E402

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
OUT = os.path.join(ROOT, "out")
AUX_BASE = 0x623782AB
SITES = {2: 0x641A5, 3: 0x64543, 4: 0x648D0, 5: 0x63B5B, 6: 0x64DAD, 7: 0x65541,
         8: 0x69508, 9: 0x66DCF, 10: 0x67B92, 11: 0x681E3, 12: 0x67086, 13: 0x676FD,
         17: 0x65DE2, 18: 0x665AE, 19: 0x6687B, 20: 0x69C31, 21: 0x698F4,
         22: 0x6901B, 25: 0x6881E, 28: 0x68D8D, 29: 0x6A259, 30: 0x6A687}

PRIMS = {
    "sigma0 (SHA-256 msg sched)": {7, 18, 3},
    "sigma1 (SHA-256 msg sched)": {17, 19, 10},
    "Sigma0 (SHA-256 round)": {2, 13, 22},
    "Sigma1 (SHA-256 round)": {6, 11, 25},
    "SHA-512 sigma0": {1, 8, 7},
    "SHA-512 sigma1": {19, 61, 6},
    "SHA-512 Sigma0": {28, 34, 39},
    "SHA-512 Sigma1": {14, 18, 41},
}

SHIFT = re.compile(r"(?:ror|rol|shr|shl|sar)\s+\w+,\s*(0x[0-9a-f]+|\d+)")


def arm_start(site):
    off = tracer.pe.rva2off(site)
    try:
        insn = next(tracer.MD.disasm(tracer.pe.data[off : off + 15],
                                     tracer.IMAGE_BASE + site))
    except StopIteration:
        return site + 6
    return site + insn.size


def profile(k, budget=220):
    path, _edges = tracer.trace(arm_start(SITES[k]), budget)
    shifts = []
    mnem = Counter()
    for rva, text, note, kind, raw in path:
        mnem[text.split(" ")[0]] += 1
        for m in SHIFT.finditer(text):
            v = m.group(1)
            shifts.append(int(v, 16) if v.startswith("0x") else int(v))
    return shifts, mnem, len(path)


def best_match(shifts):
    s = set(shifts)
    scores = []
    for name, pat in PRIMS.items():
        hit = len(pat & s)
        scores.append((hit, name))
    scores.sort(reverse=True)
    return scores[0] if scores else (0, "-")


def main():
    rows = []
    print(f"{'k':>3s} {'site':>9s} {'insns':>6s}  {'shifts used':40s} best match")
    for k in sorted(SITES):
        shifts, mnem, n = profile(k)
        cnt = Counter(shifts)
        used = ", ".join(f"{v}x{c}" for v, c in sorted(cnt.items()))
        hit, name = best_match(shifts)
        rows.append(dict(k=k, site=SITES[k], shifts=sorted(cnt), match=name, hits=hit,
                         insns=n, mnem=dict(mnem)))
        print(f"{k:3d} {SITES[k]:#09x} {n:6d}  {used[:40]:40s} {name} "
              f"({hit}/3 matches)")
    json.dump(rows, open(os.path.join(OUT, "sha_match.json"), "w"), indent=1)


if __name__ == "__main__":
    main()
