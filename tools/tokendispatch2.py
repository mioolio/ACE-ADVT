"""
tokendispatch2.py -- complete token -> compare-site map for every declared token.

Scans .tvm0 for `cmp eax, imm32` (and r8d..r15d forms) whose immediate is a token
of either family, so the dispatch chains for the higher tokens (k>=12) and the
aux family become visible.
"""
from __future__ import annotations

import json
import os
import struct
import sys
from collections import defaultdict

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from pe_model import PEFile  # noqa: E402

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
OUT = os.path.join(ROOT, "out")
TARGET = r"<TARGET_SYS>"
FAMILIES = {0x63AE442D: "main", 0x623782AB: "aux"}


def classify(v):
    for base, name in FAMILIES.items():
        if base <= v <= base + 0x40:
            return name, v - base
    return None, None


def main():
    pe = PEFile(TARGET)
    tv = [s for s in pe.sections if s["name"] == ".tvm0"][0]
    blob = pe.data[tv["raw_ptr"] : tv["raw_ptr"] + tv["raw_size"]]
    base = tv["va"]

    sites = defaultdict(list)
    for i in range(len(blob) - 6):
        val = None
        if blob[i] == 0x3D:
            val = struct.unpack_from("<I", blob, i + 1)[0]
        elif blob[i] == 0x41 and blob[i + 1] == 0x81 and 0xF8 <= blob[i + 2] <= 0xFF:
            val = struct.unpack_from("<I", blob, i + 3)[0]
        elif blob[i] == 0x81 and 0xF8 <= blob[i + 1] <= 0xFF:
            val = struct.unpack_from("<I", blob, i + 2)[0]
        if val is None:
            continue
        fam, k = classify(val)
        if fam:
            sites[(fam, k)].append(base + i)

    print(f"{'family':6s} {'k':>3s}  token        sites")
    for (fam, k) in sorted(sites):
        tok = [b for b, n in FAMILIES.items() if n == fam][0] + k
        print(f"{fam:6s} {k:3d}  0x{tok:08X}  " + ", ".join(f"{s:#08x}" for s in sites[(fam, k)]))
    missing_main = [k for k in range(0, 23) if ("main", k) not in sites]
    print("\nmain tokens without a compare site:", missing_main)
    json.dump({f"{fam}:{k}": [hex(s) for s in v] for (fam, k), v in sites.items()},
              open(os.path.join(OUT, "token_sites_full.json"), "w"), indent=1)


if __name__ == "__main__":
    main()
