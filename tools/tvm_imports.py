"""
tvm_imports.py -- what does the protected section actually call?

.tvm0 code cannot be linearly disassembled reliably, but the two dominant
import-access encodings are unambiguous byte patterns:

   FF 15 disp32   call qword ptr [rip+disp]
   FF 25 disp32   jmp  qword ptr [rip+disp]
   48 8B 05 d32   mov  rax, qword ptr [rip+disp]
   4C 8B 05 d32   mov  r8,  qword ptr [rip+disp]

Every rip-relative reference that lands inside the IAT (0x2F000..0x2F2A0) is a
resolved import.  Grouping them per 0x1000 page shows which protected region
belongs to which subsystem.
"""
from __future__ import annotations

import json
import os
import struct
import sys
from collections import Counter, defaultdict

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from pe_model import PEFile  # noqa: E402

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
OUT = os.path.join(ROOT, "out")
TARGET = r"<TARGET_SYS>"


def main():
    pe = PEFile(TARGET)
    model = json.load(open(os.path.join(OUT, "model.json"), encoding="utf-8"))
    iat = {int(k, 16): v for k, v in model["iat"].items()}
    iat_lo, iat_hi = min(iat), max(iat) + 8

    tv = [s for s in pe.sections if s["name"] == ".tvm0"][0]
    blob = pe.data[tv["raw_ptr"] : tv["raw_ptr"] + tv["raw_size"]]
    base = tv["va"]

    per_page = defaultdict(Counter)
    per_page_sites = defaultdict(list)
    total = Counter()

    for i in range(len(blob) - 7):
        op = None
        disp_off = None
        if blob[i] == 0xFF and blob[i + 1] in (0x15, 0x25):
            op = "call" if blob[i + 1] == 0x15 else "jmp"
            disp_off = i + 2
        elif blob[i] in (0x48, 0x4C) and blob[i + 1] == 0x8B and blob[i + 2] == 0x05:
            op = "mov"
            disp_off = i + 3
        if op is None:
            continue
        disp = struct.unpack_from("<i", blob, disp_off)[0]
        nxt = base + disp_off + 4
        tgt = nxt + disp
        if iat_lo <= tgt < iat_hi:
            api = iat.get(tgt - (tgt % 8))
            if api is None:
                continue
            page = (base + i) // 0x1000 * 0x1000
            per_page[page][api] += 1
            total[api] += 1
            per_page_sites[page].append((base + i, op, api))

    print(f"import references found in .tvm0: {sum(total.values())} "
          f"({len(total)} distinct APIs)")
    print("\n== per page (top pages) ==")
    for page, c in sorted(per_page.items(), key=lambda kv: -sum(kv[1].values()))[:18]:
        top = ", ".join(f"{a.split('!')[-1]}({n})" for a, n in c.most_common(5))
        print(f"  {page:#08x}  refs={sum(c.values()):4d}  {top}")

    print("\n== APIs used inside .tvm0 ==")
    for api, n in total.most_common(40):
        print(f"  {n:4d}  {api}")

    json.dump(dict(pages={hex(k): dict(v) for k, v in per_page.items()},
                   total=dict(total)),
              open(os.path.join(OUT, "tvm_imports.json"), "w"), indent=1)


if __name__ == "__main__":
    main()
