"""
jtable.py -- find indirect jump tables in .tvm0.

Patterns
  FF 24 C5 disp32      jmp qword ptr [rax*8 + disp32]
  FF 24 CD disp32      jmp qword ptr [rbp*8 + disp32]  (and other SIB variants)
  FF 24 25 disp32      jmp qword ptr [disp32]            (absolute slot)

A table with a small, dense set of entries pointing at code is an opcode
dispatch table: that is how the envelope opcode is turned into a handler.
"""
from __future__ import annotations

import json
import os
import struct
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from pe_model import PEFile, IMAGE_BASE  # noqa: E402

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
OUT = os.path.join(ROOT, "out")
TARGET = r"<TARGET_SYS>"


def main():
    pe = PEFile(TARGET)
    tv = [s for s in pe.sections if s["name"] == ".tvm0"][0]
    blob = pe.data[tv["raw_ptr"] : tv["raw_ptr"] + tv["raw_size"]]
    base = tv["va"]
    img_lo, img_hi = 0x1000, pe.size_of_image

    hits = []
    for i in range(len(blob) - 8):
        if blob[i] != 0xFF or blob[i + 1] != 0x24:
            continue
        modrm = blob[i + 2]
        if (modrm & 0xC7) != 0x04:      # require SIB form
            continue
        sib = blob[i + 3]
        scale = 1 << (sib >> 6)
        index = (sib >> 3) & 7
        if index == 4:                  # no index
            continue
        disp = struct.unpack_from("<i", blob, i + 4)[0]
        table_rva = disp - IMAGE_BASE if disp >= IMAGE_BASE else disp
        hits.append(dict(site=base + i, table=table_rva, elems=blob[i : i + 8].hex(),
                         index_reg=index, scale=scale))

    print(f"indirect jump-table sites: {len(hits)}")
    for h in hits[:20]:
        print(f"  site={h['site']:#08x} table={h['table']:#x} idx=r{h['index_reg']} "
              f"scale={h['scale']} bytes={h['elems']}")

    # decode entries of candidate tables (8-byte slots, absolute addresses)
    print("\n== table contents ==")
    seen = set()
    for h in hits:
        t = h["table"]
        if t in seen or not (0x1000 <= t < pe.size_of_image):
            continue
        seen.add(t)
        vals = []
        for k in range(16):
            off = pe.rva2off(t + k * 8)
            if off is None:
                break
            v = struct.unpack_from("<Q", pe.data, off)[0]
            if not (IMAGE_BASE + 0x1000 <= v < IMAGE_BASE + img_hi):
                break
            vals.append(v - IMAGE_BASE)
        if len(vals) >= 3:
            print(f"  table {t:#x}  n={len(vals)}: " + " ".join(f"{v:#x}" for v in vals))
            for k, v in enumerate(vals):
                print(f"     [{k}] -> {v:#08x}")

    json.dump(hits, open(os.path.join(OUT, "jumptables.json"), "w"), indent=1)


if __name__ == "__main__":
    main()
