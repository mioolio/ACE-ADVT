"""
fn.py -- annotated dump of one function (or range) from the model.

usage: python tools/fn.py 1da0 [--end 2000] [--wide]

Annotations
  call sub_x / loc_x      direct control flow, resolved to symbols
  [rip+X] -> dat_x        rip-relative target; if it is an IAT slot the import
                          name is appended, if it is a string the text is shown
  jmp qword ptr [r*8+t]   jump table: entries are decoded and listed
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


def load():
    pe = PEFile(TARGET)
    model = json.load(open(os.path.join(OUT, "model.json"), encoding="utf-8"))
    items = {it["rva"]: it for it in model["items"]}
    labels = {int(k, 16): v for k, v in model["labels"].items()}
    iat = {int(k, 16): v for k, v in model["iat"].items()}
    return pe, model, items, labels, iat


def cstr(pe, rva, maxlen=80):
    off = pe.rva2off(rva)
    if off is None:
        return None
    raw = pe.data[off : off + maxlen]
    end = raw.find(b"\0")
    if end < 4:
        return None
    s = raw[:end]
    if any(c < 0x20 or c > 0x7E for c in s):
        return None
    return s.decode("ascii", "replace")


def dump(start, end=None, wide=False):
    pe, model, items, labels, iat = load()
    if end is None:
        for f in model["functions"]:
            if f["begin"] == start:
                end = f["end"]
                break
    if end is None:
        raise SystemExit("unknown function end")
    print(f"; ---- {labels.get(start, hex(start))}  {start:#x}..{end:#x} "
          f"({end - start} bytes) ----")
    rva = start
    while rva < end:
        it = items.get(rva)
        if it is None:
            print(f"{rva:08x}  <gap>")
            break
        line = f"{rva:08x}  {it['bytes'][:32]:<34}"
        if it["kind"] == "insn":
            txt = it["mnem"] + (" " + it["ops"] if it["ops"] else "")
            note = ""
            if it.get("ripref") is not None:
                t = it["ripref"]
                if t in iat:
                    note = iat[t]
                else:
                    s = cstr(pe, t)
                    if s:
                        note = f'"{s}"'
                    else:
                        note = labels.get(t, f"dat_{t:x}")
            elif it.get("branch") is not None:
                note = labels.get(it["branch"], f"{it['branch']:#x}")
            # jump table detection
            if it["mnem"] == "jmp" and "rip" in it["ops"]:
                pass
            line += f" {txt:<50}"
            if note:
                line += f" ; {note}"
            print(line.rstrip())
            if wide and it["mnem"] == "jmp" and it.get("ripref") and "[" in it["ops"]:
                tbl = it["ripref"]
                print(f"           jump table @ {tbl:#x}:")
                for i in range(24):
                    off = pe.rva2off(tbl + i * 4)
                    if off is None:
                        break
                    v = struct.unpack_from("<i", pe.data, off)[0]
                    tgt = (tbl + i * 4 + v) & 0xFFFFFFFF
                    if tgt < 0x1000 or tgt > 0x129000:
                        break
                    print(f"             [{i:2d}] -> {labels.get(tgt, hex(tgt))} ({tgt:#x})")
        elif it["kind"] == "pad":
            line += f" times {it['size']} db 0cch"
            print(line.rstrip())
        else:
            line += f" db ({it['size']} bytes)"
            print(line.rstrip())
        rva += it["size"]


if __name__ == "__main__":
    start = int(sys.argv[1], 16)
    end = int(sys.argv[2], 16) if len(sys.argv) > 2 and not sys.argv[2].startswith("-") else None
    dump(start, end, wide="--wide" in sys.argv)
