"""
deobf.py -- fold the driver's computed-jump obfuscation and measure how much of
the image is affected.

Patterns recognised (all end in an indirect jump whose register was just set by
constant arithmetic, so the target is statically knowable):

  A:  movabs rX, imm64 ; [pushfq] ; add rX, imm32 ; [popfq] ; jmp rX
  B:  movabs rX, imm64 ; [pushfq] ; sub rX, imm32 ; [popfq] ; jmp rX
  C:  lea rX, [rip+a]  ; lea rX, [rX+b] ; jmp rX
  D:  mov rX, imm32    ; add rX, imm32 ; jmp rX

Also reports the junk decoys (jmp/call to addresses outside the image) that the
protector inserts between the real blocks.

Output: out/jumptable.json  {site_rva: {target, pattern, span}}
"""
from __future__ import annotations

import json
import os
import re
import sys
from collections import Counter

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from pe_model import PEFile, IMAGE_BASE  # noqa: E402

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
OUT = os.path.join(ROOT, "out")
TARGET = r"<TARGET_SYS>"


def parse_imm(s):
    s = s.strip()
    try:
        return int(s, 16) if s.startswith(("0x", "-0x")) else int(s)
    except ValueError:
        return None


def main():
    pe = PEFile(TARGET)
    model = json.load(open(os.path.join(OUT, "model.json"), encoding="utf-8"))
    items = sorted(model["items"], key=lambda i: i["rva"])
    in_code = [it for it in items if pe.section_of_rva(it["rva"])["name"] in (".text", "INIT")]
    seq = in_code

    found = {}
    junk = 0
    regs_set = {}       # reg -> (value, rva, kind)
    window = []         # last few instructions

    for it in seq:
        if it["kind"] != "insn":
            window.clear()
            regs_set.clear()
            continue
        m, ops = it["mnem"], it["ops"]
        window.append(it)
        if len(window) > 8:
            window.pop(0)

        if m == "movabs":
            reg, imm = [x.strip() for x in ops.split(",")]
            v = parse_imm(imm)
            if v is not None:
                regs_set[reg] = (v, it["rva"], "abs64")
        elif m in ("mov", "add", "sub") and ops.count(",") == 1 and "+" not in ops and "[" not in ops:
            a, b = [x.strip() for x in ops.split(",")]
            v = parse_imm(b)
            if v is not None:
                if m == "mov":
                    regs_set[a] = (v & 0xFFFFFFFFFFFFFFFF, it["rva"], "abs32")
                elif a in regs_set:
                    base, _, kind = regs_set[a]
                    if m == "add":
                        regs_set[a] = ((base + v) & 0xFFFFFFFFFFFFFFFF, it["rva"], kind)
                    else:
                        regs_set[a] = ((base - v) & 0xFFFFFFFFFFFFFFFF, it["rva"], kind)
        elif m == "lea" and "rip" in ops:
            mt = re.match(r"^(\w+), \[rip ([+-]) 0x([0-9a-f]+)\]$", ops)
            if mt:
                reg = mt.group(1)
                disp = int(mt.group(3), 16) * (1 if mt.group(2) == "+" else -1)
                val = (IMAGE_BASE + it["rva"] + it["size"] + disp) & 0xFFFFFFFFFFFFFFFF
                regs_set[reg] = (val, it["rva"], "rip_abs")
        elif m == "lea" and ops.count(",") == 1:
            mt = re.match(r"^(\w+), \[(\w+) ([+-]) 0x([0-9a-f]+)\]$", ops)
            if mt and mt.group(2) in regs_set:
                reg = mt.group(1)
                base, _, kind = regs_set[mt.group(2)]
                v = int(mt.group(4), 16) * (1 if mt.group(3) == "+" else -1)
                regs_set[reg] = ((base + v) & 0xFFFFFFFFFFFFFFFF, it["rva"], kind)
        elif m == "jmp" and ops in regs_set:
            val, src_rva, kind = regs_set[ops]
            target = val - IMAGE_BASE if val >= IMAGE_BASE else val
            if 0x1000 <= target < 0x129000:
                span = it["rva"] + it["size"] - src_rva
                found[it["rva"]] = dict(target=target, pattern=kind, span=span, src=src_rva)
            else:
                junk += 1
            regs_set.pop(ops, None)
        elif m in ("jmp", "call") and it.get("branch") is not None:
            t = it["branch"]
            if not (0x1000 <= t < 0x129000):
                junk += 1

    with open(os.path.join(OUT, "jumptable.json"), "w", encoding="utf-8") as f:
        json.dump({f"{k:x}": v for k, v in found.items()}, f, indent=1)

    print(f"computed jumps resolved: {len(found)}")
    print(f"junk branches outside image: {junk}")
    pat = Counter(v["pattern"] for v in found.values())
    print("patterns:", dict(pat))
    tgt = Counter()
    for v in found.values():
        tgt[v["target"]] += 1
    print("distinct targets:", len(tgt), " most referenced:",
          [(hex(t), c) for t, c in tgt.most_common(8)])
    tot = sum(v["span"] for v in found.values())
    print(f"bytes covered by these jump islands: {tot} ({tot/0x2d87c*100:.1f}% of .text)")


if __name__ == "__main__":
    main()
