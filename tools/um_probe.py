"""
um_probe.py -- locate a 32-bit constant inside one binary and disassemble around it.

usage: python tools/um_probe.py <binary> <hexvalue> [--ctx 64] [--max 4]

Prints section, file offset, and a capstone window around each hit so the
surrounding logic (usually the envelope builder or the reply check) becomes
readable without a full loader-level analysis.
"""
from __future__ import annotations

import os
import struct
import sys

from capstone import Cs, CS_ARCH_X86, CS_MODE_64

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from pe_model import PEFile  # noqa: E402

MD = Cs(CS_ARCH_X86, CS_MODE_64)
MD.detail = True


def main():
    path = sys.argv[1]
    val = int(sys.argv[2], 16)
    ctx = 64
    maxhits = 4
    if "--ctx" in sys.argv:
        ctx = int(sys.argv[sys.argv.index("--ctx") + 1])
    if "--max" in sys.argv:
        maxhits = int(sys.argv[sys.argv.index("--max") + 1])

    pe = PEFile(path)
    data = pe.data
    pat = struct.pack("<I", val)
    hits = []
    i = data.find(pat)
    while i >= 0:
        sec = None
        for s in pe.sections:
            if s["raw_ptr"] <= i < s["raw_ptr"] + s["raw_size"]:
                sec = s
                break
        hits.append((i, sec))
        i = data.find(pat, i + 1)

    print(f"{os.path.basename(path)}: value {val:#010x} -> {len(hits)} hit(s)")
    for n, (off, sec) in enumerate(hits[:maxhits]):
        rva = sec["va"] + (off - sec["raw_ptr"]) if sec else off
        print(f"\n--- hit {n}: file {off:#x}  rva {rva:#x}  section {sec['name'] if sec else '?'} ---")
        start = max(0, off - ctx)
        blob = data[start : off + ctx]
        va = pe.image_base + (sec["va"] + (start - sec["raw_ptr"])) if sec else pe.image_base + start
        n_instr = 0
        for insn in MD.disasm(blob, va):
            mark = " <<<" if insn.address <= pe.image_base + rva < insn.address + insn.size else ""
            print(f"  {insn.address:012x}  {insn.bytes.hex():<24} {insn.mnemonic} {insn.op_str}{mark}")
            n_instr += 1
            if n_instr > 40:
                break


if __name__ == "__main__":
    main()
