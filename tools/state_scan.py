"""
state_scan.py -- map every access to the driver's global state block.

Scans .text + .tvm0 for rip-relative references whose target falls in the
.data state range (0x35000..0x35D00) and decodes each site with capstone to show
read vs write, the immediate written, and the owning byte.

This answers "who writes the readiness bitmap at 0x35B28" and produces the full
global-state map used by docs/08.
"""
from __future__ import annotations

import json
import os
import struct
import sys
from collections import Counter, defaultdict

from capstone import Cs, CS_ARCH_X86, CS_MODE_64
from capstone.x86 import X86_OP_IMM, X86_OP_MEM, X86_REG_RIP

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from pe_model import PEFile, IMAGE_BASE  # noqa: E402

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
OUT = os.path.join(ROOT, "out")
TARGET = r"<TARGET_SYS>"
LO, HI = 0x35000, 0x35D00

MD = Cs(CS_ARCH_X86, CS_MODE_64)
MD.detail = True


def main():
    pe = PEFile(TARGET)
    per_addr = defaultdict(list)
    for sec in pe.sections:
        if sec["name"] not in (".text", "INIT", ".tvm0"):
            continue
        blob = pe.data[sec["raw_ptr"] : sec["raw_ptr"] + sec["raw_size"]]
        base = sec["va"]
        i = 0
        while i < len(blob) - 8:
            try:
                insn = next(MD.disasm(blob[i : i + 15], IMAGE_BASE + base + i))
            except StopIteration:
                i += 1
                continue
            for op in insn.operands:
                if op.type == X86_OP_MEM and op.mem.base == X86_REG_RIP:
                    tgt = insn.address + insn.size + op.mem.disp - IMAGE_BASE
                    if LO <= tgt < HI:
                        write = (insn.operands[0].type == X86_OP_MEM and
                                 insn.operands[0].mem.base == X86_REG_RIP)
                        imm = ""
                        for o2 in insn.operands[1:]:
                            if o2.type == X86_OP_IMM:
                                imm = f"{o2.imm:#x}"
                        per_addr[tgt].append(dict(
                            site=base + i, sec=sec["name"], mnem=insn.mnemonic,
                            ops=insn.op_str, write=write, imm=imm,
                            size=op.size,
                        ))
                    break
            i += insn.size if insn.size else 1

    print(f"distinct state addresses touched: {len(per_addr)}")
    for addr in sorted(per_addr):
        acc = per_addr[addr]
        w = [a for a in acc if a["write"]]
        r = [a for a in acc if not a["write"]]
        print(f"\n{addr:#08x}  reads={len(r)} writes={len(w)}")
        for a in w[:6]:
            print(f"   W {a['site']:#08x} [{a['sec']}] {a['mnem']} {a['ops']}   imm={a['imm']}")
        for a in r[:4]:
            print(f"   R {a['site']:#08x} [{a['sec']}] {a['mnem']} {a['ops']}")

    json.dump({hex(k): v for k, v in per_addr.items()},
              open(os.path.join(OUT, "state_map.json"), "w"), indent=1)


if __name__ == "__main__":
    main()
