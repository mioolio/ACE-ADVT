"""
um_dis.py -- disassemble a user-mode address range from any PE.

usage: python tools/um_dis.py <binary> <rva-or-va> [length]
       RVA 0x52316 and VA 0x180052316 are both accepted.
"""
from __future__ import annotations

import os
import sys

from capstone import Cs, CS_ARCH_X86, CS_MODE_64

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from pe_model import PEFile  # noqa: E402

MD = Cs(CS_ARCH_X86, CS_MODE_64)
MD.detail = True


def main():
    path = sys.argv[1]
    addr = int(sys.argv[2], 16)
    length = int(sys.argv[3], 16) if len(sys.argv) > 3 else 0x100
    pe = PEFile(path)
    if addr >= pe.image_base:
        rva = addr - pe.image_base
    else:
        rva = addr
    off = pe.rva2off(rva)
    if off is None:
        raise SystemExit("rva not file backed")
    blob = pe.data[off : off + length]
    print(f"; {os.path.basename(path)} rva {rva:#x} va {pe.image_base + rva:#x}")
    for insn in MD.disasm(blob, pe.image_base + rva):
        note = ""
        for op in insn.operands:
            if op.type == 2 and op.mem.base == 41:      # RIP
                tgt = insn.address + insn.size + op.mem.disp
                if pe.image_base <= tgt < pe.image_base + pe.size_of_image:
                    note = f"  ; -> rva {tgt - pe.image_base:#x}"
        print(f"{insn.address:012x}  {insn.bytes.hex():<28} {insn.mnemonic} {insn.op_str}{note}")


if __name__ == "__main__":
    main()
