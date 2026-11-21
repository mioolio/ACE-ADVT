"""
dis.py -- on-demand linear disassembly with annotations (works even where the
cached partition has a mid-function blob).

usage: python tools/dis.py <rva> [length] [--tables]
"""
from __future__ import annotations

import json
import os
import struct
import sys

from capstone import Cs, CS_ARCH_X86, CS_MODE_64
from capstone.x86 import X86_OP_IMM, X86_OP_MEM, X86_REG_RIP

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from pe_model import PEFile, IMAGE_BASE  # noqa: E402

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
OUT = os.path.join(ROOT, "out")
TARGET = r"<TARGET_SYS>"

pe = PEFile(TARGET)
model = json.load(open(os.path.join(OUT, "model.json"), encoding="utf-8"))
labels = {int(k, 16): v for k, v in model["labels"].items()}
iat = {int(k, 16): v for k, v in model["iat"].items()}
funcs = {f["begin"]: f["end"] for f in model["functions"]}
MD = Cs(CS_ARCH_X86, CS_MODE_64)
MD.detail = True


def sym(a):
    return labels.get(a) or (f"sub_{a:x}" if a in funcs else f"{a:#x}")


def cstr(rva, maxlen=90):
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


def table(base, count=32, width=4, width_kind="rel32"):
    out = []
    for i in range(count):
        off = pe.rva2off(base + i * width)
        if off is None:
            break
        if width_kind == "rel32":
            v = struct.unpack_from("<i", pe.data, off)[0]
            tgt = (base + i * width + v) & 0xFFFFFFFF
        elif width_kind == "abs32":
            tgt = struct.unpack_from("<I", pe.data, off)[0]
        else:
            tgt = struct.unpack_from("<Q", pe.data, off)[0]
        if not (0x1000 <= tgt < 0x129000):
            break
        out.append(tgt)
    return out


def dump(start, length, tables=False):
    data = pe.bytes_at_rva(start, length)
    print(f"; ---- {sym(start)}  {start:#x} + {length:#x} ----")
    for insn in MD.disasm(data, IMAGE_BASE + start):
        rva = insn.address - IMAGE_BASE
        note = ""
        if insn.mnemonic in ("call", "jmp") and insn.operands:
            op = insn.operands[0]
            if op.type == X86_OP_IMM:
                t = op.imm - IMAGE_BASE
                note = ("-> " if insn.mnemonic == "call" else "") + sym(t)
            elif op.type == X86_OP_MEM and op.mem.base == X86_REG_RIP:
                t = insn.address + insn.size + op.mem.disp - IMAGE_BASE
                note = iat.get(t) or cstr(t) or labels.get(t) or f"dat_{t:x}"
                if tables and "[" in insn.op_str and "*" in insn.op_str:
                    pass
        if not note:
            for op in insn.operands:
                if op.type == X86_OP_MEM and op.mem.base == X86_REG_RIP:
                    t = insn.address + insn.size + op.mem.disp - IMAGE_BASE
                    note = iat.get(t) or cstr(t) or labels.get(t) or f"dat_{t:x}"
                    break
        print(f"{rva:08x}  {insn.bytes.hex():<30} {insn.mnemonic + ' ' + insn.op_str:<46} "
              + (f"; {note}" if note else ""))


if __name__ == "__main__":
    start = int(sys.argv[1], 16)
    length = int(sys.argv[2], 16) if len(sys.argv) > 2 and not sys.argv[2].startswith("-") else 0x100
    dump(start, length, "--tables" in sys.argv)
