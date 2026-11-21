"""
trace.py -- constant-propagating tracer for the flattened code in .tvm0.

The protector encodes every block edge as
    movabs rX, imm64 ; pushfq ; add rX, imm32 ; popfq ; jmp rX
so a small abstract interpreter recovers the successor.  Junk between the real
instructions (register shuffles, `not`, decoy jmp/call outside the image) is
decoded but does not affect the trace because it never reaches a taken edge.

usage: python tools/trace.py <rva> [max_insns] [--all]
"""
from __future__ import annotations

import json
import os
import sys
from collections import deque

from capstone import Cs, CS_ARCH_X86, CS_MODE_64
from capstone.x86 import X86_OP_IMM, X86_OP_MEM, X86_REG_RIP, X86_OP_REG

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from pe_model import PEFile, IMAGE_BASE  # noqa: E402

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
OUT = os.path.join(ROOT, "out")
TARGET = r"<TARGET_SYS>"

pe = PEFile(TARGET)
model = json.load(open(os.path.join(OUT, "model.json"), encoding="utf-8"))
labels = {int(k, 16): v for k, v in model["labels"].items()}
iat = {int(k, 16): v for k, v in model["iat"].items()}
MD = Cs(CS_ARCH_X86, CS_MODE_64)
MD.detail = True

COND = {"je", "jne", "jz", "jnz", "ja", "jae", "jb", "jbe", "jg", "jge", "jl", "jle",
        "js", "jns", "jo", "jno", "jp", "jnp", "jpe", "jpo", "jrcxz", "jecxz"}


def sym(a):
    if a in iat:
        return iat[a]
    if a in labels:
        return labels[a]
    return f"{a:#x}"


def cstr(rva):
    off = pe.rva2off(rva)
    if off is None:
        return None
    raw = pe.data[off : off + 90]
    end = raw.find(b"\0")
    if end < 4:
        return None
    s = raw[:end]
    return s.decode("ascii", "replace") if all(0x20 <= c < 0x7F for c in s) else None


def reg_name(insn, idx):
    return insn.reg_name(idx) if idx else None


def trace(start, budget=20000, show_all=False, kprobe=()):
    """returns (path, edges) where path is a list of (rva, text, note, kind)."""
    regs = {}
    seen = set()
    path = []
    edges = []
    work = deque([(start, dict(regs))])

    while work and len(path) < budget:
        rva, regs = work.popleft()
        while len(path) < budget:
            if rva in seen:
                break
            seen.add(rva)
            off = pe.rva2off(rva)
            if off is None:
                break
            try:
                insn = next(MD.disasm(pe.data[off : off + 16], IMAGE_BASE + rva))
            except StopIteration:
                break
            m, ops = insn.mnemonic, insn.op_str
            text = f"{m} {ops}".strip()
            note = ""
            kind = "real"

            # ---- abstract effects ------------------------------------------
            opnd = insn.operands
            if m == "movabs" and len(opnd) == 2 and opnd[0].type == X86_OP_REG:
                regs[reg_name(insn, opnd[0].reg)] = opnd[1].imm & 0xFFFFFFFFFFFFFFFF
            elif m in ("mov", "add", "sub") and len(opnd) == 2 and opnd[0].type == X86_OP_REG:
                r = reg_name(insn, opnd[0].reg)
                if opnd[1].type == X86_OP_IMM:
                    v = opnd[1].imm
                    if m == "mov":
                        regs[r] = v & 0xFFFFFFFFFFFFFFFF
                    elif r in regs:
                        regs[r] = (regs[r] + v) & 0xFFFFFFFFFFFFFFFF if m == "add" \
                            else (regs[r] - v) & 0xFFFFFFFFFFFFFFFF
                elif opnd[1].type == X86_OP_REG and m == "mov":
                    src = reg_name(insn, opnd[1].reg)
                    if src in regs:
                        regs[r] = regs[src]
                    else:
                        regs.pop(r, None)
                else:
                    regs.pop(r, None)
            elif m == "lea" and len(opnd) == 2 and opnd[0].type == X86_OP_REG:
                r = reg_name(insn, opnd[0].reg)
                mem = opnd[1].mem
                if opnd[1].type == X86_OP_MEM and mem.base == X86_REG_RIP:
                    regs[r] = (insn.address + insn.size + mem.disp) & 0xFFFFFFFFFFFFFFFF
                elif opnd[1].type == X86_OP_MEM and mem.base and not mem.index:
                    b = reg_name(insn, mem.base)
                    if b in regs:
                        regs[r] = (regs[b] + mem.disp) & 0xFFFFFFFFFFFFFFFF
                    else:
                        regs.pop(r, None)
                else:
                    regs.pop(r, None)
            elif m == "not" and opnd and opnd[0].type == X86_OP_REG:
                r = reg_name(insn, opnd[0].reg)
                if r in regs:
                    regs[r] = (~regs[r]) & 0xFFFFFFFFFFFFFFFF
            elif m == "xchg" and len(opnd) == 2 and all(o.type == X86_OP_REG for o in opnd):
                a, b = reg_name(insn, opnd[0].reg), reg_name(insn, opnd[1].reg)
                va, vb = regs.get(a), regs.get(b)
                regs.pop(a, None)
                regs.pop(b, None)
                if vb is not None:
                    regs[a] = vb
                if va is not None:
                    regs[b] = va
            elif m == "xor" and len(opnd) == 2 and opnd[0].type == X86_OP_REG \
                    and opnd[1].type == X86_OP_REG and opnd[0].reg == opnd[1].reg:
                regs[reg_name(insn, opnd[0].reg)] = 0
            elif m in ("push", "pop", "pushfq", "popfq", "cmp", "test", "nop"):
                pass
            elif opnd and opnd[0].type == X86_OP_REG and m not in ("call", "jmp"):
                regs.pop(reg_name(insn, opnd[0].reg), None)

            # ---- control flow ---------------------------------------------
            nxt = None
            if m == "jmp":
                if opnd and opnd[0].type == X86_OP_REG:
                    r = reg_name(insn, opnd[0].reg)
                    if r in regs:
                        t = regs[r] - IMAGE_BASE if regs[r] >= IMAGE_BASE else regs[r]
                        if 0x1000 <= t < 0x129000:
                            note = f"=> {sym(t)}"
                            kind = "edge"
                            edges.append((rva, t))
                            nxt = t
                        else:
                            note = "junk jmp (outside image)"
                            kind = "junk"
                            break
                    else:
                        note = "indirect (unknown)"
                        break
                elif opnd and opnd[0].type == X86_OP_IMM:
                    t = opnd[0].imm - IMAGE_BASE
                    if 0x1000 <= t < 0x129000:
                        note = f"=> {sym(t)}"
                        nxt = t
                    else:
                        kind = "junk"
                        break
            elif m in COND and opnd and opnd[0].type == X86_OP_IMM:
                t = opnd[0].imm - IMAGE_BASE
                note = f"cond => {sym(t)}"
                if 0x1000 <= t < 0x129000:
                    work.append((t, dict(regs)))
                nxt = None
            elif m == "call":
                if opnd and opnd[0].type == X86_OP_IMM:
                    t = opnd[0].imm - IMAGE_BASE
                    note = f"call {sym(t)}"
                elif opnd and opnd[0].type == X86_OP_MEM and opnd[0].mem.base == X86_REG_RIP:
                    t = insn.address + insn.size + opnd[0].mem.disp - IMAGE_BASE
                    note = f"call {sym(t)}"
                nxt = None
            elif m in ("ret", "retn", "ud2", "int3", "iretq", "sysret"):
                kind = "term"
                nxt = None
            else:
                nxt = (rva + insn.size)

            path.append((rva, text, note, kind, insn.bytes.hex()))
            if kind == "term":
                break
            if nxt is None:
                rva = rva + insn.size
                continue
            rva = nxt
    return path, edges


if __name__ == "__main__":
    start = int(sys.argv[1], 16)
    budget = int(sys.argv[2]) if len(sys.argv) > 2 and not sys.argv[2].startswith("-") else 400
    show_all = "--all" in sys.argv
    path, edges = trace(start, budget)
    for rva, text, note, kind, raw in path:
        if not show_all and kind == "junk":
            continue
        print(f"{rva:08x}  {raw:<28} {text:<52} {note}")
    print(f"\n; instructions traced: {len(path)}   taken edges: {len(edges)}")
