"""
trace_any.py -- constant-propagating tracer for any ACE component.

Same algorithm as tools/trace.py (documented in docs/04) but parameterised by the
PE path, so the protected bodies inside ACE-Service64.exe / ACE-CSI64.dll /
ACE-BASE.sys can be followed the same way.

usage: python tools/trace_any.py <binary> <rva> [budget]
"""
from __future__ import annotations

import os
import sys
from collections import deque

from capstone import Cs, CS_ARCH_X86, CS_MODE_64
from capstone.x86 import X86_OP_IMM, X86_OP_MEM, X86_OP_REG, X86_REG_RIP

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from pe_model import PEFile  # noqa: E402

COND = {"je", "jne", "jz", "jnz", "ja", "jae", "jb", "jbe", "jg", "jge", "jl", "jle",
        "js", "jns", "jo", "jno", "jp", "jnp", "jpe", "jpo"}
MD = Cs(CS_ARCH_X86, CS_MODE_64)
MD.detail = True


class Tracer:
    def __init__(self, path):
        self.pe = PEFile(path)
        self.base = self.pe.image_base
        self.lo = 0x1000
        self.hi = self.pe.size_of_image

    def sym(self, rva):
        s = self.pe.section_of_rva(rva)
        return f"{s['name']}+{rva - s['va']:#x}" if s else f"{rva:#x}"

    def trace(self, start_rva, budget=600):
        regs, seen, path = {}, set(), []
        work = deque([(start_rva, {})])
        while work and len(path) < budget:
            rva, regs = work.popleft()
            while len(path) < budget:
                if rva in seen:
                    break
                seen.add(rva)
                off = self.pe.rva2off(rva)
                if off is None:
                    break
                try:
                    insn = next(MD.disasm(self.pe.data[off : off + 16], self.base + rva))
                except StopIteration:
                    break
                m, ops, opnd = insn.mnemonic, insn.op_str, insn.operands
                note, kind = "", "real"

                def rn(idx):
                    return insn.reg_name(idx) if idx else None

                if m == "movabs" and len(opnd) == 2 and opnd[0].type == X86_OP_REG:
                    regs[rn(opnd[0].reg)] = opnd[1].imm & 0xFFFFFFFFFFFFFFFF
                elif m in ("mov", "add", "sub") and len(opnd) == 2 and opnd[0].type == X86_OP_REG:
                    r = rn(opnd[0].reg)
                    if opnd[1].type == X86_OP_IMM:
                        v = opnd[1].imm
                        if m == "mov":
                            regs[r] = v & 0xFFFFFFFFFFFFFFFF
                        elif r in regs:
                            regs[r] = (regs[r] + v) & 0xFFFFFFFFFFFFFFFF if m == "add" \
                                else (regs[r] - v) & 0xFFFFFFFFFFFFFFFF
                    elif opnd[1].type == X86_OP_REG and m == "mov":
                        s = rn(opnd[1].reg)
                        if s in regs:
                            regs[r] = regs[s]
                        else:
                            regs.pop(r, None)
                    else:
                        regs.pop(r, None)
                elif m == "lea" and len(opnd) == 2 and opnd[0].type == X86_OP_REG:
                    r = rn(opnd[0].reg)
                    mem = opnd[1].mem
                    if opnd[1].type == X86_OP_MEM and mem.base == X86_REG_RIP:
                        regs[r] = (insn.address + insn.size + mem.disp) & 0xFFFFFFFFFFFFFFFF
                    elif opnd[1].type == X86_OP_MEM and mem.base and not mem.index:
                        b = rn(mem.base)
                        if b in regs and regs[b] is not None:
                            regs[r] = (regs[b] + mem.disp) & 0xFFFFFFFFFFFFFFFF
                        else:
                            regs.pop(r, None)
                    else:
                        regs.pop(r, None)
                elif m == "not" and opnd and opnd[0].type == X86_OP_REG:
                    r = rn(opnd[0].reg)
                    if r in regs:
                        regs[r] = (~regs[r]) & 0xFFFFFFFFFFFFFFFF
                elif m == "xchg" and len(opnd) == 2 and all(o.type == X86_OP_REG for o in opnd):
                    a, b = rn(opnd[0].reg), rn(opnd[1].reg)
                    va, vb = regs.get(a), regs.get(b)
                    regs.pop(a, None)
                    regs.pop(b, None)
                    if vb is not None:
                        regs[a] = vb
                    if va is not None:
                        regs[b] = va
                elif m == "xor" and len(opnd) == 2 and opnd[0].type == X86_OP_REG \
                        and opnd[1].type == X86_OP_REG and opnd[0].reg == opnd[1].reg:
                    regs[rn(opnd[0].reg)] = 0
                elif m in ("push", "pop", "pushfq", "popfq", "cmp", "test", "nop"):
                    pass
                elif opnd and opnd[0].type == X86_OP_REG and m not in ("call", "jmp"):
                    regs.pop(rn(opnd[0].reg), None)

                nxt = None
                if m == "jmp":
                    if opnd and opnd[0].type == X86_OP_REG:
                        r = rn(opnd[0].reg)
                        if r in regs:
                            t = regs[r] - self.base if regs[r] >= self.base else regs[r]
                            if self.lo <= t < self.hi:
                                note = f"=> {self.sym(t)}"
                                kind = "edge"
                                nxt = t
                            else:
                                kind = "junk"
                                break
                        else:
                            note = "indirect"
                            break
                    elif opnd and opnd[0].type == X86_OP_IMM:
                        t = opnd[0].imm - self.base
                        if self.lo <= t < self.hi:
                            note = f"=> {self.sym(t)}"
                            nxt = t
                        else:
                            kind = "junk"
                            break
                elif m in COND and opnd and opnd[0].type == X86_OP_IMM:
                    t = opnd[0].imm - self.base
                    note = f"cond => {self.sym(t)}"
                    if self.lo <= t < self.hi:
                        work.append((t, dict(regs)))
                elif m == "call":
                    if opnd and opnd[0].type == X86_OP_IMM:
                        note = f"call {self.sym(opnd[0].imm - self.base)}"
                    elif opnd and opnd[0].type == X86_OP_MEM and opnd[0].mem.base == X86_REG_RIP:
                        t = insn.address + insn.size + opnd[0].mem.disp - self.base
                        note = f"call {self.sym(t)}"
                elif m in ("ret", "retn", "ud2", "int3"):
                    kind = "term"
                else:
                    nxt = rva + insn.size

                path.append((rva, f"{m} {ops}".strip(), note, kind, insn.bytes.hex()))
                if kind == "term":
                    break
                rva = nxt if nxt is not None else rva + insn.size
        return path


if __name__ == "__main__":
    path = sys.argv[1]
    rva = int(sys.argv[2], 16)
    if rva >= 0x10000000:
        import sys as _s
    budget = int(sys.argv[3]) if len(sys.argv) > 3 else 400
    t = Tracer(path)
    if rva >= t.base:
        rva -= t.base
    p = t.trace(rva, budget)
    for r, text, note, kind, raw in p:
        if kind == "junk":
            continue
        print(f"{r:08x}  {raw:<26} {text:<52} {note}")
    print(f"\n; {len(p)} instructions traced")
