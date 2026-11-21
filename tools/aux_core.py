"""
aux_core.py -- extract the semantic core of each aux handler.

The protector interleaves junk (register shuffles, `not` pairs, constant-jump
islands, the next chain comparison).  This tool keeps only the instructions that
carry data: memory accesses, arithmetic on values, comparisons, calls and
backward branches, in order, and prints the first ones per command.
"""
from __future__ import annotations

import json
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import trace as tracer  # noqa: E402

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
OUT = os.path.join(ROOT, "out")
AUX_BASE = 0x623782AB
SITES = {2: 0x641A5, 3: 0x64543, 4: 0x648D0, 5: 0x63B5B, 6: 0x64DAD, 7: 0x65541,
         8: 0x69508, 9: 0x66DCF, 10: 0x67B92, 11: 0x681E3, 12: 0x67086, 13: 0x676FD,
         17: 0x65DE2, 18: 0x665AE, 19: 0x6687B, 20: 0x69C31, 21: 0x698F4,
         22: 0x6901B, 25: 0x6881E, 28: 0x68D8D, 29: 0x6A259, 30: 0x6A687}

JUNK_MN = {"push", "pop", "pushfq", "popfq", "not", "xchg", "cld", "std", "nop",
           "fwait", "hlt", "cmc", "stc", "clc", "lahf", "sahf", "cdq", "cqo"}
CHAIN_TOKENS = {0x623782AB + k for k in range(0, 0x40)}


def arm_start(site):
    off = tracer.pe.rva2off(site)
    try:
        insn = next(tracer.MD.disasm(tracer.pe.data[off : off + 15], tracer.IMAGE_BASE + site))
    except StopIteration:
        return site + 6
    return site + insn.size


def core(k, limit=14):
    start = arm_start(SITES[k])
    path, edges = tracer.trace(start, 300)
    out = []
    for rva, text, note, kind, raw in path:
        m = text.split(" ")[0]
        if m in JUNK_MN:
            continue
        if m == "jmp":
            continue                      # jump islands are noise here
        if m == "lea" and "rip" in text:
            continue                      # address computation for the islands
        if "0x6237" in text and m == "cmp":
            break                         # reached the next chain comparison
        # keep data ops
        if (m in ("mov", "movzx", "movsx", "movsxd", "cmp", "test", "add", "sub",
                  "and", "or", "xor", "shl", "shr", "sar", "rol", "ror", "imul",
                  "mul", "div", "idiv", "movsd", "movsq", "stosb", "stosd", "stosq",
                  "rep", "neg", "inc", "dec", "bt", "bts", "btr", "setne", "sete",
                  "cmovne", "cmove", "call", "loop", "jne", "je", "jb", "ja", "jbe",
                  "jae", "jl", "jg")) or m.startswith("mov"):
            out.append((rva, text, note))
        if len(out) >= limit:
            break
    return out, len(path), len(edges)


def main():
    result = {}
    for k in sorted(SITES):
        ops, npath, nedges = core(k)
        result[k] = [dict(rva=r, text=t, note=n) for r, t, n in ops]
        print(f"\n=== aux k={k:2d} 0x{AUX_BASE + k:08X} site={SITES[k]:#08x} "
              f"(path {npath} insns / {nedges} edges) ===")
        for r, t, n in ops:
            print(f"   {r:#08x}  {t[:64]:<64} {n}")
    json.dump({str(k): v for k, v in result.items()},
              open(os.path.join(OUT, "aux_core.json"), "w"), indent=1)


if __name__ == "__main__":
    main()
