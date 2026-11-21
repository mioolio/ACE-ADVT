"""
token_chain.py -- emit the command dispatch chain in execution order.

The chain is a straight line of `cmp eax, token_k ; jne <next>` blocks inside
sub_625B1; the match path of each block is its own handler.  This tool lists the
chain as the driver walks it, with the accept/reject verdict of every token.
"""
from __future__ import annotations

import json
import os
import sys

from capstone import Cs, CS_ARCH_X86, CS_MODE_64

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from pe_model import PEFile, IMAGE_BASE  # noqa: E402

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
OUT = os.path.join(ROOT, "out")
TARGET = r"<TARGET_SYS>"
BASE_TOKEN = 0x63AE442D
ACCEPT = {3, 4, 5, 6, 7, 9, 10}
CHAIN = [(0, 0x627AC), (8, 0x62862), (1, 0x628D2), (3, 0x62910), (10, 0x6294A),
         (11, 0x62A60), (4, 0x62B24), (5, 0x62EC5), (9, 0x62F64), (2, 0x637E6)]


def main():
    pe = PEFile(TARGET)
    md = Cs(CS_ARCH_X86, CS_MODE_64)
    lines = ["; ACE-ADVT command dispatch chain (sub_625B1) -- execution order",
             "; token(k) = 0x63AE442D + k ; mask 0x907 rejects k in {0,1,2,8,11}",
             ""]
    print("k   token       verdict   cmp site   next block   handler entry")
    for k, site in CHAIN:
        off = pe.rva2off(site)
        insns = list(md.disasm(pe.data[off : off + 24], IMAGE_BASE + site))
        nxt = ""
        for ins in insns[1:2]:
            if ins.mnemonic.startswith("jne") or ins.mnemonic == "jne":
                nxt = ins.op_str
        verdict = "ACCEPT" if k in ACCEPT else "reject"
        # handler entry = the instruction after the jne
        hentry = site + insns[0].size + insns[1].size if len(insns) > 1 else site
        line = (f"{k:2d}  0x{BASE_TOKEN + k:08X}  {verdict:6s}  {site:#08x}  "
                f"{nxt:>14s}  {hentry:#08x}")
        print(line)
        lines.append(line)
    lines.append("")
    lines.append("; order observed in the driver: "
                 + " -> ".join(f"k{k}" for k, _ in CHAIN))
    with open(os.path.join(OUT, "listing", "token_chain.txt"), "w", encoding="utf-8") as f:
        f.write("\n".join(lines) + "\n")
    print("\nwrote out/listing/token_chain.txt")


if __name__ == "__main__":
    main()
