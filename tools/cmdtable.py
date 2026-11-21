"""
cmdtable.py -- decode the static command table in .data and find its consumer.

Record layout discovered at 0x35040 (stride 12):
    +0  DWORD flag      (always 1 in the observed table)
    +4  DWORD token     (0x63AE4430 .. )
    +8  DWORD 0x013500CA (record magic / secondary key)

The walker is whatever rip-references 0x35040: it decides whether the incoming
token is allowed, which is the real whitelist behind the 0x907 bitmask.
"""
from __future__ import annotations

import json
import os
import struct
import sys

from capstone import Cs, CS_ARCH_X86, CS_MODE_64
from capstone.x86 import X86_OP_MEM, X86_REG_RIP

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from pe_model import PEFile, IMAGE_BASE  # noqa: E402

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
OUT = os.path.join(ROOT, "out")
TARGET = r"<TARGET_SYS>"
TABLE = 0x35040
MAGIC = 0x013500CA
BASE_TOKEN = 0x63AE442D


def main():
    pe = PEFile(TARGET)
    print("== command table @ 0x35040 ==")
    rows = []
    for i in range(64):
        rva = TABLE + i * 12
        off = pe.rva2off(rva)
        if off is None:
            break
        flag, tok, magic = struct.unpack_from("<III", pe.data, off)
        if magic != MAGIC:
            break
        rows.append(dict(rva=rva, flag=flag, token=tok, magic=magic, k=tok - BASE_TOKEN))
        print(f"  [{i:2d}] {rva:#08x}  flag={flag}  token={tok:#010x} (k={tok - BASE_TOKEN:2d})  magic={magic:#010x}")
    print(f"  -> {len(rows)} records, table {rows[0]['rva']:#x}..{rows[-1]['rva'] + 12:#x}")

    # who references the table?
    print("\n== references to the table / its magic ==")
    md = Cs(CS_ARCH_X86, CS_MODE_64)
    md.detail = True
    for sec in pe.sections:
        if sec["name"] not in (".text", "INIT", ".tvm0"):
            continue
        blob = pe.data[sec["raw_ptr"] : sec["raw_ptr"] + sec["raw_size"]]
        base = sec["va"]
        i = 0
        while i < len(blob) - 8:
            try:
                insn = next(md.disasm(blob[i : i + 15], IMAGE_BASE + base + i))
            except StopIteration:
                i += 1
                continue
            for op in insn.operands:
                if op.type == X86_OP_MEM and op.mem.base == X86_REG_RIP:
                    tgt = insn.address + insn.size + op.mem.disp - IMAGE_BASE
                    if TABLE <= tgt < TABLE + len(rows) * 12:
                        print(f"  {base + i:#08x} [{sec['name']}] {insn.mnemonic} {insn.op_str}"
                              f"   -> {tgt:#x} (record {(tgt - TABLE) // 12})")
                    break
            i += insn.size if insn.size else 1

    json.dump(rows, open(os.path.join(OUT, "cmd_table.json"), "w"), indent=1)


if __name__ == "__main__":
    main()
