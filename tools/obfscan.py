"""
obfscan.py -- raw-byte scan for the computed-jump idiom across every section,
independent of the partition (the partition cannot be trusted inside .tvm0).

Idiom:  48|49 B8..BF <imm64>  ...  48|49 81 /0 <imm32>  ...  FF /4 (jmp r64)

The target is imm64 + imm32, which is exactly how the protector hides the real
successor block: the arithmetic runs with interrupts masked (pushfq/popfq) so
the flags clobber is invisible, and junk instructions sit between the pieces.
"""
from __future__ import annotations

import json
import os
import struct
import sys
from collections import Counter

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from pe_model import PEFile, IMAGE_BASE  # noqa: E402

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
OUT = os.path.join(ROOT, "out")
TARGET = r"<TARGET_SYS>"

REG = ["rax", "rcx", "rdx", "rbx", "rsp", "rbp", "rsi", "rdi",
       "r8", "r9", "r10", "r11", "r12", "r13", "r14", "r15"]


def scan_section(pe, sec):
    blob = pe.data[sec["raw_ptr"] : sec["raw_ptr"] + sec["raw_size"]]
    n = len(blob)
    hits = []
    for i in range(n - 16):
        rex = blob[i]
        if rex not in (0x48, 0x49, 0x4C, 0x4D) or not (0xB8 <= blob[i + 1] <= 0xBF):
            continue
        reg = (blob[i + 1] & 7) + (8 if rex & 1 else 0)
        imm = struct.unpack_from("<Q", blob, i + 2)[0]
        for j in range(i + 10, min(i + 36, n - 8)):
            rj = blob[j]
            if rj not in (0x48, 0x49, 0x4C, 0x4D) or blob[j + 1] not in (0x81, 0x83):
                continue
            modrm = blob[j + 2]
            if modrm >> 6 != 3:
                continue
            rm = (modrm & 7) + (8 if rj & 1 else 0)
            if rm != reg:
                continue
            imm2 = struct.unpack_from("<i", blob, j + 3)[0]
            step = 7 if blob[j + 1] == 0x81 else 4
            for k in range(j + step, min(j + step + 12, n - 2)):
                if blob[k] in (0x40, 0x41):
                    if blob[k + 1] == 0xFF and (blob[k + 2] & 0xF8) == 0xE0:
                        jreg = (blob[k + 2] & 7) + (8 if blob[k] & 1 else 0)
                        if jreg == reg:
                            hits.append(dict(site=sec["va"] + k, movabs=sec["va"] + i,
                                             target=(imm + imm2) & 0xFFFFFFFFFFFFFFFF,
                                             op="add" if blob[j + 1] == 0x81 else "add8",
                                             reg=REG[reg], sec=sec["name"]))
                elif blob[k] == 0xFF and (blob[k + 1] & 0xF8) == 0xE0:
                    if (blob[k + 1] & 7) == reg:
                        hits.append(dict(site=sec["va"] + k, movabs=sec["va"] + i,
                                         target=(imm + imm2) & 0xFFFFFFFFFFFFFFFF,
                                         op="add", reg=REG[reg], sec=sec["name"]))
    return hits


def main():
    pe = PEFile(TARGET)
    hits = []
    for sec in pe.sections:
        if sec["raw_size"] < 32 or sec["name"] in (".rsrc", ".reloc", ".pdata"):
            continue
        hits += scan_section(pe, sec)

    valid = [h for h in hits if IMAGE_BASE <= h["target"] < IMAGE_BASE + pe.size_of_image]
    print(f"computed-jump sites: {len(hits)}   targets inside image: {len(valid)}")
    by_sec = Counter(h["sec"] for h in hits)
    print("by section:", dict(by_sec))
    tgt = Counter(h["target"] - IMAGE_BASE for h in valid)
    print("distinct targets:", len(tgt))
    for t, c in tgt.most_common(12):
        print(f"  {t:#08x}  x{c}")
    pages = Counter(((h["site"] - 0) // 0x1000) * 0x1000 for h in hits)
    print("top pages:", [(hex(p), c) for p, c in pages.most_common(12)])
    json.dump(hits, open(os.path.join(OUT, "obfscan.json"), "w"), indent=1)


if __name__ == "__main__":
    main()
