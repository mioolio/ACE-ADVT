"""
immref.py -- search every section for immediates that point at a given RVA or
equal a given constant (used to find indirect consumers of the command table).
"""
from __future__ import annotations

import os
import struct
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from pe_model import PEFile, IMAGE_BASE  # noqa: E402

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
TARGET = r"<TARGET_SYS>"


def find(pe, value, size):
    pat = (value & ((1 << (size * 8)) - 1)).to_bytes(size, "little")
    hits = []
    for sec in pe.sections:
        blob = pe.data[sec["raw_ptr"] : sec["raw_ptr"] + sec["raw_size"]]
        i = blob.find(pat)
        while i >= 0:
            hits.append((sec["name"], sec["va"] + i))
            i = blob.find(pat, i + 1)
    return hits


def main():
    pe = PEFile(TARGET)
    targets = [
        ("table base (imm64 VA)", IMAGE_BASE + 0x35040, 8),
        ("table base (rva32)", 0x35040, 4),
        ("record magic 0x13500CA", 0x013500CA, 4),
        ("token base 0x63AE442D", 0x63AE442D, 4),
        ("token k=18 0x63AE443F", 0x63AE443F, 4),
    ]
    for name, val, size in targets:
        hits = find(pe, val, size)
        print(f"{name}: {len(hits)} hits")
        for sec, rva in hits[:8]:
            print(f"   {sec:7s} {rva:#08x}")
    # dump the bytes around the table start to see the record from a data view
    off = pe.rva2off(0x35030)
    print("\nbytes @0x35030:", pe.data[off : off + 0x30].hex())
    off = pe.rva2off(0x35124)
    print("bytes @0x35124 (after table):", pe.data[off : off + 0x40].hex())


if __name__ == "__main__":
    main()
