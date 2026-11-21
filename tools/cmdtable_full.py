"""
cmdtable_full.py -- decode every command-table record in the image.

Record layout (12 bytes, .data starting ~0x3501C):
    +0  DWORD magic    (0x013500CA for the 0x63AE44xx family, 0x013500CE for 0x623782xx)
    +4  DWORD flag     (always 1 in observed records)
    +8  DWORD token    (command token; family base + k)

The decoder walks the .data region and emits every well-formed record, so the
complete command space (including the families that never appear in the
dispatch chain) becomes visible.
"""
from __future__ import annotations

import json
import os
import struct
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from pe_model import PEFile  # noqa: E402

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
OUT = os.path.join(ROOT, "out")
TARGET = r"<TARGET_SYS>"
SCAN_START, SCAN_END = 0x35000, 0x35400
MAGICS = {0x013500CA, 0x013500CE}
FAMILIES = {0x63AE442D: "main", 0x623782AB: "aux"}


def family_of(tok):
    for base, name in FAMILIES.items():
        if base <= tok <= base + 0x40:
            return name, tok - base
    return None, None


def main():
    pe = PEFile(TARGET)
    rows = []
    rva = SCAN_START
    while rva < SCAN_END - 12:
        off = pe.rva2off(rva)
        if off is None:
            break
        magic, flag, tok = struct.unpack_from("<III", pe.data, off)
        if magic in MAGICS and flag in (0, 1) and tok >= 0x60000000:
            fam, k = family_of(tok)
            rows.append(dict(rva=rva, magic=magic, flag=flag, token=tok, family=fam, k=k))
            rva += 12
        else:
            rva += 4

    print(f"records: {len(rows)}")
    for r in rows:
        fam = r["family"] or "?"
        kk = f"k={r['k']:2d}" if r["k"] is not None else "k= ?"
        print(f"  {r['rva']:#08x}  magic={r['magic']:#010x}  flag={r['flag']}  "
              f"token={r['token']:#010x}  [{fam:4s} {kk}]")

    fams = {}
    for r in rows:
        fams.setdefault(r["family"] or "?", []).append(r["k"])
    print("\nfamilies:")
    for f, ks in fams.items():
        print(f"  {f}: {len(ks)} records, k = {sorted(x for x in ks if x is not None)}")

    json.dump(rows, open(os.path.join(OUT, "cmd_table_full.json"), "w"), indent=1)


if __name__ == "__main__":
    main()
