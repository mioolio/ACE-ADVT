"""
ioctl_scan.py -- hunt for the device-control code space.

Two independent searches inside .tvm0:
  1. instruction immediates: cmp/test/sub/add against a 32-bit value whose
     DEVICE_TYPE field is 0x22 (FILE_DEVICE_UNKNOWN) or 0x8000+ (vendor range)
  2. data tables: runs of dwords that look like CTL_CODE values

CTL_CODE(DeviceType, Function, Method, Access) = (DeviceType<<16)|(Access<<14)|(Function<<2)|Method
"""
from __future__ import annotations

import json
import os
import struct
import sys
from collections import Counter, defaultdict

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from pe_model import PEFile  # noqa: E402

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
OUT = os.path.join(ROOT, "out")
TARGET = r"<TARGET_SYS>"


def looks_like_ctl(v):
    if v == 0 or v > 0xFFFFFFFF:
        return None
    dev = (v >> 16) & 0xFFFF
    func = (v >> 2) & 0xFFF
    method = v & 3
    access = (v >> 14) & 3
    if dev in (0x22, 0x9C40, 0x8000, 0x8001, 0x8002, 0x8003):
        if 0 < func < 0x1000:
            return (dev, func, method, access)
    return None


def main():
    pe = PEFile(TARGET)
    tv = [s for s in pe.sections if s["name"] == ".tvm0"][0]
    blob = pe.data[tv["raw_ptr"] : tv["raw_ptr"] + tv["raw_size"]]

    # ---- 1. immediates following cmp/test/sub/add (81 /7, /1, /5, /0 and 3D) --
    hits = []
    for i in range(len(blob) - 6):
        rex = blob[i]
        if rex in (0x48, 0x49, 0x4C, 0x4D) and blob[i + 1] == 0x81:
            modrm = blob[i + 2]
            if modrm == 0xF8 or modrm == 0xF9 or modrm == 0xFA or modrm == 0xFB:  # cmp r, imm32
                v = struct.unpack_from("<I", blob, i + 3)[0]
                t = looks_like_ctl(v)
                if t:
                    hits.append((tv["va"] + i, v, t))
        if blob[i] == 0x3D:  # cmp eax, imm32
            v = struct.unpack_from("<I", blob, i + 1)[0]
            t = looks_like_ctl(v)
            if t:
                hits.append((tv["va"] + i, v, t))

    print(f"cmp-immediate CTL_CODE candidates: {len(hits)}")
    for site, v, t in hits[:40]:
        print(f"  {site:#08x}  0x{v:08X}  dev={t[0]:#06x} fn={t[1]:#05x} method={t[2]} access={t[3]}")

    # ---- 2. dword tables -----------------------------------------------------
    tables = []
    i = 0
    while i < len(blob) - 4:
        v = struct.unpack_from("<I", blob, i)[0]
        if looks_like_ctl(v):
            start = i
            vals = []
            while i < len(blob) - 4:
                v2 = struct.unpack_from("<I", blob, i)[0]
                if looks_like_ctl(v2):
                    vals.append(v2)
                    i += 4
                else:
                    break
            if len(vals) >= 2:
                tables.append((tv["va"] + start, vals))
            continue
        i += 4
    print(f"\ndword tables that look like CTL_CODE arrays: {len(tables)}")
    for base, vals in tables[:12]:
        print(f"  {base:#08x}  n={len(vals)}: " + " ".join(f"{v:08X}" for v in vals[:8]))


if __name__ == "__main__":
    main()
