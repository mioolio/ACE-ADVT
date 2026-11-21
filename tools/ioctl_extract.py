"""
ioctl_extract.py -- enumerate the device-control codes and summarise each arm.

The protected dispatcher compares the requested code against a chain of
immediates (`cmp r8d, imm32`).  Every such immediate is a CTL_CODE, so the whole
control surface can be recovered statically without executing anything.

For each code the arm is traced a little way so the report can say what it does
in terms of helper calls and global state.
"""
from __future__ import annotations

import json
import os
import struct
import sys
from collections import Counter

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
sys.argv_backup = sys.argv
from pe_model import PEFile  # noqa: E402
import trace as tracer  # noqa: E402

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
OUT = os.path.join(ROOT, "out")
TARGET = r"<TARGET_SYS>"

CMP_OPS = {
    0xF8: "r8d", 0xF9: "r9d", 0xFA: "r10d", 0xFB: "r11d", 0xFC: "r12d",
    0xFD: "r13d", 0xFE: "r14d", 0xFF: "r15d",
}


def decode(code):
    return dict(device_type=(code >> 16) & 0xFFFF,
                access=(code >> 14) & 3,
                function=(code >> 2) & 0xFFF,
                method=code & 3)


def main():
    pe = PEFile(TARGET)
    tv = [s for s in pe.sections if s["name"] == ".tvm0"][0]
    blob = pe.data[tv["raw_ptr"] : tv["raw_ptr"] + tv["raw_size"]]
    base = tv["va"]

    found = {}
    for i in range(len(blob) - 7):
        # 41 81 F8+ /r  imm32   -> cmp r8d..r15d, imm32
        if blob[i] == 0x41 and blob[i + 1] == 0x81 and blob[i + 2] in CMP_OPS:
            code = struct.unpack_from("<I", blob, i + 3)[0]
            if (code >> 16) in (0x22, 0x8000, 0x8001, 0x8002, 0x9C40):
                found.setdefault(code, []).append((base + i, CMP_OPS[blob[i + 2]]))
        # 81 F8..FF  imm32 -> cmp eax..edi, imm32
        elif blob[i] == 0x81 and blob[i + 1] in (0xF8, 0xF9, 0xFA, 0xFB, 0xFC, 0xFD, 0xFE, 0xFF):
            code = struct.unpack_from("<I", blob, i + 2)[0]
            if (code >> 16) in (0x22, 0x8000, 0x8001, 0x8002, 0x9C40):
                found.setdefault(code, []).append((base + i, "r32"))
        elif blob[i] == 0x3D:
            code = struct.unpack_from("<I", blob, i + 1)[0]
            if (code >> 16) in (0x22, 0x8000, 0x8001, 0x8002, 0x9C40):
                found.setdefault(code, []).append((base + i, "eax"))

    print(f"distinct CTL_CODE constants: {len(found)}")
    rows = []
    for code, sites in sorted(found.items()):
        d = decode(code)
        rows.append(dict(code=code, **d, sites=[hex(s) for s, _ in sites]))
        print(f"  0x{code:08X}  dev=0x{d['device_type']:04X} fn=0x{d['function']:03X} "
              f"method={d['method']} access={d['access']}  sites={len(sites)}")
    json.dump(rows, open(os.path.join(OUT, "ioctl_codes.json"), "w"), indent=1)

    # group by method/access to see the interface style
    style = Counter((r["method"], r["access"]) for r in rows)
    print("\n(method, access) ->", {f"{m}/{a}": n for (m, a), n in style.items()})
    print("methods: 0=BUFFERED 1=IN_DIRECT 2=OUT_DIRECT 3=NEITHER")
    print("access : 0=ANY 1=READ 2=WRITE 3=BOTH")


if __name__ == "__main__":
    main()
