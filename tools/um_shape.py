"""
um_shape.py -- section/entropy/import shape for the ACE binaries.

Uses the project's own PEFile (dict sections) so it works on every component,
including the packed kernel drivers, and shows whether a binary is packed
(entropy > 7.2 on a big section) or has the .tvm0-style protector segment.
"""
from __future__ import annotations

import math
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from pe_model import PEFile  # noqa: E402

ROOT = r"<ACE_ROOT>"
TARGETS = [
    "ACE-BASE.sys", "ACE-BOOT.sys", "ACE-CORE302706.sys",
    "ACE-Service64.exe", "ACE-Tray.exe", "Uninstaller.exe",
    r"SGuard\x64\SGuard64.exe", r"SGuard\x64\SGuardSvc64.exe",
    r"SGuard\x64\SGuardUpdate64.exe", r"SGuard\x64\Uninstall64.exe",
    r"SGuard\x64\ACE-Safe.dll", r"SGuard\x64\ACE-Trace.dll",
    r"SGuard\x64\Plugins\ACE-ATS64.dll", r"SGuard\x64\Plugins\ACE-CSI64.dll",
    r"SGuard\x64\Plugins\ACE-DFS64.dll", r"SGuard\x64\Plugins\ACE-DRV64.dll",
    r"SGuard\x64\Plugins\ACE-SSC64.dll", r"SGuard\x64\Plugins\ACE-SSC-DRV64.sys",
]


def entropy(b: bytes) -> float:
    if not b:
        return 0.0
    h = [0] * 256
    for c in b:
        h[c] += 1
    return -sum((x / len(b)) * math.log2(x / len(b)) for x in h if x)


def main():
    for rel in TARGETS:
        path = os.path.join(ROOT, rel)
        if not os.path.exists(path):
            print(f"{rel}: MISSING")
            continue
        pe = PEFile(path)
        packed = sum(1 for s in pe.sections if entropy(s.get("data", b"")) > 7.2 and s["raw_size"] > 0x4000)
        print(f"\n=== {rel} ===")
        print(f"  size {len(pe.data):,}  sections {len(pe.sections)}  "
              f"subsystem {pe.subsystem}  ep {pe.entry_point:#x}  packed-sections {packed}")
        for s in pe.sections:
            blob = pe.data[s["raw_ptr"] : s["raw_ptr"] + s["raw_size"]]
            print(f"    {s['name']:10s} va={s['va']:#08x} vsize={s['vsize']:#9x} "
                  f"raw={s['raw_size']:#9x} ent={entropy(blob):5.2f} "
                  f"chars={s['chars']:#010x}")


if __name__ == "__main__":
    main()
