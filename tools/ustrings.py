"""
ustrings.py -- dump UTF-16 and ASCII strings from a component's data sections.

usage: python tools/ustrings.py <binary> [minlen] [filter]

ACE-BASE.sys keeps a plaintext UTF-16 table (device names, dynamically resolved
API names, registry paths), which is the fastest way to describe what a kernel
component does without unpacking .tvm0.
"""
from __future__ import annotations

import os
import re
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from pe_model import PEFile  # noqa: E402


def main():
    path = sys.argv[1]
    minlen = int(sys.argv[2]) if len(sys.argv) > 2 else 6
    filt = sys.argv[3].lower() if len(sys.argv) > 3 else ""
    pe = PEFile(path)
    print(f"== {os.path.basename(path)} : {len(pe.data):,} bytes ==")
    total = 0
    for sec in pe.sections:
        if sec["name"] not in (".rdata", ".data", "PAGE", ".tvm0"):
            continue
        blob = pe.data[sec["raw_ptr"] : sec["raw_ptr"] + sec["raw_size"]]
        items = []
        for m in re.finditer(rb"(?:[\x20-\x7e]\x00){%d,}" % minlen, blob):
            t = m.group().decode("utf-16-le")
            items.append((sec["va"] + m.start(), t))
        for m in re.finditer(rb"[\x20-\x7e]{%d,}" % minlen, blob):
            t = m.group().decode("ascii")
            items.append((sec["va"] + m.start(), t))
        items.sort()
        seen = set()
        for rva, t in items:
            if filt and filt not in t.lower():
                continue
            if t in seen:
                continue
            seen.add(t)
            total += 1
            print(f"  {rva:08x} [{sec['name']:6s}] {t}")
    print(f"\n{total} unique strings")


if __name__ == "__main__":
    main()
