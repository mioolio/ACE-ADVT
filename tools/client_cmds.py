"""
client_cmds.py -- recover the user-mode command table by scanning for the
record-building idiom

    BA <imm32>                 mov edx, <token>
    41 B8 CA 00 35 01          mov r8d, 0x013500CA      (table magic)
    E8 <rel32>                 call <record helper>

Every hit is one command the client knows about, with the family token and the
call site, which maps the client API onto the driver's token space (docs/09).
"""
from __future__ import annotations

import os
import struct
import sys
from collections import defaultdict

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from pe_model import PEFile  # noqa: E402

ROOT = r"<ACE_ROOT>"
MAGIC = struct.pack("<I", 0x013500CA)
FAMILIES = {0x63AE442D: "main", 0x623782AB: "aux"}


def classify(tok):
    for base, name in FAMILIES.items():
        if base <= tok <= base + 0x60:
            return name, tok - base
    return None, None


def main():
    found = defaultdict(list)
    for dirpath, _d, files in os.walk(ROOT):
        for fn in files:
            if not fn.lower().endswith((".exe", ".dll", ".sys")):
                continue
            path = os.path.join(dirpath, fn)
            rel = os.path.relpath(path, ROOT)
            try:
                pe = PEFile(path)
            except Exception:
                continue
            data = pe.data
            for s in pe.sections:
                blob = data[s["raw_ptr"] : s["raw_ptr"] + s["raw_size"]]
                base = s["va"]
                i = 0
                while True:
                    j = blob.find(MAGIC, i)
                    if j < 0:
                        break
                    i = j + 1
                    # look back up to 12 bytes for `BA imm32`
                    for k in range(j - 12, j):
                        if k < 0 or blob[k] != 0xBA:
                            continue
                        tok = struct.unpack_from("<I", blob, k + 1)[0]
                        fam, idx = classify(tok)
                        if fam:
                            found[fam].append(dict(binary=rel, section=s["name"],
                                                   rva=base + k, token=tok, k=idx))
                            break
    for fam in ("main", "aux"):
        rows = sorted({(r["binary"], r["rva"], r["k"]) for r in found[fam]})
        print(f"\n=== family {fam}: {len(rows)} client call sites ===")
        by_bin = defaultdict(list)
        for b, rva, k in rows:
            by_bin[b].append((k, rva))
        for b in sorted(by_bin):
            ks = sorted({k for k, _ in by_bin[b]})
            print(f"  {b}: {len(by_bin[b])} sites, k = {ks}")
    import json
    json.dump({f: sorted({(r["binary"], r["rva"], r["k"]) for r in found[f]})
               for f in ("main", "aux")},
              open(os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))),
                                "out", "client_cmds.json"), "w"), indent=1)


if __name__ == "__main__":
    main()
