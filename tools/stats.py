"""
stats.py -- numbers used by the documentation (imports xref, mnemonic mix,
function size histogram, section table).
"""
from __future__ import annotations

import collections
import json
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from pe_model import PEFile, IMAGE_BASE  # noqa: E402

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
OUT = os.path.join(ROOT, "out")
TARGET = os.environ.get("ADVT_TARGET", r"<TARGET_SYS>")


def main():
    pe = PEFile(TARGET)
    model = json.load(open(os.path.join(OUT, "model.json"), encoding="utf-8"))
    items = model["items"]
    iat = {int(k, 16): v for k, v in model["iat"].items()}

    print("== sections ==")
    for s in pe.sections:
        print(f"{s['name']:8s} va={s['va']:#08x} vsize={s['vsize']:#8x} "
              f"raw={s['raw_ptr']:#08x}+{s['raw_size']:#7x} chars={s['chars']:#010x}")

    print("\n== imports by module ==")
    mods = collections.Counter(v.split("!")[0] for v in iat.values())
    for m, c in mods.items():
        print(f"{m:16s} {c}")
    print("total slots", len(iat))

    print("\n== hottest imported APIs (direct call/jmp through IAT) ==")
    calls = collections.Counter()
    for it in items:
        if it["kind"] == "insn" and it.get("ripref") in iat:
            calls[iat[it["ripref"]]] += 1
    for api, c in calls.most_common(20):
        print(f"{c:5d}  {api}")

    print("\n== mnemonic mix ==")
    mix = collections.Counter(it["mnem"] for it in items if it["kind"] == "insn")
    total = sum(mix.values())
    for m, c in mix.most_common(20):
        print(f"{m:12s} {c:6d}  {c/total*100:5.2f}%")

    print("\n== item kinds ==")
    kinds = collections.Counter(it["kind"] for it in items)
    print(dict(kinds))
    print("code bytes", sum(it["size"] for it in items if it["kind"] in ("insn", "pad", "data")))

    print("\n== function size histogram ==")
    sizes = [f["end"] - f["begin"] for f in model["functions"]]
    buckets = collections.Counter()
    for s in sizes:
        if s < 0x40:
            buckets["< 64B"] += 1
        elif s < 0x100:
            buckets["64-255B"] += 1
        elif s < 0x400:
            buckets["256-1023B"] += 1
        elif s < 0x1000:
            buckets["1-4KB"] += 1
        else:
            buckets[">= 4KB"] += 1
    for k in ("< 64B", "64-255B", "256-1023B", "1-4KB", ">= 4KB"):
        print(f"{k:10s} {buckets[k]}")
    print("largest:", max(sizes), "smallest:", min(sizes), "mean: %.1f" % (sum(sizes) / len(sizes)))

    print("\n== tvм0 exc table split ==")
    tv = [f for f in model["functions"] if 0x49000 <= f["begin"] < 0x129000]
    print("functions inside .tvm0:", len(tv))
    print("unwind records total:", len(model["functions"]))


if __name__ == "__main__":
    main()
