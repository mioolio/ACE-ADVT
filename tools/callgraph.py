"""
callgraph.py -- build a call graph, import xref map and per-function summary
from out/model.json.

Outputs out/graph.json:
  nodes: rva -> {name, size, calls:[rva], imports:[api], jmptables:[{insn, table_rva, targets}],
                 consts:[imm...], strrefs:[...], fan_in}
  entry: DriverEntry rva
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
TARGET = r"<TARGET_SYS>"


def main():
    pe = PEFile(TARGET)
    model = json.load(open(os.path.join(OUT, "model.json"), encoding="utf-8"))
    items = {it["rva"]: it for it in model["items"]}
    labels = {int(k, 16): v for k, v in model["labels"].items()}
    iat = {int(k, 16): v for k, v in model["iat"].items()}
    funcs = model["functions"]

    # function lookup by rva
    owner = {}
    for f in funcs:
        for r in range(f["begin"], f["end"]):
            owner[r] = f["begin"]

    # global code index per function
    per_fn = collections.defaultdict(list)
    cur = None
    for rva in sorted(items):
        it = items[rva]
        f = owner.get(rva)
        if f is not None:
            per_fn[f].append(it)

    nodes = {}
    for f in funcs:
        b = f["begin"]
        body = per_fn.get(b, [])
        calls, imports, strrefs, consts = [], [], [], []
        for it in body:
            if it["kind"] != "insn":
                continue
            if it.get("branch") is not None and it["mnem"] in ("call", "jmp"):
                t = it["branch"]
                if it["mnem"] == "call" and t in owner:
                    calls.append(t)
            if it.get("ripref") is not None:
                t = it["ripref"]
                if t in iat:
                    imports.append(iat[t])
                else:
                    s = pe.section_of_rva(t)
                    if s is not None and s["name"] in (".rdata", ".data"):
                        off = pe.rva2off(t)
                        if off is not None:
                            raw = pe.data[off : off + 64]
                            end = raw.find(b"\0")
                            if 8 <= end and all(0x20 <= c < 0x7F for c in raw[:end]):
                                strrefs.append(raw[:end].decode())
        nodes[b] = dict(name=labels.get(b, f"sub_{b:x}"), begin=b, end=f["end"],
                        size=f["end"] - f["begin"], calls=sorted(set(calls)),
                        imports=imports, strrefs=strrefs, fan_in=0)

    for b, n in nodes.items():
        for c in n["calls"]:
            if c in nodes:
                nodes[c]["fan_in"] += 1

    with open(os.path.join(OUT, "graph.json"), "w", encoding="utf-8") as fh:
        json.dump(dict(entry=model["entry_point"], nodes=nodes), fh, indent=1)

    top = sorted(nodes.values(), key=lambda n: -n["fan_in"])[:25]
    print("== top fan-in ==")
    for n in top:
        print(f"{n['name']:14s} fan_in={n['fan_in']:4d} size={n['size']:6d} "
              f"api={sorted(set(n['imports']))[:4]}")
    print("\n== nodes", len(nodes), " edges", sum(len(n['calls']) for n in nodes.values()))
    api = collections.Counter(i for n in nodes.values() for i in n["imports"])
    print("\n== import xref by function count ==")
    for a, c in api.most_common(30):
        print(f"{c:4d} funcs  {a}")


if __name__ == "__main__":
    main()
