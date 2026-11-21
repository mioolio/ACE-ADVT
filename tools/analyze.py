"""
analyze.py -- recover the code/data partition of ACE-ADVT.sys and disassemble it.

Pipeline
  1. function boundaries: exception directory (RVA 0x124000) U .pdata section copy
  2. recursive descent over .text + INIT seeded by every function entry, every
     branch target and the PE entry point
  3. uncovered bytes: int3 runs -> padding item, decodable -> instruction,
     otherwise 1-byte data item
  4. the section becomes a strict partition: sum(size) == raw size, no overlap
  5. labels minted for every referenced start
  6. emit out/model.json and out/listing/ACE-ADVT.txt

Coverage discipline: every item is written only over bytes that are still
unclaimed, so duplicate/overlapping unwind records can never corrupt the layout.
"""
from __future__ import annotations

import bisect
import json
import os
import re
import struct
import sys
from collections import defaultdict

from capstone import Cs, CS_ARCH_X86, CS_MODE_64
from capstone.x86 import X86_OP_IMM, X86_OP_MEM, X86_REG_RIP

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from pe_model import PEFile, IMAGE_BASE  # noqa: E402

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
TARGET = os.environ.get("ADVT_TARGET", r"<TARGET_SYS>")
OUT = os.path.join(ROOT, "out")
CODE_SECTIONS = (".text", "INIT")

MD = Cs(CS_ARCH_X86, CS_MODE_64)
MD.detail = True

SIZE_KW = [
    ("xmmword ptr ", "oword "), ("ymmword ptr ", "yword "), ("tbyte ptr ", "tword "),
    ("qword ptr ", "qword "), ("dword ptr ", "dword "), ("word ptr ", "word "),
    ("byte ptr ", "byte "), ("mmword ptr ", "qword "),
]


class Coverage:
    """interval set over section RVAs; items never overlap."""

    def __init__(self, base, size):
        self.base = base
        self.size = size
        self.starts = []      # sorted item starts
        self.sizes = {}       # start -> size

    def covering_end(self, rva):
        i = bisect.bisect_right(self.starts, rva) - 1
        if i >= 0:
            s = self.starts[i]
            if s + self.sizes[s] > rva:
                return s + self.sizes[s]
        return None

    def free(self, rva):
        return self.covering_end(rva) is None

    def next_start(self, rva):
        i = bisect.bisect_right(self.starts, rva)
        return self.starts[i] if i < len(self.starts) else None

    def room(self, rva, hard_limit):
        """max bytes an item starting at rva may take without touching a neighbour."""
        ns = self.next_start(rva)
        return min(hard_limit - rva, ns - rva) if ns is not None else hard_limit - rva

    def add(self, rva, size):
        assert self.free(rva), f"overlap at {rva:#x}"
        assert rva + size <= self.base + self.size, f"out of range {rva:#x}+{size:#x}"
        # nothing may be claimed after this start inside the range
        i = bisect.bisect_right(self.starts, rva)
        if i < len(self.starts):
            nxt = self.starts[i]
            assert nxt >= rva + size, f"item {rva:#x}+{size:#x} swallows {nxt:#x}"
        bisect.insort(self.starts, rva)
        self.sizes[rva] = size


def load_ref():
    return PEFile(TARGET)


def read_exc_table(pe, rva, size):
    off = pe.rva2off(rva)
    out = []
    for i in range(size // 12):
        b, e, u = struct.unpack_from("<III", pe.data, off + i * 12)
        if b and e and e > b:
            out.append((b, e, u))
    return out


def build_function_map(pe):
    funcs, sources = {}, {}
    for name, (rva, size) in (("exc", pe.directory(3)), ("pdata", (0x42000, 0x3084))):
        if not rva or not size:
            continue
        off = pe.rva2off(rva)
        if off is None:
            continue
        for b, e, u in read_exc_table(pe, rva, size):
            s = pe.section_of_rva(b)
            if s is None or s["name"] not in (".text", "INIT", ".tvm0"):
                continue
            funcs[(b, e)] = u
            sources.setdefault((b, e), set()).add(name)
    return funcs, sources


def parse_imports(pe):
    """map IAT slot RVA -> 'module!symbol'"""
    rva, size = pe.directory(1)
    off = pe.rva2off(rva)
    iat, idx = {}, 0
    while idx < size:
        base = off + idx
        ilt, stamp, chain, name_rva, first_thunk = struct.unpack_from("<IIIII", pe.data, base)
        if name_rva == 0:
            break
        dll_off = pe.rva2off(name_rva)
        end = pe.data.index(b"\0", dll_off)
        dll = pe.data[dll_off:end].decode("ascii", "replace")
        thunk = ilt or first_thunk
        j = 0
        while True:
            toff = pe.rva2off(thunk + j * 8)
            if toff is None:
                break
            v = struct.unpack_from("<Q", pe.data, toff)[0]
            if v == 0:
                break
            slot = first_thunk + j * 8
            if v & (1 << 63):
                iat[slot] = f"{dll}!ord_{v & 0xFFFF}"
            else:
                noff = pe.rva2off(v & 0x7FFFFFFF)
                nm_end = pe.data.index(b"\0", noff + 2)
                iat[slot] = f"{dll}!{pe.data[noff + 2:nm_end].decode('ascii', 'replace')}"
            j += 1
        idx += 20
    return iat


def insn_record(insn):
    rva = insn.address - IMAGE_BASE
    rec = dict(rva=rva, size=insn.size, kind="insn",
               mnem=insn.mnemonic, ops=insn.op_str,
               bytes=insn.bytes.hex(), branch=None, ripref=None)
    ops = insn.operands
    if ops and insn.mnemonic in ("call", "jmp") or (insn.mnemonic.startswith("j") and ops):
        if ops[0].type == X86_OP_IMM:
            rec["branch"] = ops[0].imm - IMAGE_BASE
        elif ops[0].type == X86_OP_MEM and ops[0].mem.base == X86_REG_RIP:
            rec["ripref"] = insn.address + insn.size + ops[0].mem.disp - IMAGE_BASE
    if rec["ripref"] is None:
        for op in ops:
            if op.type == X86_OP_MEM and op.mem.base == X86_REG_RIP:
                rec["ripref"] = insn.address + insn.size + op.mem.disp - IMAGE_BASE
                break
    return rec


def asm_text(rec, labels):
    mnem = "mov" if rec["mnem"] == "movabs" else rec["mnem"]
    ops = rec["ops"]
    for a, b in SIZE_KW:
        ops = ops.replace(a, b)
    ops = ops.replace(" ptr ", " ")
    if ops.endswith(" ptr"):
        ops = ops[:-4]
    if rec.get("ripref") is not None:
        tgt = rec["ripref"]
        lab = labels.get(tgt)
        if lab:
            ops = re.sub(r"\[rip [+-] 0x[0-9a-f]+\]", f"[rel {lab}]", ops)
    if rec.get("branch") is not None:
        lab = labels.get(rec["branch"])
        if lab:
            ops = re.sub(r"0x[0-9a-f]+$", lab, ops)
    return (mnem + (" " + ops if ops else "")).strip()


def main():
    pe = load_ref()
    iat = parse_imports(pe)
    funcs, fsources = build_function_map(pe)

    items = {}
    cov = {}
    for sec in pe.sections:
        if sec["name"] in CODE_SECTIONS:
            cov[sec["va"]] = Coverage(sec["va"], sec["raw_size"])

    def cov_for(rva):
        for base, c in cov.items():
            if base <= rva < base + c.size:
                return c
        return None

    def add(rec):
        c = cov_for(rec["rva"])
        assert c is not None, f"{rec['rva']:#x} outside code sections"
        c.add(rec["rva"], rec["size"])
        items[rec["rva"]] = rec
        return rec

    # ---- pass 1: recursive descent (entry + all unwind entries) -----------
    work = [pe.entry_point]
    work.extend(b for (b, e) in funcs)
    work.sort()
    tail_calls = 0
    guard = 0
    while work and guard < 4_000_000:
        guard += 1
        rva = work.pop()
        c = cov_for(rva)
        if c is None or not c.free(rva):
            continue
        limit = c.base + c.size
        pos = rva
        while pos < limit:
            if not c.free(pos):
                break
            b0 = pe.bytes_at_rva(pos, 1)[0]
            if b0 == 0xCC:
                break  # padding run: leave to pass 2
            room = c.room(pos, limit)
            got = None
            for insn in MD.disasm(pe.bytes_at_rva(pos, min(16, room)), IMAGE_BASE + pos):
                got = insn
                break
            if got is None:
                break
            rec = insn_record(got)
            add(rec)
            if rec.get("branch") is not None:
                work.append(rec["branch"])
                tail_calls += 1
            pos += rec["size"]
            if rec["mnem"] in ("ret", "ud2"):
                break
            if rec["mnem"] == "jmp" and rec.get("branch") is not None:
                break
            if rec["mnem"] == "int3":
                break

    # ---- pass 3: fill remaining bytes ------------------------------------
    for sec in pe.sections:
        if sec["name"] not in CODE_SECTIONS:
            continue
        c = cov[sec["va"]]
        base = sec["va"] + sec["raw_ptr"] - sec["va"]  # unused, keep offsets explicit
        raw_off = sec["raw_ptr"]
        start, end = sec["va"], sec["va"] + sec["raw_size"]
        pos = start
        while pos < end:
            ce = c.covering_end(pos)
            if ce is not None:
                pos = ce
                continue
            run = 0
            while pos + run < end and c.free(pos + run) and \
                    pe.data[raw_off + (pos - sec["va"]) + run] == 0xCC:
                run += 1
            if run:
                add(dict(rva=pos, size=run, kind="pad", bytes=pe.bytes_at_rva(pos, run).hex()))
                pos += run
                continue
            # printable-ASCII island -> embedded text blob, not code
            first = pe.data[raw_off + (pos - sec["va"])]
            if 0x20 <= first <= 0x7E:
                run = 0
                while pos + run < end and c.free(pos + run):
                    ch = pe.data[raw_off + (pos - sec["va"]) + run]
                    if not (0x20 <= ch <= 0x7E):
                        break
                    run += 1
                if run >= 4:
                    add(dict(rva=pos, size=run, kind="data",
                             bytes=pe.bytes_at_rva(pos, run).hex(), note="text-blob"))
                    pos += run
                    continue
            # zero island -> alignment / pointer table
            if first == 0x00:
                run = 0
                while pos + run < end and c.free(pos + run) and \
                        pe.data[raw_off + (pos - sec["va"]) + run] == 0x00:
                    run += 1
                if run >= 4:
                    add(dict(rva=pos, size=run, kind="data",
                             bytes=pe.bytes_at_rva(pos, run).hex(), note="zero-blob"))
                    pos += run
                    continue
            room = c.room(pos, end)
            got = None
            for insn in MD.disasm(pe.bytes_at_rva(pos, min(16, room)), IMAGE_BASE + pos):
                got = insn
                break
            if got is None:
                add(dict(rva=pos, size=1, kind="data", bytes=pe.bytes_at_rva(pos, 1).hex(),
                         note="undecodable"))
                pos += 1
                continue
            rec = insn_record(got)
            rec["note"] = "swept"
            add(rec)
            pos += rec["size"]

    # ---- verify strict partition ----------------------------------------
    order = sorted(items)
    for sec in pe.sections:
        if sec["name"] not in CODE_SECTIONS:
            continue
        expect = sec["va"]
        for rva in order:
            if sec["va"] <= rva < sec["va"] + sec["raw_size"]:
                assert rva == expect, f"hole at {expect:#x} (next item {rva:#x}) in {sec['name']}"
                expect = rva + items[rva]["size"]
        assert expect == sec["va"] + sec["raw_size"], \
            f"{sec['name']} tail hole: {expect:#x} != {sec['va'] + sec['raw_size']:#x}"

    # ---- labels ----------------------------------------------------------
    used = set()
    for it in items.values():
        if it.get("branch") is not None:
            used.add(it["branch"])
        if it.get("ripref") is not None:
            used.add(it["ripref"])
    func_begins = {b for (b, e) in funcs if b in items}
    used |= func_begins
    used.add(pe.entry_point)

    labels = {}
    for rva in sorted(used):
        it = items.get(rva)
        if it is None:
            continue
        if rva == pe.entry_point:
            labels[rva] = "DriverEntry"
        elif rva in func_begins:
            labels[rva] = f"sub_{rva:x}"
        else:
            labels[rva] = {"insn": "loc", "pad": "pad", "data": "dat"}[it["kind"]] + f"_{rva:x}"

    def cstr_at(rva):
        s = pe.section_of_rva(rva)
        if s is None or s["name"] not in (".rdata", ".data"):
            return None
        off = pe.rva2off(rva)
        if off is None:
            return None
        end = pe.data.find(b"\0", off, off + 120)
        if end <= off + 2:
            return None
        raw = pe.data[off:end]
        if any(ch < 0x20 or ch > 0x7E for ch in raw):
            return None
        return raw.decode("ascii", "replace")

    # ---- listing ---------------------------------------------------------
    os.makedirs(os.path.join(OUT, "listing"), exist_ok=True)
    lines = [
        "; ACE-ADVT.sys -- full static disassembly (code sections)",
        f"; reference sha256 {pe.sha256()}",
        f"; image base {IMAGE_BASE:#x}  entry {pe.entry_point:#x}  "
        f"unwind records {len(funcs)}  items {len(items)}",
        "",
    ]
    cur_sec = None
    for rva in order:
        it = items[rva]
        sec = pe.section_of_rva(rva)
        if sec and sec["name"] != cur_sec:
            cur_sec = sec["name"]
            lines += ["", f"; ===== section {cur_sec} @ {sec['va']:#x} ====="]
        lab = labels.get(rva)
        if lab:
            lines += ["", f"{lab}:"]
        comment = ""
        if it["kind"] == "insn":
            if it.get("ripref") in iat:
                comment = "; " + iat[it["ripref"]]
            elif it.get("ripref") is not None:
                st = cstr_at(it["ripref"])
                if st:
                    comment = f'; "{st}"'
                elif labels.get(it["ripref"]):
                    comment = "; " + labels[it["ripref"]]
            elif it.get("branch") is not None and labels.get(it["branch"]):
                comment = "; -> " + labels[it["branch"]]
            txt = asm_text(it, labels)
        elif it["kind"] == "pad":
            txt = f"times {it['size']} db 0cch"
            comment = "; int3 padding"
        else:
            txt = f"db {it['size']} byte(s)"
            comment = "; " + (it.get("note") or "data")
        lines.append(f"{rva:08x}  {it['bytes']:<34} {txt:<50} {comment}".rstrip())

    with open(os.path.join(OUT, "listing", "ACE-ADVT.txt"), "w", encoding="utf-8") as f:
        f.write("\n".join(lines) + "\n")

    model = dict(
        image_base=IMAGE_BASE,
        entry_point=pe.entry_point,
        sha256=pe.sha256(),
        items=[items[r] for r in order],
        labels={f"{k:x}": v for k, v in labels.items()},
        iat={f"{k:x}": v for k, v in iat.items()},
        functions=[dict(begin=b, end=e, unwind=u, sources=sorted(fsources.get((b, e), [])))
                   for (b, e), u in sorted(funcs.items())],
    )
    with open(os.path.join(OUT, "model.json"), "w", encoding="utf-8") as f:
        json.dump(model, f, indent=1)

    n_insn = sum(1 for i in items.values() if i["kind"] == "insn")
    n_pad = sum(i["size"] for i in items.values() if i["kind"] == "pad")
    n_data = sum(1 for i in items.values() if i["kind"] == "data")
    print(f"items={len(items)} insns={n_insn} pad_bytes={n_pad} data_items={n_data} "
          f"labels={len(labels)} funcs={len(funcs)}")


if __name__ == "__main__":
    main()
