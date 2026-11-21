"""
emit_asm.py -- model.json -> modular NASM sources.

Layout produced
  src/asm/ace_advt.asm            top level: BITS 64 / org / include order
  src/asm/parts/text_NN.asm       .text, 16 chunks (~7 KB each)
  src/asm/parts/init.asm          INIT (DriverEntry)
  src/asm/parts/<sec>_data.asm    remaining sections as transcribed db blobs
  src/asm/parts/tvm0_NNN.asm     .tvm0 in 32 chunks of 28 KB

Address model
  Everything is assembled in one flat RVA space starting at org 0x1000, so a
  label is simply `image_base + rva` and every rip-relative reference and every
  branch resolves exactly like the original.  Sections whose virtual size is
  larger than their raw size get `times N db 0` virtual padding; the packer
  slices the raw part back out per section.

Byte provenance
  * code: one line per instruction, mnemonics first, original bytes as comment
  * padding: `times N db 0cch`
  * data:   `db` blobs, split at every referenced address so labels can live there
  * signature overlay: asset, appended by build.py (not inside .text math)

Overrides
  out/emit_overrides.json  { "<rva hex>": "db" }  forces a literal-byte line for
  an instruction whose re-encoding does not reproduce the original bytes. The
  build loop fills this in automatically.
"""
from __future__ import annotations

import json
import os
import re
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from pe_model import PEFile, IMAGE_BASE  # noqa: E402

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
TARGET = os.environ.get("ADVT_TARGET", r"<TARGET_SYS>")
OUT = os.path.join(ROOT, "out")
SRC = os.path.join(ROOT, "src", "asm")
PARTS = os.path.join(SRC, "parts")
OVERRIDES = os.path.join(OUT, "emit_overrides.json")

SIZE_KW = [
    ("xmmword ptr ", "oword "), ("ymmword ptr ", "yword "), ("tbyte ptr ", "tword "),
    ("qword ptr ", "qword "), ("dword ptr ", "dword "), ("word ptr ", "word "),
    ("byte ptr ", "byte "), ("mmword ptr ", "qword "),
]


def load_json(path, default):
    if os.path.exists(path):
        with open(path, encoding="utf-8") as f:
            return json.load(f)
    return default


def fmt_bytes(bs: bytes, per_line=16, prefix="db ") -> list[str]:
    lines = []
    for i in range(0, len(bs), per_line):
        chunk = bs[i : i + per_line]
        lines.append(prefix + ", ".join(f"0x{b:02x}" for b in chunk))
    return lines


def clean_ops(ops: str) -> str:
    for a, b in SIZE_KW:
        ops = ops.replace(a, b)
    ops = ops.replace(" ptr ", " ")
    if ops.endswith(" ptr"):
        ops = ops[:-4]
    ops = re.sub(r"(byte|word|dword|qword|oword|tword) (fs|gs):\[([^\]]*)\]",
                 r"\1 [\2:\3]", ops)
    ops = re.sub(r"\bst\((\d)\)", r"st\1", ops)
    return ops


class Emitter:
    def __init__(self):
        self.pe = PEFile(TARGET)
        with open(os.path.join(OUT, "model.json"), encoding="utf-8") as f:
            self.model = json.load(f)
        self.items = {it["rva"]: it for it in self.model["items"]}
        self.code_labels = {int(k, 16): v for k, v in self.model["labels"].items()}
        self.iat = {int(k, 16): v for k, v in self.model["iat"].items()}
        self.overrides = load_json(OVERRIDES, {})
        self.data_labels: dict[int, str] = {}
        self.manifest = []
        self.raw_note = {}      # rva -> original mnemonic for forced-raw lines
        self.line_map = []      # (file, lineno, rva)
        self.stats = dict(insn=0, db_fallback=0, data_lines=0, pad=0)

    # ---------- label universe ----------
    def code_base(self, rva):
        s = self.pe.section_of_rva(rva)
        return s

    def is_code_rva(self, rva):
        s = self.pe.section_of_rva(rva)
        return s is not None and s["name"] in (".text", "INIT")

    def collect_data_labels(self):
        used = set()
        for it in self.items.values():
            if it.get("ripref") is not None:
                used.add(it["ripref"])
            if it.get("branch") is not None and it["branch"] not in self.code_labels:
                used.add(it["branch"])
        for rva in sorted(used):
            if rva in self.code_labels:
                continue
            s = self.pe.section_of_rva(rva)
            if s is None:
                continue
            if self.is_code_rva(rva) and rva in self.items:
                # instruction start inside code: give it a loc label after all
                self.code_labels[rva] = f"loc_{rva:x}"
                continue
            if self.is_code_rva(rva):
                continue  # mid-instruction target: caller falls back to db
            self.data_labels[rva] = f"dat_{rva:x}"

    # ---------- instruction text ----------
    def insn_text(self, it):
        rva = it["rva"]
        if self.overrides.get(f"{rva:x}") == "db" or self.overrides.get(hex(rva)) == "db":
            self.stats["db_fallback"] += 1
            self.raw_note[rva] = f"{it['mnem']} {it['ops']}".strip() + "   (forced raw: MSVC encoding)"
            return "db " + ", ".join(f"0x{b:02x}" for b in bytes.fromhex(it["bytes"]))
        mnem = "mov" if it["mnem"] == "movabs" else it["mnem"]
        ops = clean_ops(it["ops"])
        if it.get("ripref") is not None:
            tgt = it["ripref"]
            lab = self.code_labels.get(tgt) or self.data_labels.get(tgt)
            if lab:
                ops = re.sub(r"\[rip [+-] 0x[0-9a-f]+\]", f"[rel {lab}]", ops)
            else:
                self.overrides[f"{rva:x}"] = "db"
                self.stats["db_fallback"] += 1
                self.raw_note[rva] = f"{it['mnem']} {it['ops']}".strip() + "   (forced raw: unresolved target)"
                return "db " + ", ".join(f"0x{b:02x}" for b in bytes.fromhex(it["bytes"]))
        if it.get("branch") is not None:
            tgt = it["branch"]
            lab = self.code_labels.get(tgt) or self.data_labels.get(tgt)
            if lab:
                ops = re.sub(r"0x[0-9a-f]+$", lab, ops)
            else:
                self.overrides[f"{rva:x}"] = "db"
                self.stats["db_fallback"] += 1
                self.raw_note[rva] = f"{it['mnem']} {it['ops']}".strip() + "   (forced raw: unresolved target)"
                return "db " + ", ".join(f"0x{b:02x}" for b in bytes.fromhex(it["bytes"]))
        self.stats["insn"] += 1
        return (mnem + (" " + ops if ops else "")).strip()

    # ---------- section writers ----------
    def write_chunk(self, name, lines, rva_start, rva_end, kind):
        path = os.path.join(PARTS, name)
        os.makedirs(PARTS, exist_ok=True)
        first_line = 4
        linemap = []
        with open(path, "w", encoding="utf-8") as f:
            f.write(f"; {name}  [{rva_start:#x} .. {rva_end:#x})  {kind}\n")
            f.write(f"; generated by emit_asm.py -- do not hand edit\n\n")
            for lineno, (txt, comment, rva) in enumerate(lines, start=first_line):
                if rva is not None:
                    marker = f";@{rva:x}"
                    if comment:
                        f.write(f"{txt:<52}{marker} {comment}\n")
                    else:
                        f.write(f"{txt:<52}{marker}\n")
                    linemap.append((lineno, rva))
                else:
                    f.write(f"{txt}\n")
        with open(path + ".map", "w", encoding="utf-8") as f:
            for lineno, rva in linemap:
                f.write(f"{lineno} {rva:x}\n")
        rel = os.path.relpath(path, SRC).replace("\\", "/")
        self.manifest.append(dict(file=rel, rva_start=rva_start, rva_end=rva_end, kind=kind,
                                  lines=len(lines), first_line=first_line))

    def emit_code_range(self, rva_start, rva_end, chunk_bytes=0x2D88, tag="text"):
        chunk_start = rva_start
        lines = []
        n_chunk = 0
        cur = rva_start
        while cur < rva_end:
            it = self.items.get(cur)
            if it is None:
                raise SystemExit(f"model hole at {cur:#x}")
            if cur - chunk_start >= chunk_bytes:
                n_chunk += 1
                self.write_chunk(f"{tag}_{n_chunk:02d}.asm", lines, chunk_start, cur, "code")
                lines = []
                chunk_start = cur
            lab = self.code_labels.get(cur)
            if lab:
                lines.append((f"{lab}:", "", cur))
            if it["kind"] == "insn":
                txt = self.insn_text(it)
                cm = self.raw_note.get(cur, f"{it['bytes']}")
                if it.get("ripref") in self.iat:
                    cm += f"   ; {self.iat[it['ripref']]}"
                lines.append((txt, cm, cur))
            elif it["kind"] == "pad":
                lines.append((f"times {it['size']} db 0cch", "int3 padding", cur))
                self.stats["pad"] += it["size"]
            else:
                bs = bytes.fromhex(it["bytes"])
                sub = fmt_bytes(bs)
                for i, l in enumerate(sub):
                    lines.append((l, it.get("note") or "data" if i == 0 else "", cur + i * 16))
                self.stats["data_lines"] += len(sub)
            cur += it["size"]
        if lines:
            n_chunk += 1
            self.write_chunk(f"{tag}_{n_chunk:02d}.asm", lines, chunk_start, rva_end, "code")

    def emit_data_range(self, sec_name, rva_start, rva_end, chunk_bytes=0x7000, tag=None):
        tag = tag or re.sub(r"[^a-z0-9]", "", sec_name.lower())
        data = self.pe.bytes_at_rva(rva_start, rva_end - rva_start)
        labels = {r: v for r, v in self.data_labels.items() if rva_start <= r < rva_end}
        lines = []
        chunk_start = rva_start
        cur = rva_start
        acc = bytearray()
        acc_rva = rva_start

        def flush_acc():
            nonlocal acc, acc_rva
            if acc:
                for i, l in enumerate(fmt_bytes(bytes(acc))):
                    lines.append((l, "", acc_rva + i * 16))
                self.stats["data_lines"] += (len(acc) + 15) // 16
                acc = bytearray()
                acc_rva = cur

        while cur < rva_end:
            if cur - chunk_start >= chunk_bytes:
                flush_acc()
                self.write_chunk(f"{tag}_data_{chunk_start:x}.asm", lines, chunk_start, cur, "data")
                lines = []
                chunk_start = cur
            if cur in labels:
                flush_acc()
                lines.append((f"{labels[cur]}:", "", cur))
            acc.append(data[cur - rva_start])
            cur += 1
        flush_acc()
        if lines:
            self.write_chunk(f"{tag}_data_{chunk_start:x}.asm", lines, chunk_start, rva_end, "data")

    # ---------- top level ----------
    def run(self):
        self.collect_data_labels()
        os.makedirs(PARTS, exist_ok=True)
        order = []
        # code sections first in RVA order, data in RVA order -> keep file listing tidy
        for sec in self.pe.sections:
            if sec["name"] in (".text", "INIT"):
                self.emit_code_range(sec["va"], sec["va"] + sec["raw_size"],
                                     tag="text" if sec["name"] == ".text" else "init")
        for sec in self.pe.sections:
            if sec["name"] not in (".text", "INIT"):
                self.emit_data_range(sec["name"], sec["va"], sec["va"] + sec["raw_size"])

        # piece list in RVA order with virtual padding
        secs = self.pe.sections
        pieces = []
        for i, sec in enumerate(secs):
            nxt = secs[i + 1]["va"] if i + 1 < len(secs) else None
            pieces.append(dict(name=sec["name"], va=sec["va"], raw_size=sec["raw_size"],
                               vsize=sec["vsize"], next_va=nxt))
        with open(os.path.join(OUT, "asm_manifest.json"), "w", encoding="utf-8") as f:
            json.dump(dict(manifest=self.manifest, pieces=pieces,
                           overrides_count=len(self.overrides)), f, indent=1)
        with open(OVERRIDES, "w", encoding="utf-8") as f:
            json.dump(self.overrides, f, indent=1, sort_keys=True)

        # top-level: include parts in RVA order with virtual padding
        top = os.path.join(SRC, "ace_advt.asm")
        with open(top, "w", encoding="utf-8") as f:
            f.write("; ace_advt.asm -- top level of the ACE-ADVT.sys reassembly\n")
            f.write("; assemble with tools/build.py (nasm -f bin, flat RVA space)\n")
            f.write("BITS 64\n")
            f.write(f"org 0x{self.pe.sections[0]['va']:x}\n\n")
            for sec in secs:
                f.write(f"; ---- {sec['name']} -------------------------------------------------\n")
                for m in self.manifest:
                    if sec["va"] <= m["rva_start"] < sec["va"] + sec["raw_size"]:
                        f.write(f"%include \"{m['file']}\"\n")
                # virtual padding up to next section
                i = secs.index(sec)
                if i + 1 < len(secs):
                    gap = secs[i + 1]["va"] - (sec["va"] + sec["raw_size"])
                    if gap > 0:
                        f.write(f"times {gap} db 0        ; virtual gap ({sec['name']} -> {secs[i+1]['name']})\n")
                f.write("\n")
        print(f"insns emitted {self.stats['insn']}  db-fallbacks {self.stats['db_fallback']}  "
              f"data lines {self.stats['data_lines']}  pad {self.stats['pad']}")
        print(f"data labels {len(self.data_labels)}  code labels {len(self.code_labels)}  "
              f"parts {len(self.manifest)}")


if __name__ == "__main__":
    Emitter().run()
