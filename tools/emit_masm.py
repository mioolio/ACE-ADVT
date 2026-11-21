"""
emit_masm.py -- model.json -> one MASM (ml64) source file.

Why MASM: ml64 and the MSVC compiler share the same encoder, so `mov rcx, rbx`
becomes 48 8B CB and `xor ecx, ecx` becomes 33 C9 -- exactly the encodings the
original image uses.  NASM flips those to 89 D9 / 31 C9, which is why the NASM
path needed raw fallbacks for ~27% of the instructions.

Shape of the output
  OPTION CASEMAP:NONE
  FLAT SEGMENT ALIGN(16) 'CODE'
      <all sections in RVA order, virtual padding as `db N dup(0)`
  FLAT ENDS
  END

One flat segment keeps every cross reference internal, so the assembler emits
only REL32 fixups (resolved by tools/build_masm.py) and offsets stay 1:1 with
the image RVA space.
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
MSRC = os.path.join(ROOT, "src", "masm")
OVERRIDES = os.path.join(OUT, "emit_overrides.json")
HEX = re.compile(r"0x([0-9a-fA-F]+)")


def hb(b: int) -> str:
    """MASM byte literal: a leading A-F digit needs a zero prefix."""
    t = f"{b:02X}"
    return ("0" + t if t[0] in "ABCDEF" else t) + "h"

def masm_num(m: re.Match) -> str:
    digits = m.group(1).upper()
    if digits[0] in "ABCDEF":
        digits = "0" + digits
    return digits + "h"


class MasmEmitter:
    def __init__(self):
        self.pe = PEFile(TARGET)
        with open(os.path.join(OUT, "model.json"), encoding="utf-8") as f:
            self.model = json.load(f)
        self.items = {it["rva"]: it for it in self.model["items"]}
        self.code_labels = {int(k, 16): v for k, v in self.model["labels"].items()}
        self.iat = {int(k, 16): v for k, v in self.model["iat"].items()}
        self.overrides = json.load(open(OVERRIDES, encoding="utf-8")) if os.path.exists(OVERRIDES) else {}
        self.data_labels: dict[int, str] = {}
        self.out = []          # (text, rva|None)
        self.raw_note = {}
        self.stats = dict(insn=0, raw=0, db=0, pad=0)

    # ---------------------------------------------------------------- labels
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
            if s["name"] in (".text", "INIT") and rva in self.items:
                self.code_labels[rva] = f"loc_{rva:x}"
                continue
            if s["name"] in (".text", "INIT"):
                continue
            self.data_labels[rva] = f"dat_{rva:x}"

    # ------------------------------------------------------------ text pieces
    def insn_text(self, it):
        rva = it["rva"]
        key = f"{rva:x}"
        raw = "db " + ", ".join(hb(b) for b in bytes.fromhex(it["bytes"]))
        if self.overrides.get(key) == "db":
            self.stats["raw"] += 1
            self.raw_note[rva] = f"{it['mnem']} {it['ops']}".strip() + "   ; forced raw (MSVC encoding)"
            return raw
        mnem = "mov" if it["mnem"] == "movabs" else it["mnem"]
        ops = it["ops"]
        if it.get("ripref") is not None:
            tgt = it["ripref"]
            lab = self.code_labels.get(tgt) or self.data_labels.get(tgt)
            if lab is None:
                self.overrides[key] = "db"
                self.stats["raw"] += 1
                self.raw_note[rva] = f"{it['mnem']} {it['ops']}".strip() + "   ; forced raw (unresolved rip target)"
                return raw
            ops = re.sub(r"\[rip [+-] 0x[0-9a-f]+\]", f"[{lab}]", ops)
        if it.get("branch") is not None:
            tgt = it["branch"]
            lab = self.code_labels.get(tgt) or self.data_labels.get(tgt)
            if lab is None:
                self.overrides[key] = "db"
                self.stats["raw"] += 1
                self.raw_note[rva] = f"{it['mnem']} {it['ops']}".strip() + "   ; forced raw (unresolved branch)"
                return raw
            ops = re.sub(r"0x[0-9a-f]+$", lab, ops)
        ops = HEX.sub(masm_num, ops)
        self.stats["insn"] += 1
        return (mnem + (" " + ops if ops else "")).strip()

    # ---------------------------------------------------------------- emit
    def emit_code(self, va, size):
        cur, end = va, va + size
        while cur < end:
            it = self.items.get(cur)
            if it is None:
                raise SystemExit(f"model hole at {cur:#x}")
            lab = self.code_labels.get(cur)
            if lab:
                self.out.append((f"{lab}:", None))
            if it["kind"] == "insn":
                self.out.append((self.insn_text(it), cur))
            elif it["kind"] == "pad":
                self.out.append((f"db {it['size']} dup(0CCh)", cur))
                self.stats["pad"] += it["size"]
            else:
                bs = bytes.fromhex(it["bytes"])
                for i in range(0, len(bs), 16):
                    chunk = bs[i : i + 16]
                    self.out.append(("db " + ", ".join(hb(b) for b in chunk), cur + i))
                    self.stats["db"] += 1
            cur += it["size"]

    def emit_data(self, va, size):
        base_off = self.pe.rva2off(va)
        data = self.pe.data[base_off : base_off + size]
        labels = {r: v for r, v in self.data_labels.items() if va <= r < va + size}
        acc, acc_rva = bytearray(), va
        cur = va

        def flush():
            nonlocal acc, acc_rva
            if not acc:
                return
            bs = bytes(acc)
            for i in range(0, len(bs), 16):
                chunk = bs[i : i + 16]
                self.out.append(("db " + ", ".join(hb(b) for b in chunk), acc_rva + i))
                self.stats["db"] += 1
            acc = bytearray()
            acc_rva = cur

        while cur < va + size:
            if cur in labels:
                flush()
                self.out.append((f"{labels[cur]}:", None))
            acc.append(data[cur - va])
            cur += 1
        flush()

    def emit_virtual_gap(self, va, size):
        """zero-filled virtual tail; labels inside it must still exist."""
        labels = sorted(r for r in self.data_labels if va <= r < va + size)
        cur = va
        for lab_rva in labels:
            if lab_rva > cur:
                self.out.append((f"db {lab_rva - cur} dup(0)", None))
            self.out.append((f"{self.data_labels[lab_rva]}:", None))
            cur = lab_rva
        if va + size > cur:
            self.out.append((f"db {va + size - cur} dup(0)          ; virtual gap", None))

    def run(self):
        os.makedirs(MSRC, exist_ok=True)
        self.collect_data_labels()
        secs = self.pe.sections
        self.out.append(("OPTION CASEMAP:NONE", None))
        self.out.append(("", None))
        self.out.append(("FLAT SEGMENT ALIGN(16) 'CODE'", None))
        for i, sec in enumerate(secs):
            self.out.append((f"; ---- {sec['name']} @ {sec['va']:#x} ----", None))
            if sec["name"] in (".text", "INIT"):
                self.emit_code(sec["va"], sec["raw_size"])
            else:
                self.emit_data(sec["va"], sec["raw_size"])
            if i + 1 < len(secs):
                gap = secs[i + 1]["va"] - (sec["va"] + sec["raw_size"])
                if gap > 0:
                    self.emit_virtual_gap(sec["va"] + sec["raw_size"], gap)
        self.out.append(("FLAT ENDS", None))
        self.out.append(("", None))
        self.out.append(("END", None))

        path = os.path.join(MSRC, "ace_advt.asm")
        linemap = {}
        with open(path, "w", encoding="utf-8") as f:
            for lineno, (text, rva) in enumerate(self.out, start=1):
                if rva is None:
                    f.write(text + "\n")
                    continue
                note = self.raw_note.get(rva)
                if note:
                    f.write(f"{text:<44};@{rva:x} {note}\n")
                else:
                    f.write(f"{text:<44};@{rva:x}\n")
                linemap[lineno] = rva
        with open(os.path.join(MSRC, "line_map.json"), "w", encoding="utf-8") as f:
            json.dump({str(k): v for k, v in linemap.items()}, f)
        json.dump(self.overrides, open(OVERRIDES, "w", encoding="utf-8"), indent=1, sort_keys=True)
        print(f"masm: {self.stats['insn']} mnemonic lines, {self.stats['raw']} raw, "
              f"{self.stats['db']} data lines, {self.stats['pad']} pad bytes, "
              f"{len(self.out)} source lines")


if __name__ == "__main__":
    MasmEmitter().run()
