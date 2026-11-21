"""
build.py -- assemble the reassembled sources and repack ACE-ADVT.sys byte-exactly.

Stages
  0  assets      dos stub / authenticode blobs  (nasm, own tiny sources)
  1  headers     field-level rebuild             (tools/mkheaders.py)
  2  code+data   one flat RVA-space NASM image   (src/asm/ace_advt.asm, org 0x1000)
  3  slicing     flat image -> per-section raw bytes at their original file offsets
  4  pack        headers + sections + signature -> out/rebuild/ACE-ADVT.rebuilt.sys
  5  settle      compare per instruction through the NASM listing; any line whose
                 re-encoding differs from the original bytes is demoted to `db`
                 (override file) and the image is rebuilt until 0 differences
  6  verify      sha256/md5/checksum/size + authenticode digest

Why the listing: NASM reports the output offset of every source line, so each
instruction can be compared in place even while earlier instructions still have
a different length.  That converges in a few rounds instead of shifting the
whole image per fix.
"""
from __future__ import annotations

import hashlib
import json
import os
import re
import subprocess
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import emit_asm
import mkheaders
from pe_model import PEFile, pe_checksum  # noqa: E402

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
TARGET = os.environ.get("ADVT_TARGET", r"<TARGET_SYS>")
OUT = os.path.join(ROOT, "out")
BUILD = os.path.join(ROOT, "build")
REBUILD = os.path.join(ROOT, "out", "rebuild")
ASM = os.path.join(ROOT, "src", "asm")
NASM = r"E:\nasm\nasm.exe"
LISTING = os.path.join(OUT, "listing", "image.lst")
OVERRIDES = os.path.join(OUT, "emit_overrides.json")

FLAT_BIN = os.path.join(BUILD, "image_rva.bin")


# --------------------------------------------------------------------------- nasm
def run_nasm(asm_path, bin_path, listing=None):
    cmd = [NASM, "-f", "bin", "-w+all", "-o", bin_path, asm_path]
    if listing:
        cmd[1:1] = ["-l", listing]
    r = subprocess.run(cmd, capture_output=True, text=True, cwd=ASM)
    return r.returncode, r.stdout + r.stderr


def error_lines(text):
    """NASM: 'path:line: error: msg' (also 'path:line:col: ...')."""
    out = []
    for line in text.splitlines():
        m = re.match(r"^(.*?):(\d+):(?:\d+:)?\s*(error|fatal|warning):\s*(.*)$", line.strip())
        if m and m.group(3) != "warning":
            out.append((os.path.basename(m.group(1)), int(m.group(2)), m.group(4)))
    return out


def load_linemaps():
    maps = {}
    parts = os.path.join(ASM, "parts")
    for name in os.listdir(parts):
        if name.endswith(".map"):
            base = name[:-4]
            d = {}
            with open(os.path.join(parts, name), encoding="utf-8") as f:
                for line in f:
                    ln, rva = line.split()
                    d[int(ln)] = int(rva, 16)
            maps[base] = d
    return maps


# ------------------------------------------------------------------- listing scan
MARK = re.compile(r";@([0-9a-f]+)")


def scan_listing(path):
    """rva -> (output_offset, emitted_length_guess)"""
    off = {}
    with open(path, encoding="utf-8", errors="replace") as f:
        for line in f:
            m = MARK.search(line)
            if not m:
                continue
            rva = int(m.group(1), 16)
            head = line[:40]
            mo = re.match(r"^\s*\d+\s+([0-9A-Fa-f]{8})\s", line)
            if not mo:
                continue
            off[rva] = int(mo.group(1), 16)
    return off


# ------------------------------------------------------------------------ packing
class Packer:
    def __init__(self):
        self.pe = PEFile(TARGET)
        self.ref = self.pe.data
        self.org = self.pe.sections[0]["va"]
        self.headers = open(os.path.join(OUT, "assets", "headers.bin"), "rb").read()
        self.sig = open(os.path.join(OUT, "assets", "authenticode.bin"), "rb").read()

    def slice_sections(self, flat: bytes):
        chunks = []
        for s in self.pe.sections:
            start = s["va"] - self.org
            chunks.append(flat[start : start + s["raw_size"]])
        return chunks

    def pack(self, flat: bytes) -> bytes:
        chunks = self.slice_sections(flat)
        for s, c in zip(self.pe.sections, chunks):
            assert len(c) == s["raw_size"], (s["name"], len(c), s["raw_size"])
        body = b"".join(chunks)
        img = self.headers + body + self.sig
        assert len(img) == len(self.ref), (len(img), len(self.ref))
        # fix up the checksum we just wrote from the model: recompute over final bytes
        csum = pe_checksum(img, self.pe.opt_off + 64)
        if csum != self.pe.checksum:
            b = bytearray(img)
            b[self.pe.opt_off + 64 : self.pe.opt_off + 68] = csum.to_bytes(4, "little")
            img = bytes(b)
        return img


# --------------------------------------------------------------------------- main
def main(max_rounds=25):
    pe = PEFile(TARGET)
    os.makedirs(REBUILD, exist_ok=True)
    os.makedirs(BUILD, exist_ok=True)
    packer = Packer()
    with open(os.path.join(OUT, "model.json"), encoding="utf-8") as f:
        model = json.load(f)
    items = {it["rva"]: it for it in model["items"]}
    flat_size = pe.size_of_image - packer.org

    for rnd in range(1, max_rounds + 1):
        print(f"--- round {rnd} ---")
        emit_asm.Emitter().run()
        rc, log = run_nasm(os.path.join(ASM, "ace_advt.asm"), FLAT_BIN, LISTING)
        if rc != 0:
            maps = load_linemaps()
            errs = error_lines(log)
            print(f"nasm failed: {len(errs)} errors")
            overrides = json.load(open(OVERRIDES, encoding="utf-8")) if os.path.exists(OVERRIDES) else {}
            fixed = 0
            for fname, line, msg in errs[:2000]:
                base = fname[:-4] if fname.endswith(".asm") else fname
                lm = maps.get(base) or maps.get(base + ".asm")
                if not lm:
                    print("   unmapped:", fname, line, msg)
                    continue
                lg = sorted(lm)
                rva = None
                for cand in lg:
                    if cand <= line:
                        rva = lm[cand]
                if rva is not None and rva in items:
                    overrides[f"{rva:x}"] = "db"
                    fixed += 1
                else:
                    print("   unmapped:", fname, line, msg)
            if not fixed:
                print(log[:4000])
                raise SystemExit("nasm errors that cannot be mapped")
            json.dump(overrides, open(OVERRIDES, "w", encoding="utf-8"), indent=1, sort_keys=True)
            print(f"   demoted {fixed} lines to db")
            continue

        flat = open(FLAT_BIN, "rb").read()
        if len(flat) != flat_size:
            print(f"flat size {len(flat):#x} != expected {flat_size:#x}")
        offmap = scan_listing(LISTING)

        overrides_path = OVERRIDES
        overrides = json.load(open(overrides_path, encoding="utf-8"))

        # ---- stage 1: length defects -------------------------------------
        # A line that assembles to a different size shifts everything after it.
        # Lengths are the difference of consecutive listing offsets, so they are
        # shift-invariant and every culprit is visible in a single pass.
        seq = sorted((rva, off) for rva, off in offmap.items() if rva in items)
        bounds = [(s["va"], s["va"] + s["raw_size"]) for s in pe.sections]

        def same_section(a, b):
            return any(lo <= a < hi and lo <= b < hi for lo, hi in bounds)

        len_bad = []
        for i in range(len(seq) - 1):
            rva, off = seq[i]
            if not same_section(rva, seq[i + 1][0]):
                continue
            got_len = seq[i + 1][1] - off
            if got_len != items[rva]["size"]:
                len_bad.append((rva, items[rva]["size"], got_len))
        if len_bad:
            print(f"   length defects: {len(len_bad)}")
            for rva, want, got in len_bad[:8]:
                print(f"     {rva:08x} {items[rva]['kind']:5s} want {want} bytes got {got}")
            for rva, _, _ in len_bad:
                overrides[f"{rva:x}"] = "db"
            json.dump(overrides, open(overrides_path, "w", encoding="utf-8"), indent=1, sort_keys=True)
            print(f"   demoted {len(len_bad)} length defects")
            continue

        # ---- stage 2: same length, different encoding ---------------------
        bad = []
        shifted = 0
        for rva, it in items.items():
            got_off = offmap.get(rva)
            if got_off is None:
                continue
            if got_off != rva - packer.org:
                shifted += 1
                continue
            want = bytes.fromhex(it["bytes"])
            got = flat[got_off : got_off + len(want)]
            if got != want:
                bad.append((rva, it["kind"], want.hex(), got.hex()))
        if shifted:
            print(f"   {shifted} items at a shifted offset (no length defect left?)")
        print(f"   encoding mismatches: {len(bad)}")
        if bad:
            for rva, kind, w, g in bad[:10]:
                print(f"     {rva:08x} {kind:5s} want {w[:24]} got {g[:24]}")
            for rva, kind, w, g in bad:
                overrides[f"{rva:x}"] = "db"
            json.dump(overrides, open(overrides_path, "w", encoding="utf-8"), indent=1, sort_keys=True)
            print(f"   demoted {len(bad)} items")
            continue

        # shifted-but-correct items: verify by absolute byte identity of sections
        img = packer.pack(flat)
        diff = sum(1 for a, b in zip(img, pe.data) if a != b)
        print(f"   packed {len(img)} bytes, differing bytes: {diff}")
        with open(os.path.join(REBUILD, "ACE-ADVT.rebuilt.sys"), "wb") as f:
            f.write(img)
        if diff:
            # find first differing offset and demote that item
            for i, (a, b) in enumerate(zip(img, pe.data)):
                if a != b:
                    rva = i - 0x400 + packer.org if i >= 0x400 else None
                    print(f"   first diff at file {i:#x} (rva {rva and hex(rva)})")
                    break
            continue

        print("byte-identical image produced")
        return 0
    raise SystemExit("did not converge")


if __name__ == "__main__":
    sys.exit(main())
