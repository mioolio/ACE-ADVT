"""
build_masm.py -- Microsoft toolchain build: ml64 -> COFF -> flat RVA image -> PE

Stages
  0  emit      src/masm/ace_advt.asm           (tools/emit_masm.py)
  1  assemble  ml64 /c /nologo                 (Microsoft Macro Assembler)
  2  link-lite tools/coff.py applies the REL32 fixups (no linker needed: one
               flat segment, every reference is intra-module)
  3  slice     flat RVA space -> per-section raw bytes at original file offsets
  4  pack      rebuilt headers + sections + authenticode blob
  5  settle    compare every item in place; anything the assembler encodes
               differently is demoted to raw bytes and rebuilt until clean
  6  report    sha256 / md5 / checksum / signature
"""
from __future__ import annotations

import hashlib
import json
import os
import re
import subprocess
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import emit_masm
from coff import COFF, apply_relocations
from pe_model import PEFile, pe_checksum  # noqa: E402

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
TARGET = os.environ.get("ADVT_TARGET", r"<TARGET_SYS>")
OUT = os.path.join(ROOT, "out")
BUILD = os.path.join(ROOT, "build")
REBUILD = os.path.join(OUT, "rebuild")
MSRC = os.path.join(ROOT, "src", "masm")
ML64 = os.environ.get("ML64",
                      r"E:\VisualStudio2026\VC\Tools\MSVC\14.52.36815\bin\Hostx64\x64\ml64.exe")
OBJ = os.path.join(BUILD, "ace_advt.obj")
OVERRIDES = os.path.join(OUT, "emit_overrides.json")
MARK = re.compile(r";@([0-9a-f]+)")


def assemble():
    for f in (OBJ,):
        if os.path.exists(f):
            os.remove(f)
    r = subprocess.run([ML64, "/c", "/nologo", "/Fo" + OBJ, "/Fl" + os.path.join(BUILD, "ace_advt.lst"), "ace_advt.asm"],
                       cwd=MSRC, capture_output=True, text=True)
    return r.returncode, r.stdout + r.stderr


def error_map():
    with open(os.path.join(MSRC, "line_map.json"), encoding="utf-8") as f:
        lm = {int(k): v for k, v in json.load(f).items()}
    return lm


def parse_errors(text):
    out = []
    for line in text.splitlines():
        m = re.search(r"\((\d+)\)\s*:\s*(?:error|fatal)\s+(\w+):\s*(.*)", line)
        if m:
            out.append((int(m.group(1)), m.group(3).strip()))
    return out


def listing_offsets(obj: COFF):
    """rva -> offset, taken from the marker comments of the MASM listing."""
    lst = os.path.join(BUILD, "ace_advt.lst")
    off = {}
    if not os.path.exists(lst):
        return off
    with open(lst, encoding="utf-8", errors="replace") as f:
        for line in f:
            m = MARK.search(line)
            if not m:
                continue
            head = re.match(r"^\s*([0-9A-Fa-f]{8})\s", line)
            if head:
                off[int(m.group(1), 16)] = int(head.group(1), 16)
    return off


class Packer:
    def __init__(self):
        self.pe = PEFile(TARGET)
        self.ref = self.pe.data
        self.org = self.pe.sections[0]["va"]
        self.headers = open(os.path.join(OUT, "assets", "headers.bin"), "rb").read()
        self.sig = open(os.path.join(OUT, "assets", "authenticode.bin"), "rb").read()

    def pack(self, flat: bytes) -> bytes:
        chunks = []
        for s in self.pe.sections:
            start = s["va"] - self.org
            c = flat[start : start + s["raw_size"]]
            assert len(c) == s["raw_size"], (s["name"], len(c), s["raw_size"])
            chunks.append(c)
        img = self.headers + b"".join(chunks) + self.sig
        assert len(img) == len(self.ref), (len(img), len(self.ref))
        csum = pe_checksum(img, self.pe.opt_off + 64)
        if csum != self.pe.checksum:
            b = bytearray(img)
            b[self.pe.opt_off + 64 : self.pe.opt_off + 68] = csum.to_bytes(4, "little")
            img = bytes(b)
        return img


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
        print(f"--- round {rnd} ---", flush=True)
        emit_masm.MasmEmitter().run()
        rc, log = assemble()
        if rc != 0:
            lm = error_map()
            errs = parse_errors(log)
            unique = []
            seen = set()
            for line, msg in errs:
                rva = lm.get(line)
                if rva is None:
                    # nearest preceding emitted line
                    for cand in sorted(lm, reverse=True):
                        if cand <= line:
                            rva = lm[cand]
                            break
                if rva is None or rva in seen:
                    continue
                seen.add(rva)
                unique.append((rva, msg))
            print(f"   ml64 errors: {len(errs)} ({len(unique)} distinct items)")
            if not unique:
                print(log[:4000])
                raise SystemExit("unmappable assembler error")
            overrides = json.load(open(OVERRIDES, encoding="utf-8"))
            for rva, msg in unique[:4000]:
                overrides[f"{rva:x}"] = "db"
            json.dump(overrides, open(OVERRIDES, "w", encoding="utf-8"), indent=1, sort_keys=True)
            print(f"   demoted {len(unique)} items: " + "; ".join(m for _, m in unique[:3]))
            continue

        coff = COFF(OBJ)
        secs = [s for s in coff.sections if s["raw_size"]]
        if len(secs) != 1:
            print("   sections:", [(s["name"], s["raw_size"]) for s in coff.sections])
        sec = secs[0]
        flat = bytearray(coff.data[sec["raw_ptr"] : sec["raw_ptr"] + sec["raw_size"]])
        fixed = apply_relocations(coff, sec, flat)
        print(f"   assembled {len(flat):#x} bytes, applied {fixed} REL32 fixups", flush=True)
        if len(flat) != flat_size:
            print(f"   flat size {len(flat):#x} != expected {flat_size:#x} (length defect)")

        # length defects first: difference of consecutive line offsets
        lst = os.path.join(BUILD, "ace_advt.lst")
        offmap = listing_offsets(coff)
        overrides = json.load(open(OVERRIDES, encoding="utf-8"))
        if offmap:
            seq = sorted((rva, off) for rva, off in offmap.items() if rva in items)
            len_bad = []
            for i in range(len(seq) - 1):
                rva, off = seq[i]
                if seq[i + 1][0] - rva > items[rva]["size"] * 8:   # section boundary
                    continue
                got = seq[i + 1][1] - off
                if got != items[rva]["size"]:
                    len_bad.append((rva, items[rva]["size"], got))
            if len_bad:
                print(f"   length defects {len(len_bad)}: {[(hex(r), w, g) for r, w, g in len_bad[:5]]}")
                for rva, _, _ in len_bad:
                    overrides[f"{rva:x}"] = "db"
                json.dump(overrides, open(OVERRIDES, "w", encoding="utf-8"), indent=1, sort_keys=True)
                continue

        bad = []
        for rva, it in items.items():
            want_off = rva - packer.org
            if want_off + it["size"] > len(flat):
                continue
            want = bytes.fromhex(it["bytes"])
            got = bytes(flat[want_off : want_off + len(want)])
            if got != want:
                bad.append((rva, want.hex(), got.hex()))
        print(f"   in-place mismatches: {len(bad)}", flush=True)
        if bad:
            for rva, w, g in bad[:8]:
                print(f"     {rva:08x} want {w[:24]} got {g[:24]}")
            for rva, _, _ in bad:
                overrides[f"{rva:x}"] = "db"
            json.dump(overrides, open(OVERRIDES, "w", encoding="utf-8"), indent=1, sort_keys=True)
            print(f"   demoted {len(bad)} items")
            continue

        img = packer.pack(bytes(flat))
        diff = sum(1 for a, b in zip(img, pe.data) if a != b)
        with open(os.path.join(REBUILD, "ACE-ADVT.rebuilt.sys"), "wb") as f:
            f.write(img)
        print(f"   packed {len(img)} bytes, differing bytes: {diff}")
        if diff:
            for i, (a, b) in enumerate(zip(img, pe.data)):
                if a != b:
                    print(f"   first diff at file {i:#x}")
                    break
            continue
        print("byte-identical image produced by ml64")
        return 0
    raise SystemExit("did not converge")


if __name__ == "__main__":
    sys.exit(main())
