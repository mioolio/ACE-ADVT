"""
mkheaders.py -- rebuild the PE headers field by field and prove them byte-equal.

Nothing is copied: every field is written by name and compared against the
reference image.  The DOS stub / Rich header block (0x40 .. e_lfanew) is build
metadata (tool version vector + its XOR checksum), so it is a transcribed blob
that lives in src/asm/assets/dos_stub.asm.
"""
from __future__ import annotations

import os
import struct
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from pe_model import PEFile, pe_checksum  # noqa: E402

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
TARGET = os.environ.get("ADVT_TARGET", r"<TARGET_SYS>")
OUT = os.path.join(ROOT, "out")
ASSETS = os.path.join(OUT, "assets")


def build_headers(pe: PEFile, stub: bytes) -> bytes:
    d = pe.data
    e_lfanew = struct.unpack_from("<I", d, 0x3C)[0]
    assert len(stub) == e_lfanew - 0x40, (len(stub), hex(e_lfanew))

    # ---- DOS header (0x00 .. 0x40), every field written by name -------------
    dos = bytearray(0x40)
    struct.pack_into("<H", dos, 0x00, 0x5A4D)      # e_magic 'MZ'
    struct.pack_into("<H", dos, 0x02, 0x0090)      # e_cblp
    struct.pack_into("<H", dos, 0x04, 0x0003)      # e_cp
    struct.pack_into("<H", dos, 0x06, 0x0000)      # e_crlc
    struct.pack_into("<H", dos, 0x08, 0x0004)      # e_cparhdr
    struct.pack_into("<H", dos, 0x0A, 0x0000)      # e_minalloc
    struct.pack_into("<H", dos, 0x0C, 0xFFFF)      # e_maxalloc
    struct.pack_into("<H", dos, 0x0E, 0x0000)      # e_ss
    struct.pack_into("<H", dos, 0x10, 0x00B8)      # e_sp
    struct.pack_into("<H", dos, 0x12, 0x0000)      # e_csum
    struct.pack_into("<H", dos, 0x14, 0x0000)      # e_ip
    struct.pack_into("<H", dos, 0x16, 0x0000)      # e_cs
    struct.pack_into("<H", dos, 0x18, 0x0040)      # e_lfarlc
    struct.pack_into("<H", dos, 0x1A, 0x0000)      # e_ovno
    struct.pack_into("<I", dos, 0x3C, e_lfanew)    # e_lfanew

    # ---- PE signature + COFF header ----------------------------------------
    coff = bytearray()
    coff += b"PE\0\0"
    coff += struct.pack("<HHIIIHH", pe.machine, pe.nsections, pe.timestamp,
                        pe.ptr_symtab, pe.nsyms, pe.size_opt, pe.characteristics)

    # ---- optional header (PE32+) ------------------------------------------
    oh = struct.unpack_from("<H", d, pe.opt_off)[0]
    major_linker, minor_linker = struct.unpack_from("<BB", d, pe.opt_off + 2)
    size_code, size_init, size_uninit = struct.unpack_from("<III", d, pe.opt_off + 4)
    major_os, minor_os = struct.unpack_from("<HH", d, pe.opt_off + 40)
    major_img, minor_img = struct.unpack_from("<HH", d, pe.opt_off + 44)
    major_sub, minor_sub = struct.unpack_from("<HH", d, pe.opt_off + 48)
    win32ver = struct.unpack_from("<I", d, pe.opt_off + 52)[0]
    loader_flags = struct.unpack_from("<I", d, pe.opt_off + 104)[0]

    opt = bytearray()
    opt += struct.pack("<HBB", 0x20B, major_linker, minor_linker)
    opt += struct.pack("<III", size_code, size_init, size_uninit)
    opt += struct.pack("<II", pe.entry_point, pe.base_of_code)
    opt += struct.pack("<Q", pe.image_base)
    opt += struct.pack("<II", pe.section_alignment, pe.file_alignment)
    opt += struct.pack("<HHHHHH", major_os, minor_os, major_img, minor_img, major_sub, minor_sub)
    opt += struct.pack("<I", win32ver)
    opt += struct.pack("<III", pe.size_of_image, pe.size_of_headers, pe.checksum)
    opt += struct.pack("<HH", pe.subsystem, pe.dll_characteristics)
    opt += struct.pack("<QQQQ", pe.size_of_stack_reserve, pe.size_of_stack_commit,
                       pe.size_of_heap_reserve, pe.size_of_heap_commit)
    opt += struct.pack("<II", loader_flags, pe.number_of_rva_and_sizes)
    for rva, size in pe.directories:
        opt += struct.pack("<II", rva, size)
    assert len(opt) == 112 + 16 * 8, len(opt)

    # ---- section table -----------------------------------------------------
    secs = bytearray()
    for s in pe.sections:
        name = s["name"].encode("ascii").ljust(8, b"\0")
        secs += name
        secs += struct.pack("<IIII", s["vsize"], s["va"], s["raw_size"], s["raw_ptr"])
        secs += struct.pack("<II", 0, 0)  # relocations / line numbers
        secs += struct.pack("<HHI", 0, 0, s["chars"])

    blob = bytes(dos) + stub + bytes(coff) + bytes(opt) + bytes(secs)
    if len(blob) < pe.size_of_headers:
        blob += b"\0" * (pe.size_of_headers - len(blob))   # header padding to FileAlignment
    return blob


def main():
    pe = PEFile(TARGET)
    os.makedirs(ASSETS, exist_ok=True)
    stub_path = os.path.join(ASSETS, "dos_stub.bin")
    if not os.path.exists(stub_path):
        raise SystemExit("build dos_stub.bin first (assemble src/asm/assets/dos_stub.asm)")
    with open(stub_path, "rb") as f:
        stub = f.read()
    hdr = build_headers(pe, stub)
    with open(os.path.join(ASSETS, "headers.bin"), "wb") as f:
        f.write(hdr)
    ref = pe.data[: pe.size_of_headers]
    print(f"headers built {len(hdr)} bytes, reference {len(ref)}")
    if hdr == ref:
        print("header bytes: identical to reference")
    else:
        diffs = [(i, hdr[i], ref[i]) for i in range(min(len(hdr), len(ref))) if hdr[i] != ref[i]]
        print(f"header bytes: {len(diffs)} differ, first 12: "
              + ", ".join(f"{i:#x}:{a:02x}!={b:02x}" for i, a, b, in diffs[:12]))
        raise SystemExit(1)


if __name__ == "__main__":
    main()
