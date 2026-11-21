"""
gen_assets.py -- transcribe the two non-RVA build assets into assembly source.

  1. DOS stub + Rich header     [0x40 .. e_lfanew)     0xB0 bytes
  2. Authenticode blob          [cert_offset .. EOF)   21168 bytes

Both are opaque byte structures (tool-version vector with its XOR checksum, and
a PKCS#7 signature).  They are transcribed as `db` so the repository holds no
undocumented binary blobs; the assembler still has to produce them byte-exact.
"""
from __future__ import annotations

import os
import subprocess
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from pe_model import PEFile  # noqa: E402

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
TARGET = os.environ.get("ADVT_TARGET", r"<TARGET_SYS>")
OUT = os.path.join(ROOT, "out")
ASSETS = os.path.join(OUT, "assets")
ASRC = os.path.join(ROOT, "src", "asm", "assets")
NASM = r"E:\nasm\nasm.exe"


def db_lines(bs: bytes, per_line=16):
    return [", ".join(f"0x{b:02x}" for b in bs[i : i + per_line]) for i in range(0, len(bs), per_line)]


def write_asm(path, title, blob, bits=32, org=0):
    with open(path, "w", encoding="utf-8") as f:
        f.write(f"; {title}\n; transcribed from the reference image -- build asset\n")
        f.write(f"BITS {bits}\norg 0x{org:x}\n\n")
        for i, line in enumerate(db_lines(blob)):
            f.write(f"db {line:<72} ; +{i*16:06x}\n")


def assemble(asm_path, bin_path):
    os.makedirs(os.path.dirname(bin_path), exist_ok=True)
    r = subprocess.run([NASM, "-f", "bin", "-o", bin_path, asm_path],
                       capture_output=True, text=True)
    if r.returncode != 0:
        raise SystemExit(f"nasm failed for {asm_path}:\n{r.stderr}")
    return open(bin_path, "rb").read()


def main():
    pe = PEFile(TARGET)
    os.makedirs(ASRC, exist_ok=True)
    os.makedirs(ASSETS, exist_ok=True)
    e_lfanew = int.from_bytes(pe.data[0x3C:0x40], "little")

    stub = pe.data[0x40:e_lfanew]
    sig = pe.data[pe.cert_offset :]
    print(f"dos stub {len(stub)} bytes   authenticode {len(sig)} bytes")

    stub_asm = os.path.join(ASRC, "dos_stub.asm")
    sig_asm = os.path.join(ASRC, "authenticode.asm")
    write_asm(stub_asm, "DOS stub + Rich header (0x40 .. e_lfanew)", stub, bits=32)
    write_asm(sig_asm, "Authenticode PKCS#7 signature blob (overlay)", sig, bits=32)

    got_stub = assemble(stub_asm, os.path.join(ASSETS, "dos_stub.bin"))
    got_sig = assemble(sig_asm, os.path.join(ASSETS, "authenticode.bin"))
    print("stub  round-trip:", "OK" if got_stub == stub else "MISMATCH")
    print("cert  round-trip:", "OK" if got_sig == sig else "MISMATCH")
    if got_stub != stub or got_sig != sig:
        raise SystemExit(1)


if __name__ == "__main__":
    main()
