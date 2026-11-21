"""
verify.py -- final acceptance report for the reconstruction.

Checks
  1. byte identity (size, sha256, md5, first difference)
  2. PE structure: section table, directories, entry point, checksum
  3. Authenticode status of the rebuilt file (PowerShell Get-AuthenticodeSignature)
  4. reconstruction coverage: how many instructions came from mnemonics vs raw bytes
  5. repeatability: build metadata (nasm version, override count)

Writes out/verification.json and prints the report table.
"""
from __future__ import annotations

import hashlib
import json
import os
import subprocess
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from pe_model import PEFile, pe_checksum  # noqa: E402

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
OUT = os.path.join(ROOT, "out")
TARGET = os.environ.get("ADVT_TARGET", r"<TARGET_SYS>")
REBUILT = os.path.join(OUT, "rebuild", "ACE-ADVT.rebuilt.sys")


def sha256(b):
    return hashlib.sha256(b).hexdigest()


def md5(b):
    return hashlib.md5(b).hexdigest()


def main():
    ref_b = open(TARGET, "rb").read()
    new_b = open(REBUILT, "rb").read()
    ref = PEFile(TARGET)
    new = PEFile(REBUILT)

    mismatches = [i for i, (a, b) in enumerate(zip(ref_b, new_b)) if a != b]
    report = dict(
        reference=dict(path=TARGET, size=len(ref_b), sha256=sha256(ref_b), md5=md5(ref_b)),
        rebuilt=dict(path=REBUILT, size=len(new_b), sha256=sha256(new_b), md5=md5(new_b)),
        identical=ref_b == new_b,
        differing_bytes=len(mismatches) + abs(len(ref_b) - len(new_b)),
        checksum=dict(stored=ref.checksum, recomputed=pe_checksum(new_b, new.opt_off + 64)),
        structure=dict(
            entry_point=hex(new.entry_point),
            size_of_image=hex(new.size_of_image),
            sections=[dict(name=s["name"], va=hex(s["va"]), vsize=s["vsize"],
                           raw_ptr=hex(s["raw_ptr"]), raw_size=s["raw_size"])
                      for s in new.sections],
            directories=[dict(index=i, rva=hex(r), size=s) for i, (r, s) in enumerate(new.directories)],
        ),
    )

    # ---- coverage numbers from the model / emit statistics -----------------
    with open(os.path.join(OUT, "model.json"), encoding="utf-8") as f:
        model = json.load(f)
    kinds = {}
    for it in model["items"]:
        kinds[it["kind"]] = kinds.get(it["kind"], 0) + 1
    overrides = {}
    p = os.path.join(OUT, "emit_overrides.json")
    if os.path.exists(p):
        overrides = json.load(open(p, encoding="utf-8"))
    n_insn = kinds.get("insn", 0)
    raw = len([k for k in overrides if overrides[k] == "db"])
    report["coverage"] = dict(
        items=len(model["items"]),
        instructions=n_insn,
        padding_items=kinds.get("pad", 0),
        data_items=kinds.get("data", 0),
        labels=len(model["labels"]),
        functions=len(model["functions"]),
        mnemonic_lines=n_insn - raw,
        raw_byte_lines=raw,
        mnemonic_ratio=round((n_insn - raw) / n_insn * 100, 2) if n_insn else 0.0,
    )

    # ---- authenticode -----------------------------------------------------
    try:
        ps = (
            "$s = Get-AuthenticodeSignature -LiteralPath '" + REBUILT + "';"
            " '" + '"status":"' + "' + $s.Status + '" + '";'
        )
        out = subprocess.run(["powershell", "-NoProfile", "-Command",
                              f"(Get-AuthenticodeSignature -LiteralPath '{REBUILT}').Status;"
                              f"(Get-AuthenticodeSignature -LiteralPath '{REBUILT}').SignerCertificate.Subject"],
                             capture_output=True, text=True).stdout.strip().splitlines()
        report["authenticode"] = dict(status=out[0].strip() if out else "?", subject=out[1].strip() if len(out) > 1 else "")
    except Exception as exc:  # pragma: no cover
        report["authenticode"] = dict(status=f"error: {exc}")

    # ---- environment ------------------------------------------------------
    nasm = subprocess.run([r"E:\nasm\nasm.exe", "-v"], capture_output=True, text=True).stdout.strip()
    report["toolchain"] = dict(assembler=nasm, packer="tools/build.py", headers="tools/mkheaders.py")

    with open(os.path.join(OUT, "verification.json"), "w", encoding="utf-8") as f:
        json.dump(report, f, indent=1)

    # ---- print ------------------------------------------------------------
    print(f"size        {report['reference']['size']} / {report['rebuilt']['size']}")
    print(f"sha256      {report['rebuilt']['sha256']}")
    print(f"            {report['reference']['sha256']}")
    print(f"md5         {report['rebuilt']['md5']}")
    print(f"identical   {report['identical']}  differing bytes {report['differing_bytes']}")
    print(f"checksum    stored {report['checksum']['stored']:#x} recomputed {report['checksum']['recomputed']:#x}")
    print(f"entry       {report['structure']['entry_point']}   image {report['structure']['size_of_image']}")
    print(f"signature   {report['authenticode'].get('status')}  {report['authenticode'].get('subject')}")
    c = report["coverage"]
    print(f"coverage    {c['instructions']} instructions, {c['mnemonic_lines']} from mnemonics "
          f"({c['mnemonic_ratio']}%), {c['raw_byte_lines']} raw")
    print(f"model       {c['items']} items, {c['functions']} unwind functions, {c['labels']} labels")
    return 0 if report["identical"] and report["authenticode"].get("status", "").lower().startswith("valid") else 1


if __name__ == "__main__":
    sys.exit(main())
