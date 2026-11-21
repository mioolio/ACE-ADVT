"""
um_scan.py -- triage every binary under AntiCheatExpert.

For each PE it reports: size, machine, subsystem, timestamp, linker version,
debug/PDB path, signature state, section table summary, and -- most useful for
linking the user-mode side to the driver we already reversed -- whether it
contains any of the protocol constants:

    device names  \\Device\\ACE-ADVT / \\DosDevices\\Global\\ACE-ADVT
    ioctl codes   0x00222824 0x0022282C 0x00222834 0x80000063 0x80000267
    tokens        0x63AE442D (main family) 0x623782AB (aux family)
    reply magic   0x01343BEB
    table magic   0x013500CA
    envelope size 0x24C
    SHA-256 IV / K constants
"""
from __future__ import annotations

import json
import os
import struct
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from pe_model import PEFile  # noqa: E402

ROOT = r"<ACE_ROOT>"
OUT = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "out")

PROBE_DWORD = {
    0x00222824: "ioctl_main_A",
    0x0022282C: "ioctl_main_B",
    0x00222834: "ioctl_main_C",
    0x80000063: "ioctl_aux_A",
    0x80000267: "ioctl_aux_B",
    0x63AE442D: "token_main_base",
    0x63AE4430: "token_main_k3",
    0x623782AB: "token_aux_base",
    0x01343BEB: "reply_magic",
    0x013500CA: "table_magic",
    0x0000024C: "envelope_size",
    0x6A09E667: "sha256_iv0",
    0x428A2F98: "sha256_k0",
    0x9C51BBD3: "token_scramble",
}
PROBE_UTF16 = {
    "\\Device\\ACE-ADVT": "devname",
    "\\DosDevices\\Global\\ACE-ADVT": "symlink",
    "\\\\.\\Global\\ACE-ADVT": "dosdevice_path",
    "ACE-ADVT": "shortname",
}


def scan(path):
    data = open(path, "rb").read()
    hits = {}
    for val, name in PROBE_DWORD.items():
        pat = struct.pack("<I", val)
        n = data.count(pat)
        if n:
            hits[name] = n
    for s, name in PROBE_UTF16.items():
        pat = s.encode("utf-16-le")
        n = data.count(pat)
        if n:
            hits[name] = n
        pat8 = s.encode("ascii")
        n8 = data.count(pat8)
        if n8 > 1:
            hits[name + "_ascii"] = n8
    return hits


def pe_info(path):
    try:
        pe = PEFile(path)
    except Exception as exc:
        return dict(error=str(exc))
    info = dict(
        size=len(pe.data),
        machine=hex(pe.machine),
        subsystem=pe.subsystem,
        timestamp=pe.timestamp,
        linker=f"{pe.data[pe.opt_off + 2]}.{pe.data[pe.opt_off + 3]}",
        entry=hex(pe.entry_point),
        image_base=hex(pe.image_base),
        sections=[(s["name"], s["vsize"], s["raw_size"]) for s in pe.sections],
        debug=[],
    )
    # debug directory -> PDB path
    rva, size = pe.directories[6]
    if rva and size:
        off = pe.rva2off(rva)
        for i in range(size // 28):
            typ, sz, _rva, ptr = struct.unpack_from("<IIII", pe.data, off + i * 28)
            if typ == 2 and ptr:
                raw = pe.data[ptr : ptr + sz]
                idx = raw.find(b"RSDS")
                if idx >= 0:
                    info["debug"].append(raw[idx + 24 :].split(b"\0")[0].decode("ascii", "replace"))
    return info


def main():
    rows = []
    for dirpath, _dirs, files in os.walk(ROOT):
        for fn in files:
            path = os.path.join(dirpath, fn)
            if not fn.lower().endswith((".exe", ".dll", ".sys")):
                continue
            rel = os.path.relpath(path, ROOT)
            info = pe_info(path)
            hits = scan(path)
            info.update(path=rel, hits=hits)
            rows.append(info)
            print(f"\n=== {rel} ===")
            if "error" in info:
                print("   ", info["error"])
                continue
            print(f"   size={info['size']:,} machine={info['machine']} subsystem={info['subsystem']} "
                  f"linker={info['linker']} stamp={info['timestamp']:#x}")
            if info["debug"]:
                print(f"   pdb: {info['debug'][0]}")
            if hits:
                print("   protocol hits: " + ", ".join(f"{k}x{v}" for k, v in sorted(hits.items())))
            else:
                print("   protocol hits: none")
    json.dump(rows, open(os.path.join(OUT, "um_triage.json"), "w"), indent=1)
    print(f"\nscanned {len(rows)} binaries -> out/um_triage.json")


if __name__ == "__main__":
    main()
