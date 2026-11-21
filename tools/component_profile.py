"""
component_profile.py -- one-shot capability profile for any ACE component.

Emits, per binary:
  * identity: size, subsystem, linker, timestamp, PDB path, sections, .tvm0 size
  * imports grouped by capability (kernel APIs / win32 APIs / crypto / network)
  * strings filtered into categories: device paths, named pipes, mutexes,
    registry paths, driver/service names, DLL targets, URLs, API names
  * counts for each category

usage: python tools/component_profile.py <binary> [--json out.json]
"""
from __future__ import annotations

import json
import os
import re
import struct
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from pe_model import PEFile  # noqa: E402

KERNEL_API = ("Ps", "Ke", "Mm", "Zw", "Nt", "Ob", "Io", "Ex", "Rtl", "Flt", "Cm", "Se", "Hal")
WIN32_HOT = ("CreateFile", "DeviceIoControl", "ReadFile", "WriteFile", "CreateProcess",
             "OpenProcess", "VirtualAlloc", "VirtualProtect", "CreateThread", "LoadLibrary",
             "GetProcAddress", "RegOpenKey", "RegSetValue", "RegDelete", "CreateService",
             "StartService", "EnumProcesses", "NtQuery", "Toolhelp", "SetWindowsHook",
             "CreateMutex", "CreateEvent", "WaitForSingleObject", "WriteProcessMemory",
             "ReadProcessMemory", "IsDebuggerPresent", "CheckRemoteDebugger",
             "OutputDebugString", "GetTickCount", "QueryPerformanceCounter", "GetSystemInfo")
CRYPTO_API = ("Crypt", "BCrypt", "NCrypt")
NET_API = ("socket", "connect", "send", "recv", "WSA", "Internet", "WinHttp", "Http")

CATS = {
    "device": re.compile(r"^\\\\?(Device|DosDevices|GLOBALROOT)\\", re.I),
    "dosdevice": re.compile(r"^\\\\\.\\", re.I),
    "pipe": re.compile(r"\\\\pipe\\|\\\\\.\\pipe\\", re.I),
    "mutex": re.compile(r"^(Global|Local)\\", re.I),
    "registry": re.compile(r"^(\\Registry\\|SOFTWARE\\|SYSTEM\\|HKEY_)", re.I),
    "driver": re.compile(r"\.sys$|\.drv$", re.I),
    "dll": re.compile(r"\.dll$", re.I),
    "url": re.compile(r"^(https?|wss?)://|^[\w.-]+\.(com|cn|net|org)/", re.I),
    "api": re.compile(r"^(Ps|Ke|Mm|Zw|Nt|Ob|Io|Ex|Rtl|Flt|Cm|Se|Hal)[A-Z]"),
}


def strings(pe, minlen=5, cap=4000):
    out = []
    for sec in pe.sections:
        if sec["name"] not in (".rdata", ".data", ".tvm0", "PAGE", ".cave"):
            continue
        blob = pe.data[sec["raw_ptr"] : sec["raw_ptr"] + sec["raw_size"]]
        for m in re.finditer(rb"(?:[\x20-\x7e]\x00){%d,}" % minlen, blob):
            out.append((sec["name"], sec["va"] + m.start(), m.group().decode("utf-16-le")))
        for m in re.finditer(rb"[\x20-\x7e]{%d,}" % minlen, blob):
            out.append((sec["name"], sec["va"] + m.start(), m.group().decode("ascii")))
        if len(out) > cap * 8:
            break
    return out


def imports(pe):
    rva, size = pe.directories[1]
    off = pe.rva2off(rva)
    mods = {}
    idx = 0
    while idx < size:
        base = off + idx
        ilt, _s, _c, name_rva, first_thunk = struct.unpack_from("<IIIII", pe.data, base)
        if name_rva == 0:
            break
        dll_off = pe.rva2off(name_rva)
        dll = pe.data[dll_off : pe.data.index(b"\0", dll_off)].decode("ascii", "replace")
        thunk = ilt or first_thunk
        names = []
        j = 0
        while True:
            toff = pe.rva2off(thunk + j * 8)
            if toff is None:
                break
            v = struct.unpack_from("<Q", pe.data, toff)[0]
            if v == 0:
                break
            if v & (1 << 63):
                names.append(f"ord_{v & 0xFFFF}")
            else:
                noff = pe.rva2off(v & 0x7FFFFFFF)
                names.append(pe.data[noff + 2 : pe.data.index(b"\0", noff + 2)].decode("ascii", "replace"))
            j += 1
        mods[dll] = names
        idx += 20
    return mods


def pdb_path(pe):
    rva, size = pe.directories[6]
    if not rva or not size:
        return None
    off = pe.rva2off(rva)
    for i in range(size // 28):
        typ, sz, _r, ptr = struct.unpack_from("<IIII", pe.data, off + i * 28)
        if typ == 2 and ptr:
            raw = pe.data[ptr : ptr + sz]
            k = raw.find(b"RSDS")
            if k >= 0:
                return raw[k + 24 :].split(b"\0")[0].decode("ascii", "replace")
    return None


def main():
    path = sys.argv[1]
    pe = PEFile(path)
    prof = dict(path=os.path.basename(path), size=len(pe.data), subsystem=pe.subsystem,
                linker=f"{pe.data[pe.opt_off + 2]}.{pe.data[pe.opt_off + 3]}",
                timestamp=pe.timestamp, pdb=pdb_path(pe),
                sections=[(s["name"], s["vsize"], s["raw_size"]) for s in pe.sections])

    mod = imports(pe)
    prof["import_modules"] = {k: len(v) for k, v in mod.items()}
    allnames = [n for v in mod.values() for n in v]
    prof["kernel_api"] = sorted(n for n in allnames if n.startswith(KERNEL_API))
    prof["win32_hot"] = sorted(n for n in allnames if any(h in n for h in WIN32_HOT))
    prof["crypto_api"] = sorted(n for n in allnames if any(h in n for h in CRYPTO_API))
    prof["net_api"] = sorted(n for n in allnames if any(h in n for h in NET_API))

    cats = {k: [] for k in CATS}
    seen = set()
    for sec, rva, t in strings(pe):
        if t in seen:
            continue
        seen.add(t)
        for name, rx in CATS.items():
            if rx.search(t):
                if len(cats[name]) < 60:
                    cats[name].append(t)
                break
    prof["strings"] = cats

    print(f"\n{'='*78}\n{prof['path']}  {prof['size']:,} B  subsystem={prof['subsystem']} "
          f"linker={prof['linker']}  pdb={prof['pdb']}")
    print(f"  imports: " + ", ".join(f"{k}({v})" for k, v in
                                     sorted(prof['import_modules'].items(), key=lambda kv: -kv[1])[:10]))
    if prof["kernel_api"]:
        print(f"  kernel APIs ({len(prof['kernel_api'])}): " + ", ".join(prof["kernel_api"][:18]))
    if prof["win32_hot"]:
        print(f"  hot win32 ({len(prof['win32_hot'])}): " + ", ".join(prof["win32_hot"][:14]))
    for name in ("device", "dosdevice", "pipe", "mutex", "registry", "driver", "url"):
        if cats[name]:
            print(f"  {name} ({len(cats[name])}): " + " | ".join(cats[name][:6]))

    if "--json" in sys.argv:
        dst = sys.argv[sys.argv.index("--json") + 1]
        json.dump(prof, open(dst, "w"), indent=1)


if __name__ == "__main__":
    main()
