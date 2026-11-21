"""
sys_ioctl.py -- recover the device + IOCTL surface of any ACE driver.

For each binary:
  * device names      UTF-16 strings matching \\Device\\ / \\DosDevices\\ / \\\\.\\
  * CTL_CODE constants every `cmp r32, imm32` (and `mov r32, imm32` compared right
                      after) whose DEVICE_TYPE field is in the vendor range, in
                      all executable sections including .tvm0
  * decoded fields    device type / function / method / access

usage: python tools/sys_ioctl.py <binary> [more binaries...]
"""
from __future__ import annotations

import os
import re
import struct
import sys
from collections import defaultdict

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from pe_model import PEFile  # noqa: E402

DEV_TYPES = {0x22, 0x8000, 0x8001, 0x8002, 0x8003, 0x8004, 0x8005, 0x9C40, 0x9C41, 0x9C42}



def device_type_of(pe):
    """read the DeviceType immediate passed to IoCreateDevice*/IoCreateDeviceSecure*"""
    import struct as _s
    from capstone import Cs, CS_ARCH_X86, CS_MODE_64
    from capstone.x86 import X86_OP_MEM, X86_REG_RIP
    md = Cs(CS_ARCH_X86, CS_MODE_64)
    md.detail = True
    rva, size = pe.directories[1]
    off = pe.rva2off(rva)
    slots = {}
    idx = 0
    while idx < size:
        base = off + idx
        ilt, _stamp, _chain, name_rva, first_thunk = _s.unpack_from("<IIIII", pe.data, base)
        if name_rva == 0:
            break
        dll_off = pe.rva2off(name_rva)
        _dll = pe.data[dll_off : pe.data.index(b"\0", dll_off)]
        thunk = ilt or first_thunk
        j = 0
        while True:
            toff = pe.rva2off(thunk + j * 8)
            if toff is None:
                break
            v = _s.unpack_from("<Q", pe.data, toff)[0]
            if v == 0:
                break
            noff = pe.rva2off(v & 0x7FFFFFFF)
            name = pe.data[noff + 2 : pe.data.index(b"\0", noff + 2)].decode("ascii", "replace")
            if name.lower().startswith("iocreatedevice"):
                slots[first_thunk + j * 8] = name
            j += 1
        idx += 20

    found = []
    for sec in pe.sections:
        if sec["name"] not in (".text", "INIT", "PAGE", ".cave", ".tvm0"):
            continue
        blob = pe.data[sec["raw_ptr"] : sec["raw_ptr"] + sec["raw_size"]]
        base = sec["va"]
        i = 0
        while i < len(blob) - 8:
            try:
                insn = next(md.disasm(blob[i : i + 15], pe.image_base + base + i))
            except StopIteration:
                i += 1
                continue
            hit = None
            for op in insn.operands:
                if op.type == X86_OP_MEM and op.mem.base == X86_REG_RIP:
                    tgt = insn.address + insn.size + op.mem.disp - pe.image_base
                    if tgt in slots:
                        hit = slots[tgt]
                    break
            if hit:
                back = max(0, i - 64)
                for ins2 in md.disasm(blob[back:i], pe.image_base + base + back):
                    if ins2.mnemonic == "mov" and ins2.op_str.startswith("r9d, 0x"):
                        try:
                            val = int(ins2.op_str.split(", ")[1], 16)
                            found.append((base + i, hit, val))
                        except ValueError:
                            pass
            i += insn.size if insn.size else 1
    return found


def decode(code):
    return dict(dev=(code >> 16) & 0xFFFF, access=(code >> 14) & 3,
                func=(code >> 2) & 0xFFF, method=code & 3)


def device_names(pe):
    out = []
    for sec in pe.sections:
        if sec["name"] not in (".rdata", ".data", ".tvm0"):
            continue
        blob = pe.data[sec["raw_ptr"] : sec["raw_ptr"] + sec["raw_size"]]
        for m in re.finditer(rb"(?:[\x20-\x7e]\x00){8,}", blob):
            t = m.group().decode("utf-16-le")
            if t.startswith(("\\Device\\", "\\DosDevices\\", "\\\\.\\")):
                out.append((sec["va"] + m.start(), t))
        for m in re.finditer(rb"\\\\(?:Device|DosDevices)\\\\[A-Za-z0-9_{}\-\.]{2,}", blob):
            t = m.group().decode("ascii", "replace")
            out.append((sec["va"] + m.start(), t))
    seen, uniq = set(), []
    for rva, t in sorted(set(out)):
        if t not in seen:
            seen.add(t)
            uniq.append((rva, t))
    return uniq


def ioctls(pe):
    hits = defaultdict(list)
    for sec in pe.sections:
        if sec["name"] not in (".text", "INIT", "PAGE", ".cave", ".tvm0"):
            continue
        blob = pe.data[sec["raw_ptr"] : sec["raw_ptr"] + sec["raw_size"]]
        base = sec["va"]
        i = 0
        while i < len(blob) - 6:
            val = None
            if blob[i] == 0x3D:                                    # cmp eax, imm32
                val = struct.unpack_from("<I", blob, i + 1)[0]
            elif blob[i] == 0x81 and 0xF8 <= blob[i + 1] <= 0xFF:   # cmp r32, imm32
                val = struct.unpack_from("<I", blob, i + 2)[0]
            elif blob[i] == 0x41 and blob[i + 1] == 0x81 and 0xF8 <= blob[i + 2] <= 0xFF:
                val = struct.unpack_from("<I", blob, i + 3)[0]
            if val is not None and (val >> 16) in DEV_TYPES:
                hits[val].append(base + i)
            i += 1
    return hits


def main():
    for path in sys.argv[1:]:
        pe = PEFile(path)
        print(f"\n{'='*74}\n{os.path.basename(path)}  ({len(pe.data):,} bytes)\n{'='*74}")
        print("device names:")
        for rva, t in device_names(pe):
            print(f"  {rva:08x}  {t}")
        for site, nm, val in device_type_of(pe):
            print(f'  {nm} at {site:#08x}: DeviceType={val:#x}')
        table = ioctls(pe)
        print(f"\nCTL_CODE candidates: {len(table)}")
        for code in sorted(table):
            d = decode(code)
            sites = table[code]
            print(f"  0x{code:08X}  dev=0x{d['dev']:04X} fn=0x{d['func']:03X} "
                  f"method={d['method']} access={d['access']}  sites={len(sites)} "
                  f"({', '.join(f'{s:#x}' for s in sites[:4])}{' ...' if len(sites) > 4 else ''})")


if __name__ == "__main__":
    main()
