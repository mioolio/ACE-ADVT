"""
iat_refs.py -- find the code that references specific imported functions.

usage: python tools/iat_refs.py <binary> [name-filter]

Prints every import slot (module!name @ IAT rva) and, for the slots matching the
filter, every rip-relative reference in code sections with a small disassembly
window.  This is how a minifilter's registration call and its callback table are
found without a full session.
"""
from __future__ import annotations

import os
import sys

from capstone import Cs, CS_ARCH_X86, CS_MODE_64
from capstone.x86 import X86_OP_MEM, X86_REG_RIP

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from pe_model import PEFile, IMAGE_BASE  # noqa: E402

MD = Cs(CS_ARCH_X86, CS_MODE_64)
MD.detail = True


def imports(pe):
    """module!name -> IAT slot RVA"""
    rva, size = pe.directories[1]
    off = pe.rva2off(rva)
    out = {}
    idx = 0
    while idx < size:
        base = off + idx
        import struct
        ilt, stamp, chain, name_rva, first_thunk = struct.unpack_from("<IIIII", pe.data, base)
        if name_rva == 0:
            break
        dll_off = pe.rva2off(name_rva)
        end = pe.data.index(b"\0", dll_off)
        dll = pe.data[dll_off:end].decode("ascii", "replace")
        thunk = ilt or first_thunk
        j = 0
        while True:
            toff = pe.rva2off(thunk + j * 8)
            if toff is None:
                break
            v = struct.unpack_from("<Q", pe.data, toff)[0]
            if v == 0:
                break
            slot = first_thunk + j * 8
            if v & (1 << 63):
                name = f"ord_{v & 0xFFFF}"
            else:
                noff = pe.rva2off(v & 0x7FFFFFFF)
                name = pe.data[noff + 2 : pe.data.index(b"\0", noff + 2)].decode("ascii", "replace")
            out[f"{dll}!{name}"] = slot
            j += 1
        idx += 20
    return out


def main():
    path = sys.argv[1]
    filt = sys.argv[2].lower() if len(sys.argv) > 2 else ""
    pe = PEFile(path)
    iat = imports(pe)
    wanted = {k: v for k, v in iat.items() if filt in k.lower()}
    print(f"{os.path.basename(path)}: {len(iat)} imports, {len(wanted)} match '{filt}'")
    for k in sorted(wanted):
        print(f"  {k:44s} slot rva {wanted[k]:#x}")

    if not wanted:
        return
    slots = {v: k for k, v in wanted.items()}
    print("\nreferences:")
    for sec in pe.sections:
        if sec["name"] not in (".text", "INIT", "PAGE", ".cave", ".tvm0"):
            continue
        blob = pe.data[sec["raw_ptr"] : sec["raw_ptr"] + sec["raw_size"]]
        base = sec["va"]
        i = 0
        while i < len(blob) - 8:
            try:
                insn = next(MD.disasm(blob[i : i + 15], IMAGE_BASE + base + i))
            except StopIteration:
                i += 1
                continue
            for op in insn.operands:
                if op.type == X86_OP_MEM and op.mem.base == X86_REG_RIP:
                    tgt = insn.address + insn.size + op.mem.disp - IMAGE_BASE
                    if tgt in slots:
                        print(f"  {base + i:#08x} [{sec['name']:6s}] {insn.mnemonic} {insn.op_str}"
                              f"   -> {slots[tgt]}")
                    break
            i += insn.size if insn.size else 1


if __name__ == "__main__":
    main()
