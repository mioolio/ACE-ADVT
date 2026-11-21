"""
flt_callers.py -- who calls the FltMgr thunks in ACE-BASE and with what arguments.

Prints, for every `call <thunk>` site, the preceding instructions so the argument
setup (filter handle, instance, file object) is visible.  This answers whether the
driver owns a minifilter handle or receives one from elsewhere.
"""
from __future__ import annotations

import os
import struct
import sys

from capstone import Cs, CS_ARCH_X86, CS_MODE_64

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from pe_model import PEFile, IMAGE_BASE  # noqa: E402

MD = Cs(CS_ARCH_X86, CS_MODE_64)
MD.detail = True

# thunk addresses discovered by tools/iat_refs.py (ACE-BASE.sys)
THUNKS = {
    0x75276: "FltGetFileNameInformationUnsafe",
    0x7527C: "FltReleaseFileNameInformation",
    0x75282: "FltGetRequestorProcessId",
    0x75288: "FltUnregisterFilter",
    0x7528E: "FltObjectDereference",
    0x75294: "FltAllocatePoolAlignedWithTag",
    0x7529A: "FltFreePoolAlignedWithTag",
    0x752A0: "FltGetFileNameInformation",
    0x752A6: "FltParseFileNameInformation",
    0x752AC: "FltCreateFileEx",
    0x752B2: "FltReadFile",
    0x752B8: "FltWriteFile",
    0x752BE: "FltSetInformationFile",
    0x752C4: "FltClose",
    0x752CA: "FltGetVolumeFromInstance",
    0x752D0: "FltGetVolumeProperties",
}


def main():
    path = sys.argv[1]
    pe = PEFile(path)
    sites = []
    for sec in pe.sections:
        if sec["name"] not in (".text", "INIT", "PAGE", ".cave"):
            continue
        blob = pe.data[sec["raw_ptr"] : sec["raw_ptr"] + sec["raw_size"]]
        base = sec["va"]
        for i in range(len(blob) - 5):
            if blob[i] != 0xE8:
                continue
            rel = struct.unpack_from("<i", blob, i + 1)[0]
            tgt = base + i + 5 + rel
            if tgt in THUNKS:
                sites.append((base + i, tgt))

    print(f"call sites into FltMgr thunks: {len(sites)}")
    for site, tgt in sites:
        print(f"\n--- {site:#08x} -> {THUNKS[tgt]} ---")
        start = max(0, pe.rva2off(site) - 48)
        va = IMAGE_BASE + pe.section_of_rva(site)["va"] + (start - pe.section_of_rva(site)["raw_ptr"])
        shown = 0
        for insn in MD.disasm(pe.data[start : pe.rva2off(site) + 5], va):
            print(f"  {insn.address - IMAGE_BASE:08x}  {insn.mnemonic} {insn.op_str}")
            shown += 1
        print(f"  {site:#08x}  call {THUNKS[tgt]}")


if __name__ == "__main__":
    main()
