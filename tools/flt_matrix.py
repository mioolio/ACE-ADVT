"""
flt_matrix.py -- which ACE component actually registers a minifilter?

Scans every component's import table for FltMgr / WDM / Ob callbacks and prints a
matrix, so the "who is the real minifilter" question is answered from imports
rather than from names.
"""
from __future__ import annotations

import os
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from iat_refs import imports  # reuse the parser
from pe_model import PEFile  # noqa: E402

ROOT = r"<ACE_ROOT>"

INTEREST = [
    "FltRegisterFilter", "FltStartFiltering", "FltCreateCommunicationPort",
    "FltSendMessage", "FltGetVolumeFromName", "FltGetInstanceFromVolume",
    "FltCreateFileEx", "FltReadFile", "FltWriteFile", "FltSetInformationFile",
    "PsSetCreateProcessNotifyRoutine", "PsSetCreateThreadNotifyRoutine",
    "PsSetLoadImageNotifyRoutine", "ObRegisterCallbacks", "CmRegisterCallback",
    "IoRegisterFsRegistrationChange", "KeRegisterBugCheckReasonCallback",
    "ZwUnloadDriver", "MmGetSystemRoutineAddress", "IoCreateDevice",
]


def main():
    rows = []
    for dirpath, _d, files in os.walk(ROOT):
        for fn in sorted(files):
            if not fn.lower().endswith(".sys"):
                continue
            path = os.path.join(dirpath, fn)
            pe = PEFile(path)
            iat = imports(pe)
            hits = {k.split("!")[-1]: v for k, v in iat.items()}
            row = {name: (name in hits) for name in INTEREST}
            rows.append((fn, len(iat), row))

    names = [n for n in INTEREST]
    print(f"{'component':26s} {'imps':>5s}  " + " ".join(f"{n[:6]:>6s}" for n in names))
    for fn, n, row in rows:
        cells = " ".join(f"{'  Y   ' if row[n] else '  .   '}" for n in names)
        print(f"{fn:26s} {n:5d}  {cells}")
    print("\nlegend:")
    for i, n in enumerate(names):
        print(f"  {i+1:2d}. {n}")


if __name__ == "__main__":
    main()
