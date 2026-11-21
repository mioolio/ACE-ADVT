"""
tvm_map.py -- map the 111 protected functions to the helper functions they call.

Inside .tvm0 the protector resolves most services dynamically, but it still calls
plain .text helpers with `E8 rel32`.  Those calls are unambiguous byte patterns,
so each protected block can be attributed to a subsystem by the helper set it
reaches (helper -> imports comes from out/graph.json).
"""
from __future__ import annotations

import json
import os
import struct
import sys
from collections import Counter, defaultdict

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from pe_model import PEFile, IMAGE_BASE  # noqa: E402

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
OUT = os.path.join(ROOT, "out")
TARGET = r"<TARGET_SYS>"

SUBSYS = {
    "memory-map": {"IoAllocateMdl", "MmProbeAndLockPages", "MmMapLockedPagesSpecifyCache",
                   "MmUnlockPages", "IoFreeMdl", "MmUnmapLockedPages"},
    "physical": {"MmGetPhysicalAddress", "MmMapIoSpace", "MmAllocateContiguousMemory",
                 "MmFreeContiguousMemory", "MmGetVirtualForPhysical"},
    "process": {"PsLookupProcessByProcessId", "PsGetCurrentProcessId", "PsGetCurrentThreadId",
                "KeStackAttachProcess", "KeUnstackDetachProcess", "IoGetCurrentProcess",
                "ZwOpenProcess", "ZwQueryInformationProcess", "PsLookupThreadByThreadId",
                "PsGetThreadProcess", "PsThreadType", "ObReferenceObjectByHandle",
                "ObDereferenceObjectDeferDelete", "ObfReferenceObject", "ObfDereferenceObject"},
    "threads": {"PsCreateSystemThread", "PsTerminateSystemThread", "KeWaitForSingleObject",
                "KeSetSystemGroupAffinityThread", "KeRevertToUserGroupAffinityThread",
                "KeIpiGenericCall", "KeGetCurrentProcessorNumberEx",
                "KeQueryActiveProcessorCountEx", "KeQueryActiveProcessorCount"},
    "hook": {"HalDispatchTable"},
    "bugcheck": {"KeRegisterBugCheckReasonCallback", "KeDeregisterBugCheckReasonCallback",
                 "KeBugCheckEx"},
    "registry": {"ZwOpenKey", "ZwDeleteValueKey", "RtlGetVersion"},
    "unload": {"ZwUnloadDriver", "IoDeleteDevice", "IoDeleteSymbolicLink",
               "IoUnregisterShutdownNotification", "RtlFreeAnsiString"},
    "sync": {"KeAcquireGuardedMutex", "KeReleaseGuardedMutex", "KeInitializeGuardedMutex",
             "KeTryToAcquireGuardedMutex", "KeInitializeEvent", "KeSetEvent", "KeClearEvent",
             "IoCreateNotificationEvent"},
    "pool": {"ExAllocatePoolWithTag", "ExFreePoolWithTag"},
}


def classify(apis):
    score = Counter()
    for a in apis:
        short = a.split("!")[-1]
        for k, v in SUBSYS.items():
            if short in v:
                score[k] += 1
    return [k for k, _ in score.most_common(3)]


def main():
    pe = PEFile(TARGET)
    model = json.load(open(os.path.join(OUT, "model.json"), encoding="utf-8"))
    graph = json.load(open(os.path.join(OUT, "graph.json"), encoding="utf-8"))
    nodes = {int(k): v for k, v in graph["nodes"].items()}
    iat = {int(k, 16): v for k, v in model["iat"].items()}

    tv = [s for s in pe.sections if s["name"] == ".tvm0"][0]
    blob = pe.data[tv["raw_ptr"] : tv["raw_ptr"] + tv["raw_size"]]
    base = tv["va"]

    funcs = [f for f in model["functions"] if 0x49000 <= f["begin"] < 0x129000]
    funcs.sort(key=lambda f: f["begin"])
    print(f"protected functions: {len(funcs)}")

    rows = []
    for f in funcs:
        b, e = f["begin"], f["end"]
        helpers = Counter()
        for i in range(b - base, min(e - base, len(blob)) - 5):
            if blob[i] == 0xE8:
                rel = struct.unpack_from("<i", blob, i + 1)[0]
                tgt = base + i + 5 + rel
                if 0x1000 <= tgt < 0x49000:
                    helpers[tgt] += 1
        apis = []
        for h in helpers:
            n = nodes.get(h)
            if n:
                apis += n["imports"]
        rows.append(dict(begin=b, end=e, size=e - b, helpers=len(helpers),
                         apis=sorted(set(apis)), tags=classify(apis),
                         top_helpers=[hex(h) for h, _ in helpers.most_common(4)]))

    tagcount = Counter(t for r in rows for t in r["tags"][:1])
    print("primary subsystem of the protected functions:", dict(tagcount))
    api_use = Counter(a.split("!")[-1] for r in rows for a in r["apis"])
    print("\nAPIs reachable from protected code (via helpers):")
    for a, n in api_use.most_common(30):
        print(f"  {n:3d}  {a}")
    print("\n== largest protected functions ==")
    for r in sorted(rows, key=lambda r: -r["size"])[:15]:
        print(f"  {r['begin']:#08x} size={r['size']:6d} helpers={r['helpers']:3d} "
              f"tags={','.join(r['tags']) or '-'} api={','.join(a.split('!')[-1] for a in r['apis'][:4])}")
    json.dump(rows, open(os.path.join(OUT, "tvm_functions.json"), "w"), indent=1)


if __name__ == "__main__":
    main()
