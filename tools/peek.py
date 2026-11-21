import pefile
from capstone import *
p=r"<TARGET_SYS>"
pe=pefile.PE(p)
def rva2off(rva):
    for s in pe.sections:
        if s.VirtualAddress<=rva<s.VirtualAddress+max(s.Misc_VirtualSize,s.SizeOfRawData):
            return s.PointerToRawData+(rva-s.VirtualAddress)
    return rva
base=pe.OPTIONAL_HEADER.ImageBase
for sec,start,ln in [("INIT",0x46000,0x2c0),("text_head",0x1000,0x200),("tvm_head",0x124000,0x200)]:
    off=rva2off(start); data=open(p,"rb").read()[off:off+ln]
    print("==== %s rva=%x ===="%(sec,start))
    md=Cs(CS_ARCH_X86,CS_MODE_64)
    for i in md.disasm(data,base+start):
        print("%08x  %-24s %s %s"%(i.address,i.bytes.hex(),i.mnemonic,i.op_str))
