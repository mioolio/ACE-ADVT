import pefile,struct,math
p=r"<TARGET_SYS>"
d=open(p,"rb").read()
pe=pefile.PE(p)
def rva2off(rva):
    for s in pe.sections:
        if s.VirtualAddress<=rva<s.VirtualAddress+max(s.Misc_VirtualSize,s.SizeOfRawData):
            return s.PointerToRawData+(rva-s.VirtualAddress)
    return None
def sec_of(rva):
    for s in pe.sections:
        if s.VirtualAddress<=rva<s.VirtualAddress+s.Misc_VirtualSize: return s.Name.decode().strip("\x00")
    return "?"
for name,rva,size in [("pdata(.pdata)",0x42000,0x3084),("exc(tvm)",0x124000,0x3228)]:
    off=rva2off(rva)
    print("=== %s rva=%x off=%s entries=%d ==="%(name,rva,hex(off) if off else None,size//12))
    from collections import Counter
    c=Counter(); mn=1<<64; mx=0
    for i in range(size//12):
        b,e,u=struct.unpack_from("<III",d,off+i*12)
        c[sec_of(b)]+=1; mn=min(mn,b); mx=max(mx,e)
    print("  sections:",dict(c)," range %x..%x"%(mn,mx))
    for i in range(0,min(4,size//12)):
        b,e,u=struct.unpack_from("<III",d,off+i*12)
        print("   entry%d begin=%x end=%x unwind=%x"%(i,b,e,u))
print("=== tvm0 entropy by 4K block ===")
s=[x for x in pe.sections if x.Name.startswith(b".tvm0")][0]
b=s.get_data()
for i in range(0,len(b),0x4000):
    blk=b[i:i+0x4000]
    h=[0]*256
    for ch in blk: h[ch]+=1
    e=-sum((x/len(blk))*math.log2(x/len(blk)) for x in h if x)
    print("  +%06x ent=%.2f  %s"%(i,e,blk[:16].hex()))
