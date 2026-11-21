import pefile,math,hashlib
p=r"<TARGET_SYS>"
d=open(p,"rb").read()
pe=pefile.PE(p)
opt=pe.OPTIONAL_HEADER
names={0:"EXPORT",1:"IMPORT",2:"RESOURCE",3:"EXCEPTION",4:"SECURITY",5:"BASERELOC",6:"DEBUG",7:"ARCH",8:"GLOBALPTR",9:"TLS",10:"LOADCFG",11:"BOUNDIMPORT",12:"IAT",13:"DELAYIMPORT",14:"CLR"}
for i,dd in enumerate(opt.DATA_DIRECTORY):
    if dd.VirtualAddress or dd.Size: print("%-12s VA=%08x size=%x"%(names.get(i,i),dd.VirtualAddress,dd.Size))
print("--- exports ---")
try:
    for e in pe.DIRECTORY_ENTRY_EXPORT.symbols: print(hex(e.address), e.name, e.ordinal)
except Exception as ex: print("none:",ex)
print("--- imports ---")
try:
    for m in pe.DIRECTORY_ENTRY_IMPORT:
        print("MODULE",m.dll.decode())
        for imp in m.imports[:40]: print("   ",imp.name, hex(imp.address) if imp.address else "")
except Exception as ex: print("none:",ex)
print("--- entropy ---")
for s in pe.sections:
    b=s.get_data()
    h=[0]*256
    for c in b: h[c]+=1
    e=-sum((x/len(b))*math.log2(x/len(b)) for x in h if x)
    print("%-8s raw=%7d ent=%.3f"%(s.Name.decode().strip("\x00"),len(b),e))
print("--- overlay ---")
end=max(s.PointerToRawData+s.SizeOfRawData for s in pe.sections)
print("sec end",hex(end),"filesize",hex(len(d)),"overlay",len(d)-end)
print("sha256",hashlib.sha256(d).hexdigest())
