import pefile,struct
from collections import Counter
p=r"<TARGET_SYS>"
d=open(p,"rb").read(); pe=pefile.PE(p)
def rva2off(rva):
    for s in pe.sections:
        if s.VirtualAddress<=rva<s.VirtualAddress+max(s.Misc_VirtualSize,s.SizeOfRawData):
            return s.PointerToRawData+(rva-s.VirtualAddress)
for sec in pe.sections:
    if sec.Name.startswith(b".text"):
        t=sec; break
tv=t.Misc_VirtualSize
off=rva2off(0x42000)
funcs=[]
for i in range(0x3084//12):
    b,e,u=struct.unpack_from("<III",d,off+i*12)
    funcs.append((b,e))
funcs.sort()
print("functions:",len(funcs))
cov=[False]*tv
for b,e in funcs:
    for x in range(b, min(e,tv)): cov[x-0x1000 if x>=0x1000 else 0]=True
n=sum(cov); print("covered bytes: %d / %d (%.1f%%)"%(n,tv,100*n/tv))
# gaps
gaps=[];i=0
while i<tv:
    if not cov[i]:
        j=i
        while j<tv and not cov[j]: j+=1
        gaps.append((i+0x1000,j-i)); i=j
    else: i+=1
print("gaps:",len(gaps),"total gap bytes",sum(g[1] for g in gaps))
# how much of gap is 0xcc
cc=0
for rva,l in gaps:
    o=rva2off(rva); seg=d[o:o+l]; cc+=seg.count(0xcc)
print("int3 bytes in gaps:",cc,"(%.1f%% of gap)"%(100*cc/sum(g[1] for g in gaps)))
gaps.sort(key=lambda x:-x[1])
print("largest gaps:")
for rva,l in gaps[:15]: print("   %x  len %d"%(rva,l))
# check for non-cc gap content sample
for rva,l in gaps[:2]:
    o=rva2off(rva); print("sample gap %x:"%rva, d[o:o+min(l,64)].hex())
