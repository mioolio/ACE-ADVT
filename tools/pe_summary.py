import pefile,sys,hashlib,math,os
p=r"<TARGET_SYS>"
d=open(p,"rb").read()
pe=pefile.PE(p,fast_load=False)
m=pe.FILE_HEADER.Machine; opt=pe.OPTIONAL_HEADER
print("size",len(d))
print("machine %04x"%m, "chars %04x"%pe.FILE_HEADER.Characteristics)
print("subsystem",opt.Subsystem,"dllchars %04x"%opt.DllCharacteristics)
print("ImageBase %x EntryPoint %x"%(opt.ImageBase,opt.AddressOfEntryPoint))
print("SizeOfImage %x SizeOfHeaders %x Checksum %x"%(opt.SizeOfImage,opt.SizeOfHeaders,opt.CheckSum))
print("TimeDateStamp %08x"%pe.FILE_HEADER.TimeDateStamp)
try:
  print("PDB", pe.DIRECTORY_ENTRY_DEBUG[0].entry.PdbFileName)
except Exception as e:
  print("no debug dir",e)
print("--- sections ---")
print("%-10s %10s %10s %10s %10s %s"%("name","VA","VSize","RawPtr","RawSize","Chars"))
for s in pe.sections:
  print("%-10s %10x %10x %10x %10x %08x"%(s.Name.decode(errors="replace").strip("\x00"),s.VirtualAddress,s.Misc_VirtualSize,s.PointerToRawData,s.SizeOfRawData,s.Characteristics))
print("--- data dirs ---")
for i,dd in enumerate(opt.DATA_DIRECTORY):
  if dd.VirtualAddress or dd.Size:
    print(i, pefile.DIRECTORY_ENTRY[i]["name"] if i<len(pefile.DIRECTORY_ENTRY) else i, hex(dd.VirtualAddress), hex(dd.Size))
