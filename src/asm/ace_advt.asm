; ace_advt.asm -- top level of the ACE-ADVT.sys reassembly
; assemble with tools/build.py (nasm -f bin, flat RVA space)
BITS 64
org 0x1000

; ---- .text -------------------------------------------------
%include "parts/text_01.asm"
%include "parts/text_02.asm"
%include "parts/text_03.asm"
%include "parts/text_04.asm"
%include "parts/text_05.asm"
%include "parts/text_06.asm"
%include "parts/text_07.asm"
%include "parts/text_08.asm"
%include "parts/text_09.asm"
%include "parts/text_10.asm"
%include "parts/text_11.asm"
%include "parts/text_12.asm"
%include "parts/text_13.asm"
%include "parts/text_14.asm"
%include "parts/text_15.asm"
%include "parts/text_16.asm"
times 1536 db 0        ; virtual gap (.text -> .rdata)

; ---- .rdata -------------------------------------------------
%include "parts/rdata_data_2f000.asm"
times 1536 db 0        ; virtual gap (.rdata -> .data)

; ---- .data -------------------------------------------------
%include "parts/data_data_35000.asm"
times 52224 db 0        ; virtual gap (.data -> .pdata)

; ---- .pdata -------------------------------------------------
%include "parts/pdata_data_42000.asm"
times 3584 db 0        ; virtual gap (.pdata -> INIT)

; ---- INIT -------------------------------------------------
%include "parts/init_01.asm"
times 1024 db 0        ; virtual gap (INIT -> .rsrc)

; ---- .rsrc -------------------------------------------------
%include "parts/rsrc_data_47000.asm"
times 3072 db 0        ; virtual gap (.rsrc -> .reloc)

; ---- .reloc -------------------------------------------------
%include "parts/reloc_data_48000.asm"
times 3584 db 0        ; virtual gap (.reloc -> .tvm0)

; ---- .tvm0 -------------------------------------------------
%include "parts/tvm0_data_49000.asm"
%include "parts/tvm0_data_50000.asm"
%include "parts/tvm0_data_57000.asm"
%include "parts/tvm0_data_5e000.asm"
%include "parts/tvm0_data_65000.asm"
%include "parts/tvm0_data_6c000.asm"
%include "parts/tvm0_data_73000.asm"
%include "parts/tvm0_data_7a000.asm"
%include "parts/tvm0_data_81000.asm"
%include "parts/tvm0_data_88000.asm"
%include "parts/tvm0_data_8f000.asm"
%include "parts/tvm0_data_96000.asm"
%include "parts/tvm0_data_9d000.asm"
%include "parts/tvm0_data_a4000.asm"
%include "parts/tvm0_data_ab000.asm"
%include "parts/tvm0_data_b2000.asm"
%include "parts/tvm0_data_b9000.asm"
%include "parts/tvm0_data_c0000.asm"
%include "parts/tvm0_data_c7000.asm"
%include "parts/tvm0_data_ce000.asm"
%include "parts/tvm0_data_d5000.asm"
%include "parts/tvm0_data_dc000.asm"
%include "parts/tvm0_data_e3000.asm"
%include "parts/tvm0_data_ea000.asm"
%include "parts/tvm0_data_f1000.asm"
%include "parts/tvm0_data_f8000.asm"
%include "parts/tvm0_data_ff000.asm"
%include "parts/tvm0_data_106000.asm"
%include "parts/tvm0_data_10d000.asm"
%include "parts/tvm0_data_114000.asm"
%include "parts/tvm0_data_11b000.asm"
%include "parts/tvm0_data_122000.asm"

