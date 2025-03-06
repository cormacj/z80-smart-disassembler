;-----------------------------------
; Produced using: z80-disassembler.py v0.75 - A Smart Z80 reverse assembler
; Visit https://github.com/cormacj/z80-smart-disassembler for updates and to report issues
;
; Command line used: z80-disassembler.py HELLO.COM -o HELLO.disassembled.asm -l 0x100 -e 0x117 -t HELLO.template 
;-----------------------------------

    org 0x100

;--------------------------------------
Hello:                         ;          XREF: 
    LD C,9                     ;0x100:   0e 09  ".."  
    LD DE,S_109                ;0x102:   11 09 01  "..."   - References: "Hello, world!$"
    CALL 0x5                   ;0x105:   cd 05 00  "..." 
    RET                        ;0x108:   c9  "." 
;--------------------------------------
S_109:                         ;          XREF: 0x102 
    DEFB "Hello, world!$", 0x00  ;0x109:   0x109 to 0x11a
