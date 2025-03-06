;-----------------------------------
; Produced using: z80-disassembler.py v0.75 - A Smart Z80 reverse assembler
; Visit https://github.com/cormacj/z80-smart-disassembler for updates and to report issues
;
; Command line used: z80-disassembler.py a.bin -o example_output.asm -t sample_code.template 
;-----------------------------------

    org 0x100

    SET 7,(IY+1)               ;0x100:   fd cb 01 fe  "...." 
    JP C_0132                  ;0x104:   c3 32 01  ".2." 
;--------------------------------------
S_107:                         ;          XREF: 0x132 0x13C 
    DEFB "This is a C string", 0x00  ;0x107:   0x107 to 0x11c
;--------------------------------------
S_11a:                         ;          XREF: 
    DEFB "This is a Amstrad strin", 'g' + 0x80  ;0x11a:   0x11a to 0x134
;--------------------------------------
C_0132:                        ;          XREF: 0x104 
    LD HL,S_107                ;0x132:   21 07 01  "!.."   - References: "This is a C string"
    LD (D_0163),HL             ;0x135:   22 63 01  ""c."  
    CALL C_0154                ;0x138:   cd 54 01  ".T." 
    RET                        ;0x13b:   c9  "." 
    LD HL,S_107                ;0x13c:   21 07 01  "!.."   - References: "This is a C string"
    LD (D_0163),HL             ;0x13f:   22 63 01  ""c."  
    CALL C_0154                ;0x142:   cd 54 01  ".T." 
    RET                        ;0x145:   c9  "." 
;--------------------------------------
A_string:                      ;          XREF: 0x154 0x15C 
    DEFB 0x41                  ;0x146:   "A"
    DEFB 0x0                   ;0x147:   0x0
;--------------------------------------
AB_string:                     ;          XREF: 
    DEFB 0x41                  ;0x148:   
    DEFB "B", 0x00             ;0x149:   0x149 to 0x14b
;--------------------------------------
ABC_string:                    ;          XREF: 
    DEFB "ABC", 0x00           ;0x14b:   0x14b to 0x151
;--------------------------------------
S_14f:                         ;          XREF: 
    DEFB "ABCD", 0x00          ;0x14f:   0x14f to 0x156
;--------------------------------------
C_0154:                        ;          XREF: 0x138 
    LD HL,A_string             ;0x154:   21 46 01  "!F."  
    JR C_0132                  ;0x157:   18 d9  ".." 
    JR C_015C                  ;0x159:   18 01  ".." 
    RET                        ;0x15b:   c9  "." 
;--------------------------------------
C_015C:                        ;          XREF: 0x159 
    LD IX,A_string             ;0x15c:   dd 21 46 01  ".!F."  
    DJNZ C_015C                ;0x160:   10 fa  ".." 
    RET                        ;0x162:   c9  "." 
;--------------------------------------
D_0163:                        ;          XREF: 0x135 0x13F 
    DEFB 0x0                   ;0x163:   0x0
    DEFB 0x0                   ;0x164:   0x0
