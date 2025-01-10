;Pass 0: Prep
;Pass 1: Identify Data areas ;Pass 3: Build call/jump table 
;Part ??: Tagging all the areas
;Part ??.a: Search for strings
;Part ??.b: Build structure
;Part ??: Code:


org 0xc000
    SET 7,(IY+1)               ;0xc000:   fd cb 01 fe  "...." Set bit 7 of (IY+1)
    JP C_C032                  ;0xc004:   c3 32 c0  ".2."     Jump to address at 0xc032
;--------------------------------------

D_C007:                        ;         XREF=0xC032 0xC03C 
    DEFB "This is a C string"  ;0xc007:                       
    DEFB 0x0                   ;0xc019:                       
    DEFB "This is a Amstrad strin"  ;0xc01a:                       
    DEFB ('g') + 0x80          ;0xc031:                       
;--------------------------------------

C_C032:                        ;         XREF=0xC004 0xC057 
    LD HL,D_C007               ;0xc032:   21 07 c0  "!.."     Load HL with the value from D_C007  - References: "This is a C string"
    LD (D_C063),HL             ;0xc035:   22 63 c0  ""c."     Load (D_C063) with the value from HL 
    CALL C_C054                ;0xc038:   cd 54 c0  ".T."     The current PC value plus three is pushed onto the stack, then PC is loaded with 0xc054.
    RET                        ;0xc03b:   c9  "."             The top stack entry is popped into PC, resuming execution at that point.
    LD HL,D_C007               ;0xc03c:   21 07 c0  "!.."     Load HL with the value from D_C007  - References: "This is a C string"
    LD (D_C063),HL             ;0xc03f:   22 63 c0  ""c."     Load (D_C063) with the value from HL 
    CALL C_C054                ;0xc042:   cd 54 c0  ".T."     The current PC value plus three is pushed onto the stack, then PC is loaded with 0xc054.
    RET                        ;0xc045:   c9  "."             The top stack entry is popped into PC, resuming execution at that point.
;--------------------------------------

D_C046:                        ;         XREF=0xC054 0xC05C 
    DEFB "A"                   ;0xc046:                       
    DEFB 0x0                   ;0xc047:                       
    DEFB "A"                   ;0xc048:                       
    DEFB "B"                   ;0xc049:                       
    DEFB 0x0                   ;0xc04a:                       
    DEFB "ABC"                 ;0xc04b:                       
    DEFB 0x0                   ;0xc04e:                       
    DEFB "ABCD"                ;0xc04f:                       
    DEFB 0x0                   ;0xc053:                       
;--------------------------------------

C_C054:                        ;         XREF=0xC038 0xC042 
    LD HL,D_C046               ;0xc054:   21 46 c0  "!F."     Load HL with the value from D_C046 
    JR C_C032                  ;0xc057:   18 d9  ".."         Relative jump so it can only jump between 128 bytes back/ahead to C_C032
    JR C_C05C                  ;0xc059:   18 01  ".."         Relative jump so it can only jump between 128 bytes back/ahead to C_C05C
    RET                        ;0xc05b:   c9  "."             The top stack entry is popped into PC, resuming execution at that point.
;--------------------------------------

C_C05C:                        ;         XREF=0xC060 0xC059 
    LD IX,D_C046               ;0xc05c:   dd 21 46 c0  ".!F." Load IX with the value from D_C046 
    DJNZ C_C05C                ;0xc060:   10 fa  ".."         The B register is decremented, and if not zero, the signed value d is added to PC. The jump is measured from the start of the instruction opcode. Note that DJNZ does a relative jump, so it can only jump between 128 bytes back/ahead.
    RET                        ;0xc062:   c9  "."             The top stack entry is popped into PC, resuming execution at that point.
;--------------------------------------

D_C063:                        ;         XREF=0xC035 0xC03F 
    DEFB 0x0                   ;0xc063:                       
    DEFB 0x0                   ;0xc064:                       
