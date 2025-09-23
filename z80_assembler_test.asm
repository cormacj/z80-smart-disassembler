; Z80 Assembler Complete Test Program
; This program does NOT do anything useful at runtime.
; Its purpose is to exercise every Z80 instruction and syntax case.

        ORG 0100h             ; Origin pseudo-op

; --- 8-bit Load ---
        LD A,0                ; Immediate
        LD B,1
        LD C,2
        LD D,3
        LD E,4
        LD H,5
        LD L,6

        LD A,B                ; Register to register
        LD B,C
        LD D,E
        LD H,L
        LD L,A

        LD A,(HL)             ; Memory to register
        LD (HL),A
        LD (HL),B
        LD (HL),C

        LD A,(IX+5)           ; Indexed
        LD (IX+5),A
        LD A,(IY-6)
        LD (IY-6),A

; --- 16-bit Load ---
        LD BC,1234h           ; Immediate
        LD DE,5678h
        LD HL,9ABCh
        LD SP,0FEDh

        LD HL,(DATA_AREA)         ; Indirect
        LD (DATA_AREA),HL
        LD DE,(2000h)
        LD (2000h),DE
        LD BC,(3000h)
        LD (3000h),BC
        LD SP,(4000h)
        LD (4000h),SP

        LD (1234h),A          ; Direct
        LD (1234h),BC
        LD (1234h),DE
        LD (1234h),HL

        LD IX,0ABCDh
        LD IY,0BCDEh
        LD (IX+0),A
        LD (IY+127),B

; --- Exchange, Stack, Transfer ---
        EX DE,HL
        EX AF,AF'
        EXX
        EX (SP),HL
        EX (SP),IX
        EX (SP),IY

        PUSH AF
        PUSH BC
        PUSH DE
        PUSH HL
        PUSH IX
        PUSH IY

        POP AF
        POP BC
        POP DE
        POP HL
        POP IX
        POP IY

; --- 8-bit Arithmetic ---
        ADD A,B
        ADD A,C
        ADD A,D
        ADD A,E
        ADD A,H
        ADD A,L
        ADD A,(HL)
        ADD A,(IX+1)
        ADD A,(IY-2)
        ADD A,0x12

        ADC A,B
        ADC A,(HL)
        ADC A,0x34

        SUB B
        SUB (HL)
        SUB (IX+3)
        SUB 0x56

        SBC A,C
        SBC A,(HL)
        SBC A,0x78

        INC A
        INC B
        INC (HL)
        INC (IX+1)
        INC (IY-1)

        DEC A
        DEC C
        DEC (HL)
        DEC (IX+2)
        DEC (IY-3)

        AND B
        AND (HL)
        AND (IX+1)
        AND 0xFF

        OR D
        OR (HL)
        OR (IX+2)
        OR 0x0F

        XOR E
        XOR (HL)
        XOR (IX+3)
        XOR 0xF0

        CP H
        CP (HL)
        CP (IX+4)
        CP 0xAA

; --- 16-bit Arithmetic ---
        ADD HL,BC
        ADD HL,DE
        ADD HL,HL
        ADD HL,SP
        ADD IX,BC
        ADD IX,DE
        ADD IX,IX
        ADD IX,SP
        ADD IY,BC
        ADD IY,DE
        ADD IY,IY
        ADD IY,SP

        ADC HL,BC
        SBC HL,DE

        INC BC
        INC DE
        INC HL
        INC SP
        INC IX
        INC IY

        DEC BC
        DEC DE
        DEC HL
        DEC SP
        DEC IX
        DEC IY

; --- Rotate and Shift ---
        RLCA
        RRCA
        RLA
        RRA

        RLC B
        RRC C
        RL D
        RR E
        SLA H
        SRA L
        SRL A

        RLC (HL)
        RRC (HL)
        RL (HL)
        RR (HL)
        SLA (HL)
        SRA (HL)
        SRL (HL)

        RLC (IX+0)
        RRC (IX+1)
        RL (IX+2)
        RR (IX+3)
        SLA (IX+4)
        SRA (IX+5)
        SRL (IX+6)

        RLC (IY+7)
        RRC (IY+8)
        RL (IY+9)
        RR (IY+10)
        SLA (IY+11)
        SRA (IY+12)
        SRL (IY+13)

; --- Bit Manipulation ---
        BIT 0,A
        BIT 7,H
        BIT 2,(HL)
        BIT 4,(IX+3)
        BIT 6,(IY-1)

        SET 0,B
        SET 7,(HL)
        SET 3,(IX+2)
        SET 5,(IY+5)

        RES 0,D
        RES 7,(HL)
        RES 1,(IX+1)
        RES 2,(IY+2)

; --- Jumps, Calls, Returns ---
        JP 0x1234
        JP NZ,0x2345
        JP Z,0x3456
        JP NC,0x4567
        JP C,0x5678
        JP PO,0x6789
        JP PE,0x789A
        JP P,0x89AB
        JP M,0x9ABC
LABEL_JR:
        JP (HL)
        JP (IX)
        JP (IY)

        JR LABEL_JR
        JR NZ,LABEL_JR
        JR Z,LABEL_JR
        JR NC,LABEL_JR
        JR C,LABEL_JR

        DJNZ LABEL_JR

        CALL 0x1111
        CALL NZ,0x2222
        CALL Z,0x3333
        CALL NC,0x4444
        CALL C,0x5555
        CALL PO,0x6666
        CALL PE,0x7777
        CALL P,0x8888
        CALL M,0x9999

        RET
        RET NZ
        RET Z
        RET NC
        RET C
        RET PO
        RET PE
        RET P
        RET M

        RETI
        RETN

; --- Input/Output Instructions ---
        IN A,(0x12)
        IN B,(C)
        IN C,(C)
        IN D,(C)
        IN E,(C)
        IN H,(C)
        IN L,(C)

        OUT (0x34),A
        OUT (C),A
        OUT (C),B
        OUT (C),C
        OUT (C),D
        OUT (C),E
        OUT (C),H
        OUT (C),L

; --- Block Transfer and Search ---
        LDI
        LDIR
        LDD
        LDDR
        CPI
        CPIR
        CPD
        CPDR
        INI
        INIR
        IND
        INDR
        OUTI
        OTIR
        OUTD
        OTDR

; --- Miscellaneous ---
        CCF
        SCF
        NOP
        HALT
        DI
        EI

        IM 0
        IM 1
        IM 2

        RST 0x00
        RST 0x08
        RST 0x10
        RST 0x18
        RST 0x20
        RST 0x28
        RST 0x30
        RST 0x38

; --- Special Registers ---
        LD A,I
        LD A,R
        LD I,A
        LD R,A

DATA_AREA:
; --- Pseudo-ops and direct data ---
        DB 0x00,0xFF,0xAA
        DW 0x1234,0x5678
        DS 4
EQ_LABEL:        EQU 0x1000

label1: JP label1

        END
