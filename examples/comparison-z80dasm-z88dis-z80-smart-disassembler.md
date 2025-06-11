I took AMSDOS.COM from a CPM disc and tested the output of various disassemblers:

z88dis:

```
$ z88dk.z88dk-dis -mz80 -o 0x100 -e 0x140 AMSDOS.COM
                    ld        c,$0c                         ;[0100] 0e 0c
                    call      $0005                         ;[0102] cd 05 00
                    ld        a,l                           ;[0105] 7d
                    di                                      ;[0106] f3
                    ld        bc,$7f8e                      ;[0107] 01 8e 7f
                    exx                                     ;[010a] d9
                    ex        af,af'                        ;[010b] 08
                    xor       a                             ;[010c] af
                    ex        af,af'                        ;[010d] 08
                    ld        de,$0000                      ;[010e] 11 00 00
                    cp        $30                           ;[0111] fe 30
                    jr        c,$0124                       ;[0113] 38 0f
                    ld        de,$4000                      ;[0115] 11 00 40
                    ld        bc,$7fc4                      ;[0118] 01 c4 7f
                    ld        hl,$49ed                      ;[011b] 21 ed 49
                    ld        ($4122),hl                    ;[011e] 22 22 41
                    jp        $4122                         ;[0121] c3 22 41
                    ld        sp,$c000                      ;[0124] 31 00 c0
                    ld        a,$c9                         ;[0127] 3e c9
                    ld        ($0038),a                     ;[0129] 32 38 00
                    push      de                            ;[012c] d5
                    call      $bcc8                         ;[012d] cd c8 bc
                    pop       de                            ;[0130] d1
                    ld        hl,$0139                      ;[0131] 21 39 01
                    add       hl,de                         ;[0134] 19
                    call      $bcd4                         ;[0135] cd d4 bc
                    rst       $00                           ;[0138] c7
                    ld        b,d                           ;[0139] 42
                    ld        b,c                           ;[013a] 41
                    ld        d,e                           ;[013b] 53
                    ld        c,c                           ;[013c] 49
                    jp        $001a                         ;[013d] c3 1a 00
```


z80dasm:

```
$ z80dasm -a -l AMSDOS.COM
; z80dasm 1.1.6
; command line: z80dasm -a -l AMSDOS.COM

	org	00100h

	ld c,00ch		;0100
	call 00005h		;0102
	ld a,l			;0105
	di			;0106
	ld bc,07f8eh		;0107
	exx			;010a
	ex af,af'			;010b
	xor a			;010c
	ex af,af'			;010d
	ld de,00000h		;010e
	cp 030h		;0111
	jr c,l0124h		;0113
	ld de,04000h		;0115
	ld bc,07fc4h		;0118
	ld hl,049edh		;011b
	ld (04122h),hl		;011e
	jp 04122h		;0121
l0124h:
	ld sp,0c000h		;0124
	ld a,0c9h		;0127
	ld (00038h),a		;0129
	push de			;012c
	call 0bcc8h		;012d
	pop de			;0130
	ld hl,l0139h		;0131
	add hl,de			;0134
	call 0bcd4h		;0135
	rst 0			;0138
l0139h:
	ld b,d			;0139
	ld b,c			;013a
	ld d,e			;013b
	ld c,c			;013c
	jp 0001ah		;013d
```

z80-smart-disassember:
```
$ ./z80-disassembler.py -l 0x100 AMSDOS.COM -e 0x140

z80-disassembler.py - v0.80 - A Smart Z80 reverse assembler
Visit https://github.com/cormacj/z80-smart-disassembler for updates and to report issues

Disassembling AMSDOS.COM: 64 bytes



Pass 1: Identify addressable areas

Pass 2: Search for strings

Pass 3: Build code structure

Pass 4: Validate labels

Pass 5: Produce final listing
;-----------------------------------
; Produced using: z80-disassembler.py v0.80 - A Smart Z80 reverse assembler
; Visit https://github.com/cormacj/z80-smart-disassembler for updates and to report issues
;
; Command line used: z80-disassembler.py -l 0x100 AMSDOS.COM -e 0x140
;-----------------------------------

; Define labels for external calls



    org 0x100

    LD C,12                    ;0x100:   0e 0c  ".."
    CALL 0x5                   ;0x102:   cd 05 00  "..."
    LD A,L                     ;0x105:   7d  "}"
    DI                         ;0x106:   f3  "."
    LD BC,0x7f8e               ;0x107:   01 8e 7f  "..."
    EXX                        ;0x10a:   d9  "."
    EX AF,AF'                  ;0x10b:   08  "."
    XOR A                      ;0x10c:   af  "."
    EX AF,AF'                  ;0x10d:   08  "."
    LD DE,0                    ;0x10e:   11 00 00  "..."
    CP 0x30                    ;0x111:   fe 30  ".0"
    JR c, C_0124               ;0x113:   38 0f  "8."
    LD DE,0x4000               ;0x115:   11 00 40  "..@"
    LD BC,0x7fc4               ;0x118:   01 c4 7f  "..."
    LD HL,0x49ed               ;0x11b:   21 ed 49  "!.I"
    LD (0x4122),HL             ;0x11e:   22 22 41  """A"
    JP 0x4122                  ;0x121:   c3 22 41  "."A"
;--------------------------------------
C_0124:                        ;          XREF: 0x113
    LD SP,0xc000               ;0x124:   31 00 c0  "1.."
    LD A,0xc9                  ;0x127:   3e c9  ">."
    LD (0x38),A                ;0x129:   32 38 00  "28."
    PUSH DE                    ;0x12c:   d5  "."
    CALL 0xbcc8                ;0x12d:   cd c8 bc  "..."
    POP DE                     ;0x130:   d1  "."
    LD HL,S_0139               ;0x131:   21 39 01  "!9."   - References: "BASI"
    ADD HL,DE                  ;0x134:   19  "."
    CALL 0xbcd4                ;0x135:   cd d4 bc  "..."
    RST 0                      ;0x138:   c7  "."
;--------------------------------------
S_0139:                        ;          XREF: 0x131
    DEFB "BASI", 'C' + 0x80    ;0x139:   0x139 to 0x140
    DEFB 0x1a                  ;0x13e:   0x1a
    DEFB 0x0                   ;0x13f:


Lines of code: 42
Code Labels: 1
Data Labels: 1
```
