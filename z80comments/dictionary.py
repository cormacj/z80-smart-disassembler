opcode_comments = {
"ADC": "Adds $2 and the carry flag to $1.",
"ADD": "Adds $2 to $1. 8-bit arithmetic: N flag is reset, P/V is interpreted as overflow. Rest of the flags is modified by definition.",
"AND": "Bitwise AND on A with $1",
"BIT": "Tests bit $1 of the memory location pointed to by $2.",
"CALL": "The current PC value plus three is pushed onto the stack, then PC is loaded with $1.",
"CALL(2)": "Conditional call using the $1 flag. If test conditions are met, the current PC value plus three is pushed onto the stack, then is loaded with $2",
"CCF": "Inverts the carry flag.",
"CP": "Subtracts $1 from A and affects flags according to the result. A is not modified.",
"CPD": "Compares the value of the memory location pointed to by HL with A. Then HL and BC are decremented. p/v is reset if BC becomes zero and set otherwise.",
"CPDR": "Compares the value of the memory location pointed to by HL with A. Then HL and BC are decremented. If BC is not zero and z is not set, this operation is repeated. p/v is reset if BC becomes zero and set otherwise, acting as an indicator that HL reached a memory location whose value equalled A before the counter went to zero. Interrupts can trigger while this instruction is processing. ",
"CPI": "Compares the value of the memory location pointed to by HL with A. Then HL is incremented and BC is decremented. p/v is reset if BC becomes zero and set otherwise.",
"CPIR": "Compares the value of the memory location pointed to by HL with A. Then HL is incremented and BC is decremented. If BC is not zero and z is not set, this operation is repeated. p/v is reset if BC becomes zero and set otherwise, acting as an indicator that HL reached a memory location whose value equalled A before the counter went to zero. Interrupts can trigger while this instruction is processing. ",
"CPL": "This instruction returns the same value as XORing A with $FF or subtracting A from 0xFF.",
"DAA": "When this instruction is executed, the A register is BCD corrected using the contents of the flags. The exact process is the following: if the least significant four bits of A contain a non-BCD digit (i. e. it is greater than 9) or the H flag is set, then $06 is added to the register. Then the four most significant bits are checked. If this more significant digit also happens to be greater than 9 or the C flag is set, then $60 is added.",
"DEC": "Subract 1 from $1",
"DI": "Resets both interrupt flip-flops, thus preventing maskable interrupts from triggering.",
"DJNZ": "The B register is decremented, and if not zero, the signed value d is added to PC. The jump is measured from the start of the instruction opcode. Note that DJNZ does a relative jump, so it can only jump between 128 bytes back/ahead.",
"EI": "Sets both interrupt flip-flops, thus allowing maskable interrupts to occur. An interrupt will not occur until after the immediately following instruction.",
"EX": "Exchanges the 16-bit contents of $1 and $2.",
"EXX": "Exchanges the 16-bit contents of BC, DE, and HL with BC', DE', and HL'.",
"HALT": "Suspends CPU operation until an interrupt or reset occurs.",
"IM": "Sets interrupt mode $1",
"IN": "A byte from the port at the 16-bit address contained in the BC register pair is written to B.",
"INC": "Add 1 to $1",
"IND": "A byte from the port at the 16-bit address contained in the BC register pair is written to the memory location pointed to by HL. Then HL and B are decremented. Note that the carry flag may be affected, contrary to documentation.",
"INDR": "A byte from the port at the 16-bit address contained in the BC register pair is written to the memory location pointed to by HL. Then HL and B are decremented. If B is not zero, this operation is repeated. Interrupts can trigger while this instruction is processing. Note that the carry flag may be affected, contrary to documentation.",
"INI": "A byte from the port at the 16-bit address contained in the BC register pair is written to the memory location pointed to by HL. Then HL is incremented and B is decremented. Note that the carry flag may be affected, contrary to documentation.",
"INIR": "A byte from the port at the 16-bit address contained in the BC register pair is written to the memory location pointed to by HL. Then HL is incremented and B is decremented. If B is not zero, this operation is repeated. Interrupts can trigger while this instruction is processing. Note that the carry flag may be affected, contrary to documentation.",
"JP": "Jump to address at $1",
"JP(2)": "Conditionally jump to $2 based on the flag in $1",
"JR": "Relative jump so it can only jump between 128 bytes back/ahead to $1",
"JR(2)": "Conditional relative jump based on $1",
"LD": "Load $1 with the value from $2",
"LDD": "Transfers a byte of data from the memory location pointed to by HL to the memory location pointed to by DE. Then HL, DE, and BC are decremented. p/v is reset if BC becomes zero and set otherwise.",
"LDDR": "Transfers a byte of data from the memory location pointed to by HL to the memory location pointed to by DE. Then HL, DE, and BC are decremented. If BC is not zero, this operation is repeated. Interrupts can trigger while this instruction is processing.",
"LDI": "Transfers a byte of data from the memory location pointed to by HL to the memory location pointed to by DE. Then HL and DE are incremented and BC is decremented. p/v is reset if BC becomes zero and set otherwise. ",
"LDIR": "Transfers a byte of data from the memory location pointed to by HL to the memory location pointed to by DE. Then HL and DE are incremented and BC is decremented. If BC is not zero, this operation is repeated. Interrupts can trigger while this instruction is processing. ",
"NEG": "The contents of A are negated (two's complement). Operation is the same as subtracting A from zero.",
"NOP": "No operation, 1 byte, 4 cycles. Can be used as filler or as a delay",
"OR": "Bitwise OR on A with $1",
"OTDR": "B is decremented. A byte from the memory location pointed to by HL is written to the port at the 16-bit address contained in the BC register pair. Then HL is decremented. If B is not zero, this operation is repeated. Interrupts can trigger while this instruction is processing. Note that the carry flag may be affected, contrary to documentation.",
"OTIR": "B is decremented. A byte from the memory location pointed to by HL is written to the port at the 16-bit address contained in the BC register pair. Then HL is incremented. If B is not zero, this operation is repeated. Interrupts can trigger while this instruction is processing. Note that the carry flag may be affected, contrary to documentation.",
# OUT (C),A
# OUT (C),B
# OUT (C),C
# OUT (C),D
# OUT (C),E
# OUT (C),H
# OUT (C),L
# OUT (n),A
# OUTD
# OUTI
# POP AF
# POP BC
# POP DE
# POP HL
# POP IX
# POP IY
# PUSH AF
# PUSH BC
# PUSH DE
# PUSH HL
# PUSH IX
# PUSH IY
# RES 1,(HL)
# RES 1,(IX+1)
# RES 1,(IY+1)
# RES 1,B
# RET
# RET C
# RET M
# RET NC
# RET NZ
# RET P
# RET PE
# RET PO
# RET Z
# RETI
# RETN
# RL (HL)
# RL (IX+1)
# RL (IY+1)
# RL B
# RLA
# RLC (HL)
# RLC (IX+1)
# RLC (IY+1)
# RLC B
# RLCA
# RLD
# RR (HL)
# RR (IX+1)
# RR (IY+1)
# RR B
# RRA
# RRC (HL)
# RRC (IX+1)
# RRC (IY+1)
# RRC B
# RRCA
# RRD
# RST 0
# RST 10H
# RST 18H
# RST 20H
# RST 28H
# RST 30H
# RST 38H
# RST 8H
# SBC A,(HL)
# SBC A,(IX+1)
# SBC A,(IY+1)
# SBC A,IXp
# SBC A,IYq
# SBC A,n
# SBC A,B
# SBC HL,BC
# SBC HL,DE
# SBC HL,HL
# SBC HL,SP
# SCF
# SET 1,(HL)
# SET 1,(IX+1)
# SET 1,(IY+1)
# SET 1,B
# SLA (HL)
# SLA (IX+1)
# SLA (IY+1)
# SLA B
# SRA (HL)
# SRA (IX+1)
# SRA (IY+1)
# SRA B
# SRL (HL)
# SRL (IX+1)
# SRL (IY+1)
# SRL B
# SUB (HL)
# SUB (IX+1)
# SUB (IY+1)
# SUB IXp
# SUB IYq
# SUB 10
# SUB B
# XOR (HL)
# XOR (IX+1)
# XOR (IY+1)
# XOR IXp
# XOR IYq
# XOR 1
"XOR A": ""
}

def build_comment(opcode,reg_1="",reg_2="",reg_3=""):
    code_comment=""
    if opcode in opcode_comments:
        result=opcode_comments[opcode]
        code_comment=result.replace("$1",reg_1).replace("$2",reg_2)
    return code_comment

def explain(opcode):
    # print(opcode)
    params={}
    params[1]=""
    params[2]=""
    params[3]=""
    params[0]=opcode.split(" ")[0].upper()
    # --Edgecase workaround--
    # Some commands eg, CALL, have alternate versions: CALL 0x1234 and CALL nz,0x1234
    # This builds the ability to have a second comment in the list.
    # so CALL and CALL(2) will return different comments.
    n=len(opcode.split(","))
    alt_opcode=f'{params[0]}({n})'
    if alt_opcode in opcode_comments:
        params[0]=alt_opcode
    # --------
    if "," in opcode: #A 3 part mnemonic eg ADD A,C
        params[1]=opcode.split(" ")[1].split(",")[0]
        params[2]=opcode.split(" ")[1].split(",")[1]
        if (len(opcode.split(","))>2): #Could happen with something like "set 7,(iy+1),a"
            params[3]=opcode.split(" ")[1].split(",")[2]
    elif opcode.count(" ")>0: #Whats left must be a two part mnemonic and not a single opcode eg PUSH HL
        params[1]=opcode.split(" ")[1]
    this_comment=build_comment(params[0],params[1],params[2],params[3])
    return this_comment

# Usage
# op="RET"
# print(explain(op))
# op="call z,0x1234"
# print(explain(op))
