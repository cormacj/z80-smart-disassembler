#!/usr/bin/env python3

from z80dis import z80
from z80comments import dictionary
from collections import defaultdict
import re

def code_output(address, text, display_address, comment=""):
    addr = f"{hex(address)}: " if display_address else ""
    print(f'    {text:25}  ;{addr} {comment}')

def mark_handled(start_address, size, data_type):
    for addr in range(start_address, start_address + size + 1):
        identified_areas[addr] = data_type

def update_labels(addr, xref):
    labels[addr].add(xref)

def lookup_label(addr):
    addr = int(addr)
    return f'L_{addr:X}' if (addr in labels) and (addr>code_org and addr<(code_org+len(bin_data))) else hex(addr)

def handle_data(b): #, loc, code_org):
    if (b.operands[0][0] is b.operands[0][0].REG) or (b.operands[1][0] is b.operands[0][0].REG):
        return None
    if b.operands[0][0] is b.operands[0][0].ADDR_DEREF: #if not a JP (HL)
        return b.operands[0][1]
    else:
        return b.operands[1][1]
    return None

def handle_jump(b, loc, code_org):
    #Figure out the actual address of a relative jump, or just return the address.
    if b.op.name in ('JR', 'DJNZ'): #relative
        relative_correction=code_org + loc
    else:
        relative_correction=0
    if ("(" not in z80.disasm(b)) and b.operands[0][0] is not b.operands[0][0].REG_DEREF: #if not a JP (HL)
        if b.operands[0][0] is b.operands[0][0].ADDR:
            return relative_correction + b.operands[0][1]
        elif b.operands[1][0] is b.operands[1][0].ADDR:
            return relative_correction + b.operands[1][1]
    return None

code_org = 0xc000
list_address = 1
min_length = 3
identified_areas = {}
labels = defaultdict(set)

# with open('RODOS219.ROM', 'rb') as f:
with open('a.bin', 'rb') as f:
    bin_data = f.read()

print(";Pass 0: Prep")
identified_areas = {code_org + loc: "C" for loc in range(len(bin_data) + 10)} #Assume everything is code

print(";Pass 1: Identify Data areas ", end="")
decode_buffer = bytearray(6)
data_locations = {}
loc = 0

while loc < len(bin_data):
    codesize = min(4, len(bin_data) - loc)
    decode_buffer[:codesize] = bin_data[loc:loc + codesize]
    b = z80.decode(decode_buffer, 0)
    data_addr = 0
    if b.op.name == 'LD':
        if b.operands[1][0] is b.operands[1][0].IMM:
            data_addr = b.operands[1][1]
        elif b.operands[0][0] is b.operands[1][0].ADDR_DEREF:
            data_addr = b.operands[0][1]
        if code_org < data_addr < code_org + len(bin_data):
            data_locations[data_addr] = "Found"
            mark_handled(data_addr, 2, "D")
        update_labels(data_addr, loc + code_org)
    loc += b.len

print("\n;Pass 2: Identify Strings ")
#needs rework. Should probably check all the LD A,() areas
pattern = re.compile(b'[ -~]{%d,}' % min_length)
strings_with_locations = []
str_locations = {}
str_sizes = {}
#
# for match in pattern.finditer(bin_data):
#     start_position, end_position = match.start(), match.end()
#     matched_string = match.group().decode('ascii').replace('"', '",34,"').replace("\\", '", 0x5c, "')
#     found_string = f'"{matched_string}"'
#     strings_with_locations.append((found_string, start_position, end_position))
#
# for s, start, end in strings_with_locations:
#     if re.search(r'[A-Za-z]{3,}', s):
#         str_locations[code_org+start] = s
#         str_sizes[code_org+start] = end - start
#         mark_handled(code_org + start, end - start, "D")


print(";Pass 3: Build call/jump table ", end="")
decode_buffer = bytearray(6)
jump_locations = {}
loc = 0

while loc < len(bin_data):
    codesize = min(4, len(bin_data) - loc)
    decode_buffer[:codesize] = bin_data[loc:loc + codesize]
    b = z80.decode(decode_buffer, 0)
    if loc in str_locations:
        loc += str_sizes[code_org+loc]
    elif b.op.name in ('JR', 'CALL', 'JP', 'DJNZ') and b.operands[0][0] is not b.operands[0][0].REG_DEREF:
        jump_addr = handle_jump(b, loc, code_org)
        # if b.op.name in ('JR', 'DJNZ'): #relative
        #     relative_correction=code_org + loc
        # else:
        #     relative_correction=0
        # print("jump:",jump_addr)
        if jump_addr:
            jump_locations[jump_addr] = hex(jump_addr)
            mark_handled(jump_addr, 1, "C")
            update_labels(jump_addr, loc+code_org)
        elif b.op is b.op.RET:
            mark_handled(loc, 1, "C")
        else:
            #Probably something like JP (IX)
            mark_handled(loc, 1, "C")
            # print("Error: Unhandled operator!!")
            # print("OP is:\n",z80.disasm(b))
            # print(b)
            # exit()
    loc += b.len

print("\n;Part ??: Tagging all the areas")
loc = 0
last = "C"

while loc < len(bin_data):
    identified_areas[code_org + loc] = identified_areas[code_org + loc] or last
    last = identified_areas[code_org + loc]
    loc += 1

print(";Part ??: Code:\n\n")
code_snapshot = bytearray(8)
loc = 0

print(f"org {hex(code_org)}")

while loc < len(bin_data):
    if loc + code_org in labels:
        print(";--------------------------------------")
        print(f'L_{loc + code_org:X}:'+f'{" ":23} ; {" ":8}' , end='XREF=')
        for tmp in labels[loc + code_org]:
            print(f'0x{tmp:X} ', end='')
        print("")
    codesize = min(4, len(bin_data) - loc)
    if identified_areas[code_org + loc] == "D" and (loc + code_org) in str_locations:
        code_output(loc + code_org, "DEFB " + str_locations[code_org+loc], list_address)
        loc += str_sizes[code_org+loc]
    elif identified_areas[code_org + loc] == "D":
        tmp = bin_data[loc]
        out_tmp = f'"{chr(tmp)}"' if 31 < tmp < 127 else f"('{chr(tmp - 0x80)}') + 0x80" if 31 < (tmp - 0x80) < 127 else hex(tmp)
        code_output(loc + code_org, "DEFB " + out_tmp, list_address)
        loc += 1
    elif identified_areas[code_org + loc] == "C":
        code_snapshot[:codesize] = bin_data[loc:loc + codesize]
        b = z80.decode(code_snapshot, 0)
        conds = z80.disasm(b).split(',')[0] + ","
        if b.op in (b.op.JR, b.op.DJNZ):
            jump_addr = handle_jump(b, loc, code_org)
            this_opcode=b.op.name
            if len(z80.disasm(b).split(","))>1: #conditional jumps and calls
                this_opcode=z80.disasm(b).split(",")[0]+","
            if jump_addr:
                tmp = f"{this_opcode} " + lookup_label(jump_addr)
                code_output(loc + code_org, tmp, list_address,dictionary.explain(tmp))
        elif b.op in (b.op.JP, b.op.CALL) and b.operands[0][0] is not b.operands[0][0].REG_DEREF:
            jump_addr = handle_jump(b, loc, code_org)
            if jump_addr:
                this_opcode=b.op.name
                if len(z80.disasm(b).split(","))>1: #conditional jumps and calls
                    this_opcode=z80.disasm(b).split(",")[0]+","
                tmp = f"{this_opcode} " + lookup_label(jump_addr)
                code_output(loc + code_org, tmp, list_address,dictionary.explain(z80.disasm(b)))
        elif b.op is b.op.LD:  #and b.operands[0][0] is not b.operands[0][0].REG_DEREF:
            data_addr=handle_data(b)
            if data_addr is None: # So something like LD A,(BC) or LD A,B
                code_output(loc + code_org, z80.disasm(b), list_address, dictionary.explain(z80.disasm(b)))
            else:
                tmp=z80.disasm(b)
                tmp_number=handle_data(b)
                tmp_addr=hex(handle_data(b))
                if (tmp_number>=code_org) and (tmp_number<=code_org+len(b)):
                    ld_label=f'L_{handle_data(b):X}'
                    labelled=tmp.replace(tmp_addr, ld_label) #Convert inline hex to L_xxxx label
                else:
                    labelled=tmp
                str_for_comment=""
                if data_addr in labels:
                    if handle_data(b) in str_locations:
                        str_for_comment=" - References: "+str_locations[handle_data(b)]
                code_output(loc + code_org, labelled, list_address,dictionary.explain(labelled)+" "+str_for_comment)
        else:
            code_output(loc + code_org, z80.disasm(b), list_address,dictionary.explain(z80.disasm(b)))
        loc += b.len
