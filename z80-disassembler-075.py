#!/usr/bin/env python3
# what do I need?
# array for code store
# - binary array, store at code location to simplify things
#
# array for identifying what each byte probably is
# array for labels/merged with template/needs to support EQUs for external calls eg &BB19
# array for strings wwith locations

import csv
import re
from collections import defaultdict
from collections import UserDict
from typing import NamedTuple


from z80comments import explain
from z80dis import z80

# --- Globals -----
list_address = 1
min_length = 3
identified_areas = {}
labels = defaultdict(set)
template_labels = defaultdict(set)
code=defaultdict(UserDict)
# code(address) = [bin_code][code type][label pass 1][label pass 2]
# code type is one of:
# C = Code
# B, W =  Byte or word
# S = String
#
strings_with_locations = []
str_locations = {}
str_sizes = {}
style = "asm"
myversion = "0.75"

class Pointer(NamedTuple):
    ispointer: bool
    source: int
    destination: int

def get_from_code(addr,idx):
    debug(f"{addr:04x}: {idx}")
    if is_in_code(addr):
        return code[addr][idx]
    else:
        return ""

def dump_code_array(label="",address=""):
    if address!="":
        loop=to_number(address)
        print(f'{label} {hex(loop)}: {code[loop][0]:02x} {code[loop][1]} {code[loop][2]} {code[loop][3]}')
    else:
        for loop in range(min(code),max(code)):
            print(f'{label} {hex(loop)}: {code[loop][0]:02x} {code[loop][1]} {code[loop][2]} {code[loop][3]}')

def debug(message,arg1="",arg2="",arg3=""):
    if args.debug:
        print("*debug* ",message,arg1,arg2,arg3)

def check_for_pointer(addr):
    #Input:
    # Example: addr = 0xc000
    # Returns: Pointer.ispointer=False, pointer.source=0xc000, pointer.destination=0xc0000
    #
    # Example: (0xc000) (in the binary it points to 0xd123)
    # Returns: Pointer.ispointer=True, pointer.source=0xc000, pointer.destination=0xd123

    ptr=Pointer
    if addr[0]=="(":
        # Yup, we have a pointer
        p_addr=to_number(addr.replace("(","").replace(")",""))-code_org
        ptr.ispointer=True
        ptr.source=to_number(p_addr)
        ptr.destination=(bin_data[p_addr+1]*0x100)+(bin_data[p_addr]) #Get the address where the pointer is pointing to
        print("check for ptr:",hex(p_addr),hex(ptr.destination))
        return ptr
    else:
        #Not a pointer, just a number
        ptr.source=to_number(addr)
        ptr.destination=to_number(addr)
        ptr.ispointer=False
    return ptr

def process_template(filename):
    # Example template will look like this:
    # ;roms are org 0x0c000
    # ;start address, data type, label
    # ;data types:
    # ; b = byte
    # ; w = word
    # ; s = string
    # ; c = code
    # ; p = pointer
    # 0xc000,0xc000,b,ROM_TYPE
    # 0xc001,0xc001,b,ROM_MAJOR
    # 0xc002,0xc002,b,ROM_MARK
    # 0xc003,0xc003,b,ROM_MOD
    # 0xc004,0xc004,p,CMD_TABLE_PTR
    # 0xc006,(0xc004),c,ROM_INIT
    #
    # Comments are lines that start with ";"
    begin=0
    end=0
    start_template = Pointer
    end_template = Pointer

    with open(filename, mode ='r') as file:
        csvFile = csv.reader(file)
        for lines in csvFile:
            print("-------------------------------------")
            print(f'->{lines}<-')
            if (lines!=[]):
                if (lines[0][0]!=";"): #If not a comment or blank
                    print(lines)
                    start_template=check_for_pointer(lines[0])
                    if start_template.ispointer:
                        begin=start_template.destination
                        print("is pointer",hex(begin))
                    else:
                        begin=start_template.source
                        print("NOT pointer",hex(begin))

                    print("***start***",hex(start_template.source),hex(start_template.destination))
                    end_template=check_for_pointer(lines[1])
                    print("***end***",hex(end_template.source),hex(end_template.destination))
                    # Next check for pointers and assign addresses as needed.
                    if end_template.ispointer:
                        end=end_template.destination
                    else:
                        end=end_template.source
                    print("begin,end:",hex(begin),hex(end))
                    datatype=lines[2]
                    label=lines[3]
                    print(f'Tagging {label}: {hex(begin)}')
                    template_labels[begin]=label+":"
                    addr=begin
                    match datatype.lower():
                        case 'b':
                            for loop in range(begin-0xc000,end-0xc000):
                                print(loop)
                            mark_handled(addr,1,"D")
                        case "w":
                            mark_handled(addr,2,"D")
                        case "c":
                            print("Code:",hex(begin),hex(end))
                            for loop in range(start,end):
                                mark_handled(loop-code_org,1,"C")
                            mark_handled(addr,3,"C")
                        case "p":
                            mark_handled(addr,2,"D")
                            code_loc=begin #Get the address where the pointer is pointing to
                            mark_handled(code_loc,2,"D")
                        case _:
                            print("Unknown data type: ",datatype.lower())
                            exit


def to_number(n):
    try:
        return int(str(n), 0)
    except:
        try:
            return int('0x' + n, 0)
        except:
            return float(n)

def parse_arguments():
    # Build out the parameter list.
    # There is a lot here so I'm using ArgumentParser

    import argparse

    parser = argparse.ArgumentParser(description="A Smart Z80 reverse assembler")

    parser.add_argument(dest="filename", metavar="filename", action="store")
    # parser.add_argument('-p', '--pat', metavar ='pattern',
    #                     required = True, dest ='patterns',
    #                     action ='append',
    #                     help ='text pattern to search for')

    parser.add_argument("-v", dest="verbose", action="store_true", help="verbose mode")
    parser.add_argument("-o", dest="outfile", action="store", help="output file")
    parser.add_argument("-t", dest="templatefile", action="store", help="template file")

    parser.add_argument(
        "--style",
        dest="style",
        action="store",
        choices={"asm", "lst"},
        default="asm",
        help="asm produces a file that can be assembled. lst is a dump style output",
    )
    parser.add_argument(
        "-l","--load",
        dest="loadaddress",
        action="store",
        default="0x100",
        help="Specify where in RAM the code loads",
    )

    parser.add_argument(
        "--xref",
        dest="xref",
        action="store",
        choices={"off", "on"},
        default="on",
        help="Enable or disable cross references for labels",
    )
    parser.add_argument(
        "--labeltype",
        dest="labeltype",
        action="store",
        choices={"1", "2"},
        default="1",
        help="1: Uses short name eg D_A123 or C_A345  2: Uses full names, eg data_A123 or code_A123",
    )
    parser.add_argument("-d", "--debug", action="store_true", help=argparse.SUPPRESS)
    args = parser.parse_args()
    return args  # paramaterize everything


def validate_arguments(argslist):
    # Ensure that supplied arguments are valid
    if args.debug:  # pragma: no cover
        print("--- debug output ---")
        print(f"  {argslist=}")
        # print(f' {argslist.filename=}')
        # print(f'  {args.goodbye=}, {args.name=}')
        print("")


def code_output(address, text, display_address, comment="", added_details=""):

    addr = f"{hex(address)}: " if display_address else ""
    if args.style == "asm":
        print(f"    {text:25}  ;{addr} {added_details:20} {comment}")
    else:
        print(f"{addr} {added_details:20}    {text:25}  ; {comment}")


def add_extra_info(opcode, newline="X"):
    d = z80.decode(opcode, 0)
    data_dump = ""
    txt_dump = ""
    for loop in range(0, d.len):
        data_dump = data_dump + f"{opcode[loop]:02x} "
        if opcode[loop] > 31 and opcode[loop] < 127:
            txt_dump = txt_dump + chr(opcode[loop])
        else:
            txt_dump = txt_dump + "."
    if newline == "":
        return f'\n{" ":31};{" ":8} {data_dump} "{txt_dump}"'
    else:
        return f' {data_dump} "{txt_dump}"'

def is_in_code(addr):
    # Check to see if an address falls inside the code location
    #
    if (addr>=min(code)) and (addr<=(max(code))):
        return True
    else:
        return False

def mark_handled(start_address, size, data_type):
    # Mark an identified address (or range of addresses) with a data type if it's inside the code
    if is_in_code(start_address):
        update_label_name(start_address,data_type)
        for addr in range(start_address, start_address + size + 1):
            code[addr][1]=data_type


def identified(address):
    # Shorthand for code[address][1]
    return code[address][1]

def update_label_name(addr, type):
    # Create a label name if the address is inside the code
    # print("update_label called",hex(addr))
    if is_in_code(addr):
        code[addr][2]=f'{type}_{addr:04X}'
    # labels[addr].add(xref)

def update_labels(addr, xref):
    # Add to the xref table
    labels[addr].add(xref)

def lookup_label(addr, prettyprint=""):
    # Return a hex address if outside the code
    # If its inside the code, the generate the label based on what args.labeltype is
    # (Current 1 = C_89AB and 2 = code_89AB)
    debug("Lookup label at addr=",hex(addr))

    if not is_in_code(addr):
        return hex(addr)
    addr = int(addr)
    result = identified(addr)
    # if addr==0xf40e:
    #     dump_code_array("lookup_label",hex(addr))
    # print("Code is: ",code[addr][0],code[addr][1],code[addr][2])
    # print("checking against ",code[addr][2])
    match args.labeltype:
        case "1":
            result = identified(addr)
            debug("result=",result)
        case "2":
            if identified(addr) == "C":
                result = "code"
            else:
                result = "data"
    if prettyprint != "":
        return (
            f'{result}_{addr:X}:{" ":9}'
            if (code[addr][2]!="")
            and (is_in_code(addr))
            else hex(addr)
        )
    else:
        return (
            f"{result}_{addr:X}"
            if (code[addr][2]!="")
            and (is_in_code(addr))
            else hex(addr)
        )


def handle_data(b):  # , loc, code_org):
    # Due to how the z80 disassembly library decodes instructions, this function returns the address used in a LD instruction

    if b.operands[0][0] is b.operands[0][0].ADDR_DEREF:  # if not a LD (HL)
        # print("-->",b.operands[0][1])
        return b.operands[0][1]
    elif b.operands[0][0] is b.operands[0][0].ADDR_DEREF:  # is a LD (0x1234),HL
        # print("-->",b.operands[0][1])
        return b.operands[0][1]
    elif b.operands[1][0] is b.operands[1][0].IMM:  # is a LD (0x1234),HL
        # print("-->",b.operands[0][1])
        return b.operands[1][1]
    if (b.operands[0][0] is b.operands[0][0].REG) or (
        b.operands[1][0] is b.operands[0][0].REG
    ):
        # print("--> None",b.operands[1][1])
        return None  # b.operands[1][1]
    else:
        # print("-->",b.operands[1][1])
        return b.operands[1][1]
    # print("--> All the way to none")
    return None


def handle_jump(b, current_address):
    # Figure out the actual address of a relative jump, or just return the address.
    # The disassembler library decodes a relative jump wierdly:
    #   >>> b=z80.disasm(b'\x18\xE7\x00', 0)
    #   >>> print(b)
    #   JR 0xffe9
    #   >>> print(b)
    #   OP.JR
    #   .operands[0] = (<OPER_TYPE.ADDR: 3>, -23)
    #   >>> b=z80.disasm(b'\x18\x07\x00', 0)
    #   >>> print(b)
    #   JR 0x0009
    # So for relative addresses, do the math to get the actual address so we can make it a label
    #
    # If its not relative and not JP (HL), return the address

    if b.op.name in ("JR", "DJNZ"):  # relative
        if b.operands[0][0] is b.operands[0][0].ADDR:
            relative_correction = to_number(b.operands[0][1])
        elif b.operands[1][0] is b.operands[1][0].ADDR:
            relative_correction = to_number(b.operands[1][1])
        return current_address+relative_correction
    elif ("(" not in z80.disasm(b)) and b.operands[0][0] is not b.operands[0][0].REG_DEREF:  # if not a JP (HL)
        if b.operands[0][0] is b.operands[0][0].ADDR:
            # print(hex(b.operands[0][1]))
            return to_number(b.operands[0][1])
        elif b.operands[1][0] is b.operands[1][0].ADDR:
            # print(hex(b.operands[1][1]))
            return to_number(b.operands[1][1])
    return None


def findstring(memstart, memend):
    # Regex find strings
    # print("\n;Pass 2: Identify Strings ")
    # needs rework. Should probably check all the LD A,() areas
    pattern = re.compile(b"[ -~]{%d,}" % min_length)
    # data_area = bytearray(memend - memstart)
    data_area= bytearray()

    # for loop in range(memstart, memend):
    #     # print(loop,memstart-code_org,bin_data[loop])
    #     if loop < memend:
    #         data_area[loop] = bin_data[loop]
    for match in pattern.finditer(bin_data):
        start_position, end_position = match.start(), match.end()
        matched_string = (
            match.group()
            .decode("ascii")
            .replace('"', '",34,"')
            .replace("\\", '", 0x5c, "')
        )
        found_string = f'"{matched_string}"'
        strings_with_locations.append((found_string, start_position, end_position))

    for s, start, end in strings_with_locations:
        if re.search(r"[A-Za-z]{3,}", s):
            str_locations[code_org + start] = s
            print(s)
            str_sizes[code_org + start] = end - start
            mark_handled(code_org + start, end - start, "D")

#------============ Main Area ============------
#
# First, lets get our parameters sorted out:
args = parse_arguments()

# Now check the command line arguments to make sure they are valid
validate_arguments(args)

code_org = to_number(args.loadaddress)

if args.xref == "on":
    xrefstr = "XREF: "
else:
    xrefstr = ""


print(";Loading code")
# Load binary file
with open(args.filename, "rb") as f:
    bin_data = f.read()

# Copy the binary file to the proper memory location and for processing
loc=0
while loc < len(bin_data):
    if loc>(len(bin_data)-5):
        debug(f'!! {hex(loc)}-->{hex(code_org+loc)} : {hex(bin_data[loc])}')

    code[code_org+loc][0]=bin_data[loc] # Binary data
    code[code_org+loc][1]="" # Code Type
    code[code_org+loc][2]="" # Label identification pass 1
    code[code_org+loc][3]="" # Label identification pass 2
    # print("copying ",bin_data[loc]," to ",hex(code_org+loc),". Result is ",code[code_org+loc][0])
    loc += 1

#Add padding because max(code) causes breaking. Grrr. Grumble, Grumble.
code[code_org+loc][0]=0
code[code_org+loc][1]=""
code[code_org+loc][2]=""
code[code_org+loc][3]=""

# print(hex(loc))
# print(len(bin_data))
# print(hex(len(bin_data)+0xc000))
# print(hex(min(code)))
# print(hex(max(code)))
# print(max(code)-min(code))
# for n in code:
#     if n>(0xc000+len(bin_data)-5):
#         debug(f'{hex(n)}: {hex(code[n][0])}')

# print(";Pass 0: Prep")
# identified_areas = {
#     code_org + loc: "" for loc in range(len(bin_data) + 1)
# }  # Assume everything is code

print(";Pass 1: Identify addressable areas ", end="")
decode_buffer = bytearray(6)
data_locations = {}
jump_locations = {}
# print(hex(min(code)),hex(max(code)))

loc = min(code)
end_of_code=max(code)

while loc <= end_of_code:
    # if loc>(end_of_code-5):
    #     print(hex(loc),"-->",hex(end_of_code))
    #Build a decoding buffer
    codesize = min(4, end_of_code-loc)
    for loop in range(0,codesize):
        decode_buffer[loop] = code[loop+loc][0]
    b = z80.decode(decode_buffer, 0)
    data_addr = 0
    if b.op.name == "LD":
        # print("LD process")
        data_addr = handle_data(b)
        # print(data_addr)
        if data_addr is not None:  # So something like LD A,(BC) or LD A,B
            # print("Not none?")
            # print(hex(loc))
            # print(z80.disasm(b))
            # print(hex(data_addr))
            tmp = z80.disasm(b)
            tmp_data_addr = handle_data(b)
            tmp_addr = hex(handle_data(b))
            # print(hex(tmp_data_addr))
            if is_in_code(tmp_data_addr):
                mark_handled(tmp_data_addr, 2, "D")
                update_labels(tmp_data_addr, loc)
    elif (b.op.name in ("JR", "CALL", "JP", "DJNZ")) and (b.operands[0][0] is not b.operands[0][0].REG_DEREF):
        jump_addr = handle_jump(b, loc)
        # debug("JP to ",hex(jump_addr))
        # if b.op.name in ('JR', 'DJNZ'): #relative
        #     relative_correction=code_org + loc
        # else:
        #     relative_correction=0
        # print("jump:",jump_addr)
        if (jump_addr and jump_addr not in labels):  # Its a jump, but area is already data
            # debug("JP to ",hex(jump_addr))
            jump_locations[jump_addr] = hex(jump_addr)
            mark_handled(jump_addr, 1, "C")
            # mark_handled(loc, 1, "C")
            update_labels(jump_addr, loc)
        elif b.op is b.op.RET:
            mark_handled(loc, 1, "C")
    loc += b.len

#//TODO: Reimpliment
print(";Part ??.a: Search for strings")
id_sort = sorted(identified_areas)
start = 0
end = len(bin_data)
findstring(start, end)

# for data_area in id_sort:
#     print(hex(data_area))
#     if data_area > code_org and data_area < (code_org + len(bin_data)):
#         # print(hex(data_area),identified_areas[data_area])
#         if (identified_areas[data_area] == "D") and (start == 0):
#             # print(hex(data_area)," --> Data start", )
#             start = data_area
#         elif (identified_areas[data_area] == "C") and (start != 0):
#             end = data_area
#             findstring(start, end)
#             start = 0
#             end == 0
#
# # Wrap up the end of code
# if (end == 0) and (start != 0):
#     end == len(bin_data) + code_org
#     findstring(start, end)


print(";Part ??.b: Build structure")
loc = min(code)
last = "C"
while loc <= max(code):
    # debug("Before:",code[loc][1])
    code[loc][1] = code[loc][1] or last
    # debug("After:",code[loc][1])
    last = code[loc][1]
    loc += 1

print(";Part ??: Code:\n\n")
code_snapshot = bytearray(8)
loc = 0

#--------------------- Main Section -------------------------

# dump_code_array()

# print("disasm")
print("")
if args.style == "asm":
    print(f"org {hex(code_org)}")
else:
    print(f"     org {hex(code_org)}")


if args.templatefile is not None:
    process_template(args.templatefile)


# -- Pass 1 --
# This is nearly the final assembly.
# In this pass I'm building the final labels but not outputting code
print("Pass 1")
# dump_code_array()
program_counter=min(code)

while program_counter < max(code):
    debug("loc=",hex(program_counter),hex(max(code)))
    # Build a decoding buffer
    codesize = min(4, end_of_code - program_counter)
    for loop in range(0,codesize):
        decode_buffer[loop] = code[loop+program_counter][0]
    b = z80.decode(decode_buffer, 0)

    # Next, handle labels
    if (program_counter in labels) or (program_counter in template_labels):
        if (program_counter in template_labels):
            labelname=template_labels[program_counter]
        else:
            labelname=lookup_label(program_counter,1)
        code[program_counter][3]=labelname

        # if args.style == "asm":
        #     print(";--------------------------------------")
        #     print()
        #     # print(f'{lookup_label(loc + code_org)}_{loc + code_org:X}:'+f'{" ":23} ; {" ":8}' , end='XREF=')
        #     print(f'{labelname:30} ; {" ":8} {xrefstr}', end="")
        #     if args.xref == "on":
        #         for tmp in labels[program_counter]:
        #             print(f"0x{tmp:X} ", end="")
        #     print("")
        # else:
        #     # f'    {text:25}  ;{addr} {added_details:20} {comment}')
        #     print(
        #         ";----------------------------------------------------------------------------"
        #     )
        #     print()
        #     print(
        #         f'{"":24}     {labelname:30} ; {xrefstr}', end=""
        #     )
        #     if args.xref == "on":
        #         for tmp in labels[program_counter]:
        #             print(f"0x{tmp:X} ", end="")
        #     print("")

    #Next, process code and data
    # codesize = min(4, max(code) - loc)
    # b = z80.decode(code_snapshot, 0)
    # print("--------------->",hex(loc))
    if identified(program_counter) == "D" and (program_counter in str_locations):
        #Its a string!
        debug("D - 1")
        # code_output(
        #     program_counter, "DEFB " + str_locations[program_counter], list_address
        # )
        #FIXME is this tripping too many PC increments?
        # debug("PC Bump 3")
        program_counter += str_sizes[program_counter]
    elif identified(program_counter) == "D":
        debug("D - 2")
        if is_in_code(program_counter):
            debug("D - 3")
            tmp = get_from_code(program_counter,0) #code[loc][0]
            out_tmp = (
                f'"{chr(tmp)}"'
                if 31 < tmp < 127
                else (
                    f"('{chr(tmp - 0x80)}') + 0x80" if 31 < (tmp - 0x80) < 127 else hex(tmp)
                )
            )
            # code_output(program_counter, "DEFB " + hex(tmp), list_address, out_tmp)
            # debug("PC Bump")
            program_counter += 1 #FIXME - tripping PC too much?
    elif identified(program_counter) == "C":
        debug("C - 1")
        # code_snapshot[:codesize] = bin_data[loc : loc + codesize]
        b = z80.decode(decode_buffer, 0)
        conds = z80.disasm(b).split(",")[0] + ","
        if b.op in (b.op.JR, b.op.DJNZ):
            debug("C - 1a")
            debug("Processing relative jump")
            jump_addr = handle_jump(b, program_counter)
            this_opcode = b.op.name
            if len(z80.disasm(b).split(",")) > 1:  # conditional jumps and calls
                this_opcode = z80.disasm(b).split(",")[0] + ","
            if jump_addr:
                tmp = f"{this_opcode} " + lookup_label(jump_addr)
                # code_output(
                #     program_counter,
                #     tmp,
                #     list_address,
                #     explain.code(tmp),
                #     add_extra_info(decode_buffer),
                # )
                program_counter += b.len
        elif (
            b.op in (b.op.JP, b.op.CALL)
            and b.operands[0][0] is not b.operands[0][0].REG_DEREF
        ):
            debug("C - 2")
            jump_addr = handle_jump(b, program_counter)
            debug("Processing jump")
            if jump_addr:
                this_opcode = b.op.name
                if len(z80.disasm(b).split(",")) > 1:  # conditional jumps and calls
                    this_opcode = z80.disasm(b).split(",")[0] + ","
                tmp = f"{this_opcode} " + lookup_label(jump_addr)
                # code_output(
                #     program_counter,
                #     tmp,
                #     list_address,
                #     explain.code(z80.disasm(b)),
                #     add_extra_info(decode_buffer),
                # )
                program_counter += b.len
        elif b.op is b.op.LD:  # and b.operands[0][0] is not b.operands[0][0].REG_DEREF:
            debug("C - 3")
            data_addr = handle_data(b)
            # print(data_addr)
            if data_addr is None:  # So something like LD A,(BC) or LD A,B
                # code_output(
                #     program_counter,
                #     z80.disasm(b),
                #     list_address,
                #     explain.code(z80.disasm(b)),
                #     add_extra_info(decode_buffer),
                # )
                program_counter += b.len
            else:
                debug("C - 4")
                # print("Not none?")
                tmp = z80.disasm(b)
                tmp_data_addr = handle_data(b)
                tmp_addr = hex(handle_data(b))
                # mark_handled(tmp_data_addr, 2, "D")
                if (tmp_data_addr >= code_org) and (
                    tmp_data_addr <= code_org + len(bin_data)
                ):
                    # ld_label=f'{identified(handle_data(b))}_{handle_data(b):X}'
                    ld_label = lookup_label(handle_data(b))
                    labelled = tmp.replace(
                        tmp_addr, ld_label
                    )  # Convert inline hex to L_xxxx label
                else:
                    labelled = tmp
                str_for_comment = ""
                if data_addr in labels:
                    if handle_data(b) in str_locations:
                        str_for_comment = (
                            " - References: " + str_locations[handle_data(b)]
                        )
                # code_output(
                #     program_counter,
                #     labelled,
                #     list_address,
                #     explain.code(labelled) + " " + str_for_comment,
                #     add_extra_info(decode_buffer),
                # )
                program_counter += b.len
        else:
            debug("Fell through to the end")
            # dump_code_array()
            # print(hex(program_counter))
            # print(z80.disasm(b))
            # code_output(
            #     program_counter,
            #     z80.disasm(b),
            #     list_address,
            #     explain.code(z80.disasm(b)),
            #     add_extra_info(decode_buffer),
            # )
            program_counter += b.len
            debug("PC Bump 2 - ",b.len)
    else:
        # print(b.len)
        program_counter += b.len
        debug("PC Bump 5 - ",b.len)

# -- Pass 2 --
# dump_code_array()

#Move Pass 1 into the main labels for output
for loop in range(min(code),max(code)):
    code[loop][2]=code[loop][3]

dump_code_array("Pass 2",0xf40e)

print("Pass 2")
program_counter=min(code)

while program_counter < max(code):
    debug("loc=",hex(program_counter),hex(max(code)))
    # Build a decoding buffer
    codesize = min(4, end_of_code - program_counter)
    for loop in range(0,codesize):
        decode_buffer[loop] = code[loop+program_counter][0]
    b = z80.decode(decode_buffer, 0)

    # Next, handle labels
    if (program_counter in labels) or (program_counter in template_labels):
        if (program_counter in template_labels):
            labelname=template_labels[program_counter]
        else:
            labelname=lookup_label(program_counter,1)

        if args.style == "asm":
            print(";--------------------------------------")
            print()
            # print(f'{lookup_label(loc + code_org)}_{loc + code_org:X}:'+f'{" ":23} ; {" ":8}' , end='XREF=')
            print(f'{labelname:30} ; {" ":8} {xrefstr}', end="")
            if args.xref == "on":
                for tmp in labels[program_counter]:
                    print(f"0x{tmp:X} ", end="")
            print("")
        else:
            # f'    {text:25}  ;{addr} {added_details:20} {comment}')
            print(
                ";----------------------------------------------------------------------------"
            )
            print()
            print(
                f'{"":24}     {labelname:30} ; {xrefstr}', end=""
            )
            if args.xref == "on":
                for tmp in labels[program_counter]:
                    print(f"0x{tmp:X} ", end="")
            print("")

    #Next, process code and data
    # codesize = min(4, max(code) - loc)
    # b = z80.decode(code_snapshot, 0)
    # print("--------------->",hex(loc))
    if identified(program_counter) == "D" and (program_counter in str_locations):
        #Its a string!
        debug("D2 - 1")
        code_output(
            program_counter, "DEFB " + str_locations[program_counter], list_address
        )
        #FIXME is this tripping too many PC increments?
        # debug("PC Bump 3")
        program_counter += str_sizes[program_counter]
    elif identified(program_counter) == "D":
        debug("D2 - 2")
        if is_in_code(program_counter):
            debug("D - 3")
            tmp = get_from_code(program_counter,0) #code[loc][0]
            out_tmp = (
                f'"{chr(tmp)}"'
                if 31 < tmp < 127
                else (
                    f"('{chr(tmp - 0x80)}') + 0x80" if 31 < (tmp - 0x80) < 127 else hex(tmp)
                )
            )
            code_output(program_counter, "DEFB " + hex(tmp), list_address, out_tmp)
            debug("PC Bump")
            program_counter += 1 #FIXME - tripping PC too much?
    elif identified(program_counter) == "C":
        debug("C2 - 1")
        # code_snapshot[:codesize] = bin_data[loc : loc + codesize]
        b = z80.decode(decode_buffer, 0)
        conds = z80.disasm(b).split(",")[0] + ","
        if b.op in (b.op.JR, b.op.DJNZ):
            debug("C - 1a")
            debug("Processing relative jump")
            jump_addr = handle_jump(b, program_counter)
            this_opcode = b.op.name
            if len(z80.disasm(b).split(",")) > 1:  # conditional jumps and calls
                this_opcode = z80.disasm(b).split(",")[0] + ","
            if jump_addr:
                tmp = f"{this_opcode} " + lookup_label(jump_addr)
                code_output(
                    program_counter,
                    tmp,
                    list_address,
                    explain.code(tmp),
                    add_extra_info(decode_buffer),
                )
                program_counter += b.len
        elif (
            b.op in (b.op.JP, b.op.CALL)
            and b.operands[0][0] is not b.operands[0][0].REG_DEREF
        ):
            debug("C - 2")
            jump_addr = handle_jump(b, program_counter)
            debug("Processing jump")
            #TODO: Fix jump labelling
            #The some jumps are getting bad labels and breaking reassembly.
            #In pass 1, we dry ran the output.
            #At this point code[loc][2] should be valid.
            #I need to validate that this next bit checks against code[loc][2] before making a label.
            if jump_addr:
                this_opcode = b.op.name
                if len(z80.disasm(b).split(",")) > 1:  # conditional jumps and calls
                    this_opcode = z80.disasm(b).split(",")[0] + ","
                tmp = f"{this_opcode} " + lookup_label(jump_addr)
                code_output(
                    program_counter,
                    tmp,
                    list_address,
                    explain.code(z80.disasm(b)),
                    add_extra_info(decode_buffer),
                )
                program_counter += b.len
        elif b.op is b.op.LD:  # and b.operands[0][0] is not b.operands[0][0].REG_DEREF:
            debug("C2 - 3")
            data_addr = handle_data(b)
            # print(data_addr)
            if data_addr is None:  # So something like LD A,(BC) or LD A,B
                code_output(
                    program_counter,
                    z80.disasm(b),
                    list_address,
                    explain.code(z80.disasm(b)),
                    add_extra_info(decode_buffer),
                )
                program_counter += b.len
            else:
                debug("C2 - 4")
                # print("Not none?")
                tmp = z80.disasm(b)
                tmp_data_addr = handle_data(b)
                tmp_addr = hex(handle_data(b))
                # mark_handled(tmp_data_addr, 2, "D")
                if (tmp_data_addr >= code_org) and (
                    tmp_data_addr <= code_org + len(bin_data)
                ):
                    # ld_label=f'{identified(handle_data(b))}_{handle_data(b):X}'
                    ld_label = lookup_label(handle_data(b))
                    labelled = tmp.replace(
                        tmp_addr, ld_label
                    )  # Convert inline hex to L_xxxx label
                else:
                    labelled = tmp
                str_for_comment = ""
                if data_addr in labels:
                    if handle_data(b) in str_locations:
                        str_for_comment = (
                            " - References: " + str_locations[handle_data(b)]
                        )
                code_output(
                    program_counter,
                    labelled,
                    list_address,
                    explain.code(labelled) + " " + str_for_comment,
                    add_extra_info(decode_buffer),
                )
                program_counter += b.len
        else:
            debug("Fell through to the end")
            # dump_code_array()
            # print(hex(program_counter))
            # print(z80.disasm(b))
            code_output(
                program_counter,
                z80.disasm(b),
                list_address,
                explain.code(z80.disasm(b)),
                add_extra_info(decode_buffer),
            )
            program_counter += b.len
            debug("PC2 Bump 2 - ",b.len)
    else:
        # print(b.len)
        program_counter += b.len
        debug("PC2 Bump 5 - ",b.len)
# dump_code_array()
