#!/usr/bin/env python3

import csv
import re
from collections import defaultdict
from typing import NamedTuple


from z80comments import dictionary
from z80dis import z80

# --- Globals -----
list_address = 1
min_length = 3
identified_areas = {}
labels = defaultdict(set)
template_labels = defaultdict(set)
strings_with_locations = []
str_locations = {}
str_sizes = {}
style = "asm"
myversion = "0.50"

class Pointer(NamedTuple):
    ispointer: bool
    source: int
    destination: int

def check_for_pointer(addr):
    #Input:
    # Example: addr = 0xc000
    # Returns: Pointer.ispointer=False, pointer.source=0xc000, pointer.destination=0xc0000
    #
    # Example: (0xc000) (in the binary it points to 0xd123)
    # Returns: Pointer.ispointer=True, pointer.source=0xc000, pointer.destination=0xd123

    ptr=Pointer
    print("called:",addr)
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
    if argslist.debug:  # pragma: no cover
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
    # print(opcode)
    d = z80.decode(opcode, 0)
    # print(d)
    data_dump = ""
    txt_dump = ""
    for loop in range(0, d.len):
        data_dump = data_dump + f"{opcode[loop]:02x} "
        if code_snapshot[loop] > 31 and opcode[loop] < 127:
            txt_dump = txt_dump + chr(opcode[loop])
        else:
            txt_dump = txt_dump + "."
    # print(f'---> {data_dump} "{txt_dump}"')
    if newline == "":
        return f'\n{" ":31};{" ":8} {data_dump} "{txt_dump}"'
    else:
        return f' {data_dump} "{txt_dump}"'


def mark_handled(start_address, size, data_type):
    for addr in range(start_address, start_address + size + 1):
        # if identified_areas[addr]=="":
        identified_areas[addr] = data_type


def identified(address):
    return identified_areas[address]


def update_labels(addr, xref):
    labels[addr].add(xref)


def lookup_label(addr, prettyprint=""):
    addr = int(addr)
    result = identified(addr)
    match args.labeltype:
        case "1":
            result = identified(addr)
        case "2":
            if identified(addr) == "C":
                result = "code"
            else:
                result = "data"
    if prettyprint != "":
        return (
            f'{result}_{addr:X}:{" ":9}'
            if (addr in labels)
            and (addr >= code_org and addr < (code_org + len(bin_data)))
            else hex(addr)
        )
    else:
        return (
            f"{result}_{addr:X}"
            if (addr in labels)
            and (addr >= code_org and addr < (code_org + len(bin_data)))
            else hex(addr)
        )


def handle_data(b):  # , loc, code_org):
    # print("Processing->",z80.disasm(b),b)
    # print("Addr deref? ->",b.operands[0][0] is b.operands[0][0].ADDR_DEREF)
    # print("Addr reg? ->",(b.operands[0][0] is b.operands[0][0].REG) or (b.operands[1][0] is b.operands[0][0].REG),b.operands[0][0],b.operands[1][0])
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


def handle_jump(b, loc, code_org):
    # Figure out the actual address of a relative jump, or just return the address.
    if b.op.name in ("JR", "DJNZ"):  # relative
        relative_correction = code_org + loc
    else:
        relative_correction = 0
    if ("(" not in z80.disasm(b)) and b.operands[0][0] is not b.operands[0][
        0
    ].REG_DEREF:  # if not a JP (HL)
        if b.operands[0][0] is b.operands[0][0].ADDR:
            return relative_correction + b.operands[0][1]
        elif b.operands[1][0] is b.operands[1][0].ADDR:
            return relative_correction + b.operands[1][1]
    return None


def findstring(memstart, memend):
    # print("\n;Pass 2: Identify Strings ")
    # needs rework. Should probably check all the LD A,() areas
    pattern = re.compile(b"[ -~]{%d,}" % min_length)
    data_area = bytearray(memend - code_org)

    for loop in range(memstart - code_org, memend - code_org):
        # print(loop,memstart-code_org,bin_data[loop])
        if loop <= memend - code_org:
            data_area[loop] = bin_data[loop]
    for match in pattern.finditer(data_area):
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
            str_sizes[code_org + start] = end - start
            mark_handled(code_org + start, end - start, "D")


# First, lets get our parameters sorted out:
args = parse_arguments()

# Now check the command line arguments to make sure they are valid
validate_arguments(args)
print(args.loadaddress)

code_org = to_number(args.loadaddress)

if args.xref == "on":
    xrefstr = "XREF: "
else:
    xrefstr = ""

# with open('RODOS219.ROM', 'rb') as f:
with open(args.filename, "rb") as f:
    bin_data = f.read()


print(";Pass 0: Prep")
identified_areas = {
    code_org + loc: "" for loc in range(len(bin_data) + 1)
}  # Assume everything is code

print(";Pass 1: Identify Data areas ", end="")
decode_buffer = bytearray(6)
data_locations = {}
loc = 0

while loc < len(bin_data):
    codesize = min(4, len(bin_data) - loc)
    decode_buffer[:codesize] = bin_data[loc : loc + codesize]
    b = z80.decode(decode_buffer, 0)
    data_addr = 0
    if b.op.name == "LD":
        data_addr = handle_data(b)
        # print(data_addr)
        if data_addr is not None:  # So something like LD A,(BC) or LD A,B
            # print("Not none?")
            # print(hex(data_addr))
            tmp = z80.disasm(b)
            tmp_data_addr = handle_data(b)
            tmp_addr = hex(handle_data(b))
            if (tmp_data_addr >= code_org) and (
                tmp_data_addr <= code_org + len(bin_data)
            ):
                mark_handled(tmp_data_addr, 2, "D")
                update_labels(tmp_data_addr, code_org + loc)
        #
        # if b.operands[1][0] is b.operands[1][0].IMM:
        #     data_addr = b.operands[1][1]
        # elif b.operands[0][0] is b.operands[1][0].ADDR_DEREF:
        #     data_addr = b.operands[0][1]
        # if code_org < data_addr < code_org + len(bin_data):
        #     data_locations[data_addr] = "Found"
        #     mark_handled(data_addr, 2, "D")
        # update_labels(data_addr, loc + code_org)
    loc += b.len


print(";Pass 3: Build call/jump table ", end="")
decode_buffer = bytearray(6)
jump_locations = {}
loc = 0
mark_handled(loc, 1, "C")
while loc < len(bin_data):
    codesize = min(4, len(bin_data) - loc)
    decode_buffer[:codesize] = bin_data[loc : loc + codesize]
    b = z80.decode(decode_buffer, 0)
    if loc in str_locations:
        loc += str_sizes[code_org + loc]
    elif (
        b.op.name in ("JR", "CALL", "JP", "DJNZ")
        and b.operands[0][0] is not b.operands[0][0].REG_DEREF
    ):
        jump_addr = handle_jump(b, loc, code_org)
        # if b.op.name in ('JR', 'DJNZ'): #relative
        #     relative_correction=code_org + loc
        # else:
        #     relative_correction=0
        # print("jump:",jump_addr)
        if (
            jump_addr and jump_addr not in labels
        ):  # Its a jump, but area is already data
            jump_locations[jump_addr] = hex(jump_addr)
            mark_handled(jump_addr, 1, "C")
            update_labels(jump_addr, loc + code_org)
        elif b.op is b.op.RET:
            mark_handled(loc, 1, "C")
        # else:
        #     #Probably something like JP (IX)
        #     mark_handled(loc, 1, "C")
        #     # print("Error: Unhandled operator!!")
        #     # print("OP is:\n",z80.disasm(b))
        #     # print(b)
        #     # exit()
    loc += b.len

print("\n;Part ??: Tagging all the areas")
loc = 0
last = "C"
# print(labels)
# print(identified_areas)


print(";Part ??.a: Search for strings")
id_sort = sorted(identified_areas)
start = 0
end = 0
for data_area in id_sort:
    if data_area > code_org and data_area < (code_org + len(bin_data)):
        # print(hex(data_area),identified_areas[data_area])
        if (identified_areas[data_area] == "D") and (start == 0):
            # print(hex(data_area)," --> Data start", )
            start = data_area
        elif (identified_areas[data_area] == "C") and (start != 0):
            end = data_area
            findstring(start, end)
            start = 0
            end == 0

# Wrap up the end of code
if (end == 0) and (start != 0):
    end == len(bin_data) + code_org
    findstring(start, end)


print(";Part ??.b: Build structure")
loc = 0
loc = 0
last = "C"
while loc < len(bin_data):
    identified_areas[code_org + loc] = identified_areas[code_org + loc] or last
    last = identified_areas[code_org + loc]
    loc += 1

print(";Part ??: Code:\n\n")
code_snapshot = bytearray(8)
loc = 0

#--------------------- Main Section -------------------------

if args.style == "asm":
    print(f"org {hex(code_org)}")
else:
    print(f"     org {hex(code_org)}")


if args.templatefile is not None:
    process_template(args.templatefile)

while loc < len(bin_data):
    if (loc + code_org in labels) or (loc+code_org in template_labels):
        if (loc+code_org in template_labels):
            labelname=template_labels[loc + code_org]
        else:
            labelname=lookup_label(loc + code_org,1)

        if args.style == "asm":
            print(";--------------------------------------")
            print()
            # print(f'{lookup_label(loc + code_org)}_{loc + code_org:X}:'+f'{" ":23} ; {" ":8}' , end='XREF=')
            print(f'{labelname:30} ; {" ":8} {xrefstr}', end="")
            if args.xref == "on":
                for tmp in labels[loc + code_org]:
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
                for tmp in labels[loc + code_org]:
                    print(f"0x{tmp:X} ", end="")
            print("")

    codesize = min(4, len(bin_data) - loc)
    if identified_areas[code_org + loc] == "D" and (loc + code_org) in str_locations:
        code_output(
            loc + code_org, "DEFB " + str_locations[code_org + loc], list_address
        )
        loc += str_sizes[code_org + loc]
    elif identified_areas[code_org + loc] == "D":
        tmp = bin_data[loc]
        out_tmp = (
            f'"{chr(tmp)}"'
            if 31 < tmp < 127
            else (
                f"('{chr(tmp - 0x80)}') + 0x80" if 31 < (tmp - 0x80) < 127 else hex(tmp)
            )
        )
        code_output(loc + code_org, "DEFB " + hex(tmp), list_address, out_tmp)
        loc += 1
    elif identified_areas[code_org + loc] == "C":
        code_snapshot[:codesize] = bin_data[loc : loc + codesize]
        b = z80.decode(code_snapshot, 0)
        conds = z80.disasm(b).split(",")[0] + ","
        if b.op in (b.op.JR, b.op.DJNZ):
            jump_addr = handle_jump(b, loc, code_org)
            this_opcode = b.op.name
            if len(z80.disasm(b).split(",")) > 1:  # conditional jumps and calls
                this_opcode = z80.disasm(b).split(",")[0] + ","
            if jump_addr:
                tmp = f"{this_opcode} " + lookup_label(jump_addr)
                code_output(
                    loc + code_org,
                    tmp,
                    list_address,
                    dictionary.explain(tmp),
                    add_extra_info(code_snapshot),
                )
        elif (
            b.op in (b.op.JP, b.op.CALL)
            and b.operands[0][0] is not b.operands[0][0].REG_DEREF
        ):
            jump_addr = handle_jump(b, loc, code_org)
            if jump_addr:
                this_opcode = b.op.name
                if len(z80.disasm(b).split(",")) > 1:  # conditional jumps and calls
                    this_opcode = z80.disasm(b).split(",")[0] + ","
                tmp = f"{this_opcode} " + lookup_label(jump_addr)
                code_output(
                    loc + code_org,
                    tmp,
                    list_address,
                    dictionary.explain(z80.disasm(b)),
                    add_extra_info(code_snapshot),
                )
        elif b.op is b.op.LD:  # and b.operands[0][0] is not b.operands[0][0].REG_DEREF:
            data_addr = handle_data(b)
            # print(data_addr)
            if data_addr is None:  # So something like LD A,(BC) or LD A,B
                code_output(
                    loc + code_org,
                    z80.disasm(b),
                    list_address,
                    dictionary.explain(z80.disasm(b)),
                    add_extra_info(code_snapshot),
                )
            else:
                # print("Not none?")
                tmp = z80.disasm(b)
                tmp_data_addr = handle_data(b)
                tmp_addr = hex(handle_data(b))
                mark_handled(tmp_data_addr, 2, "D")
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
                    loc + code_org,
                    labelled,
                    list_address,
                    dictionary.explain(labelled) + " " + str_for_comment,
                    add_extra_info(code_snapshot),
                )
        else:
            code_output(
                loc + code_org,
                z80.disasm(b),
                list_address,
                dictionary.explain(z80.disasm(b)),
                add_extra_info(code_snapshot),
            )
        loc += b.len
