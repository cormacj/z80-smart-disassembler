#!/usr/bin/env python3
#BUG: LD A,(0x0009) isn't parsing out the hex part for labels
"""
This program is designed to try and disassemble Z80 code and return something as close to the original
as possible. This means that strings and data need to be identified, and all the code needs to processed
and decoded.

The difficulties with this are as follows:
1. In the Amstrad CPC you can't always just go "Ok, heres the entry point, follow the code" because RSXs and
   ROMs use a selection of jumps identified by the RSX commands. This is also complicated by the Z80 command "JP (IX)"
2. Some strings look like code, and some code looks like string. This means that sometimes short strings will be missed,
   and sometimes a string gets decoded with a jump to something thats not actually a routine.
"""


# what do I need?
# array for code store
# - binary array, store at code location to simplify things
#
# array for identifying what each byte probably is
# array for labels/merged with template/needs to support EQUs for external calls eg &BB19
# array for strings with locations

import csv
import sys
import re
from collections import defaultdict
from collections import UserDict
from typing import NamedTuple

from z80comments import explain
from z80dis import z80

# --- Globals -----

# Used for processing the template file.
class Pointer(NamedTuple):
    ispointer: bool
    source: int
    destination: int

# Variables as needed
list_address = 1
min_length = 3
identified_areas = {}
labels = defaultdict(set)
template_labels = defaultdict(set)
terminator_list=[0,13,0x8d]
code=defaultdict(UserDict)
commentlevel=0
"""
code array structure is:
code[address][0] = [bin_code]
code[address][1] = [code type]
    code type is one of:
    C = Code
    B, W =  Byte or word
    S = String
code[address][2] = [label pass 1]
code[address][3] = [label pass 2]
"""

# Variables for stats
stats_labels=0 # Number of labels generated
stats_d_labels =0 # data labels
stats_c_labels =0 # code labels
stats_loc=0 # Lines of code generated
# stay_in_code = True # Don't process strings, unless its after a RET, JP, or data label
strings_with_locations = []
str_locations = {}
str_sizes = {}
style = "asm"
hexstyle = "0x"
myversion = "0.75"


#--- Debugging functions ---

def dump_code_array(label="",address=""):
    """
    A debug procedure to print out the data structure.

    @params:
        label   - Optional: Print something informational
        address - Optional: Just print a single code[] entry for that address. If address is omitted, the whole array will be printed.
    """
    if address!="":
        loop=to_number(address)
        if is_alphanumeric(code[loop][0]):
            ala=chr(code[loop][0])
        else:
            ala=""
        print(f'{label} {hex(loop)}: {code[loop][0]:02x} {code[loop][1]} {code[loop][2]} {code[loop][3]} "{ala}"')
    else:
        for loop in range(min(code),max(code)):
            if is_alphanumeric(code[loop][0]):
                ala=chr(code[loop][0])
            else:
                ala=""

            print(f'{label} {hex(loop)}: {code[loop][0]:02x} {code[loop][1]} {code[loop][2]} {code[loop][3]} "{ala}"')

def is_alphanumeric(byte):
    return (31 <= byte <= 126)  #or (65 <= byte <= 90) or (97 <= byte <= 122)

def is_terminator(byte):
    if byte in terminator_list:
        return True
    elif (31 + 128 <= byte <= 126 + 128):
        return True
    else:
        return False

def decode_terminator(byte):
    if asmtype()==3:
        hextype="&"
    else:
        hextype="0x"
    if byte>0x9f: #Asc 31+0x80
        return f"\", '{chr(byte-0x80)}' + {hextype}80"
    else:
        return f"\", {hextype}{byte:02x}"

def debug(message,arg1="",arg2="",arg3=""):
    """
    Just print a message if debug is enabled.
    """
    if args.debug:
        print("*debug* ",message,arg1,arg2,arg3)
#--------------------------------

def asmtype():
    """
    Produce a shorthand version of assembler type so I don't constantly have to do if args.assembler=="maxam"
    1=z88
    2=z80asm
    3=maxam
    """
    match args.assembler:
        case "z88":
            return 1
        case "z80asm":
            return 2
        case "maxam":
            return 3
        case _:
            print("Invalid assembler type in asmtype()")
            sys.exit(1)


def inc_program_counter(pc,inc):
    if pc+inc<=0xffff:
        return pc+inc
    else:
        return

def build_strings_from_binary_data(binary_data):
    strings = []
    current_string = []

    for byte in binary_data:
        if is_alphanumeric(byte):
            current_string.append(chr(byte))
        elif is_terminator(byte):
            if current_string:
                current_string.append(decode_terminator(byte))
                strings.append(''.join(current_string))
                current_string = []

    # Append the last string if it exists
    if current_string:
        strings.append(''.join(current_string))

    # return strings
    return (''.join(strings))

def print_progress_bar(iteration, total, prefix='', suffix='', decimals=1, length=50, fill='█', print_end="\r"):
    """
    Call in a loop to create terminal progress bar.
    If code output isn't going to a file, don't use progress bars.
    @params:
        iteration   - Required  : current iteration (Int)
        total       - Required  : total iterations (Int)
        prefix      - Optional  : prefix string (Str)
        suffix      - Optional  : suffix string (Str)
        decimals    - Optional  : positive number of decimals in percent complete (Int)
        length      - Optional  : character length of bar (Int)
        fill        - Optional  : bar fill character (Str)
        print_end   - Optional  : end character (e.g. "\r", "\r\n") (Str)
    """
    if (args.outfile is not None) and (not args.debug) and (not args.quiet):
        percent = ("{0:." + str(decimals) + "f}").format(100 * (iteration / float(total)))
        filled_length = int(length * iteration // total)
        bar = fill * filled_length + '-' * (length - filled_length)
        print(f'\r{prefix} |{bar}| {percent}% {suffix}', end=print_end)
        # # Print New Line on Complete
        # if iteration == total:
        #     print()


def do_write(asm_string=""):
    """
    Write generated code to either a file or a screen.
    """
    global stats_loc
    stats_loc=stats_loc+1
    if args.outfile is not None:
        asm_string=asm_string+'\n'
        asm_file.write(asm_string)
    else:
        print(asm_string)

def get_from_code(addr,idx):
    """
    A simple function to return only data if its inside the code we're working on.
    """
    if is_in_code(addr):
        return code[addr][idx]
    else:
        return ""

def display_version_info():
    """
    Display a version string.
    Note: This also means that I could allow custom headers later.
    """
    print()
    print(f'{sys.argv[0]} v{myversion} - A Smart Z80 reverse assembler')
    print()


def check_for_pointer(addr):
    """
    Input:
    Example: addr = 0xc000
    Returns: Pointer.ispointer=False, pointer.source=0xc000, pointer.destination=0xc0000

    Example: (0xc000) (in the binary it points to 0xd123)
    Returns: Pointer.ispointer=True, pointer.source=0xc000, pointer.destination=0xd123

    @params:
        addr    - Required: Address in the binary data array for a pointer address

    """

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
    """
    Read the template file, and decode what is being requested.

    Example template will look like this:
    ;roms are org 0x0c000
    ;start address, data type, label
    ;data types:
    ; b = byte
    ; w = word
    ; s = string
    ; c = code
    ; p = pointer
    0xc000,0xc000,b,ROM_TYPE
    0xc001,0xc001,b,ROM_MAJOR
    0xc002,0xc002,b,ROM_MARK
    0xc003,0xc003,b,ROM_MOD
    0xc004,0xc004,p,CMD_TABLE_PTR
    0xc006,(0xc004),c,ROM_INIT

    Comments are lines that start with ";"
    """

    begin=0
    end=0
    start_template = Pointer
    end_template = Pointer

    try:
        with open(filename, mode ='r') as file:
            csvFile = csv.reader(file)
            for lines in csvFile:
                # print("-------------------------------------")
                # print(f'->{lines}<-')
                if (lines!=[]):
                    if (lines[0][0]!=";"): #If not a comment or blank
                        # print(lines)
                        start_template=check_for_pointer(lines[0])
                        if start_template.ispointer:
                            begin=start_template.destination
                            # print("is pointer",hex(begin))
                        else:
                            begin=start_template.source
                            # print("NOT pointer",hex(begin))

                        # print("***start***",hex(start_template.source),hex(start_template.destination))
                        end_template=check_for_pointer(lines[1])
                        # print("***end***",hex(end_template.source),hex(end_template.destination))
                        # Next check for pointers and assign addresses as needed.
                        if end_template.ispointer:
                            end=end_template.destination
                        else:
                            end=end_template.source
                        # print("begin,end:",hex(begin),hex(end))
                        datatype=lines[2]
                        label=lines[3]
                        debug(f'Tagging {label}: {hex(begin)}')
                        # print(f'code_org={hex(code_org)}, begin={hex(begin)},len bin_data={hex(len(bin_data)+code_org)}')
                        # print(code_org < begin)
                        # print(begin < (len(bin_data)+code_org))
                        # print(hex(endaddress))
                        if not (code_org <= begin < (len(bin_data)+code_org)):
                            print("\nError: Out of bounds address in template:")
                            print(f"\t{lines[0]},{lines[1]},{lines[2]},{lines[3]}")
                            sys.exit(1)

                        code[begin][2]=label
                        code[begin][3]=label
                        template_labels[begin]=label
                        addr=begin
                        match datatype.lower():
                            # case 'b':
                            #     for loop in range(begin,end):
                            #         print(loop)
                            #     mark_handled(addr,1,"D")
                            case "w":
                                mark_handled(addr,2,"D")
                            case "c":
                                # print("Code:",hex(begin),hex(end))
                                for loop in range(begin,end):
                                    mark_handled(loop,1,"C")
                                mark_handled(addr,3,"C")
                            case "p":
                                mark_handled(addr,2,"D")
                                code_loc=begin #Get the address where the pointer is pointing to
                                mark_handled(code_loc,2,"D")
                            case "s":
                                for loop in range(begin,end-1):
                                    mark_handled(loop,1,"S")
                            case _:
                                print("Unknown data type: ",datatype.lower())
                                exit
    except OSError:
        print("Error: Could not open template file:", filename)
        sys.exit(1)

def to_number(n):
    """
    Convert a string in most formats to a number
    @params:
        n   - Required: A string containing a number in any format
    """
    try:
        return int(str(n), 0)
    except Exception:
        try:
            return int('0x' + n, 0)
        except Exception:
            return float(n)

def parse_arguments():
    """
    Process all the command line parameters
    returns ArgumentParser in args
    """

    import argparse

    parser = argparse.ArgumentParser(description="A Smart Z80 reverse assembler")

    parser.add_argument(dest="filename", metavar="filename", action="store")
    # parser.add_argument('-p', '--pat', metavar ='pattern',
    #                     required = True, dest ='patterns',
    #                     action ='append',
    #                     help ='text pattern to search for')

    parser.add_argument("-v", dest="verbose", action="store_true", help="verbose mode")
    parser.add_argument("-q", dest="quiet", action="store_true", help="quiet mode")
    parser.add_argument("-o", dest="outfile", action="store", help="output file")
    parser.add_argument("-t", dest="templatefile", action="store", help="template file")
    parser.add_argument("-s", dest="stringterminator", action="store", help=f"string terminator value - defaults are {terminator_list} and printable characters+0x80 ")

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
        "-e","--end",
        dest="endaddress",
        action="store",
        default="0",
        help="Stop disassembling before the end of the file. Note: sometimes exported files include extra data depending on the program used to extract them from a disc. Default is full length of binary file.",
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
        "--stayincode",
        dest="stay_in_code",
        action="store_true",
        # choices={"1", "2"},
        default=False,
        help="Don't try to decode data after a RET/JP",
    )
    parser.add_argument(
        "--labeltype",
        dest="labeltype",
        action="store",
        choices={"1", "2"},
        default="1",
        help="1: Uses short name eg D_A123 or C_A345  2: Uses full names, eg data_A123 or code_A123",
    )
    parser.add_argument(
        "-c","--commentlevel",
        dest="commentlevel",
        action="store",
        choices={"0","1", "2"},
        default="0",
        help="0: No code explanations 1: Data references only  2: Everything",
    )
    parser.add_argument(
        "-a","--assembler",
        dest="assembler",
        action="store",
        choices={"z88","z80asm", "maxam"},
        default="z88",
        help="Format the code for particular assemblers",
    )
    parser.add_argument("-d", "--debug", action="store_true", help=argparse.SUPPRESS)
    args = parser.parse_args()
    return args  # paramaterize everything


def validate_arguments(argslist):
    """
    Process any command line parameters that don't need to moved out to the main area of code
    """

    global asm_file
    global stay_in_code
    global hexstyle
    # print(argslist)
    # Ensure that supplied arguments are valid
    if asmtype()==3:
        hexstyle="&"
    else:
        hexstyle="0x"

    if argslist.debug:  # pragma: no cover
        print("--- debug output ---")
        print(f"  {argslist=}")
        # print(f' {argslist.filename=}')
        # print(f'  {args.goodbye=}, {args.name=}')
        print("")
    if argslist.outfile is not None:
        print("Writing code to ",argslist.outfile)
        print()
        try:
            asm_file=open(args.outfile, 'w')
        except OSError:
            print("Error: Could not write to output file:", args.outfile)
            sys.exit(1)

    if args.stringterminator is not None:
        terminator_list.append(to_number(args.stringterminator))
        # print(terminator_list)
    commentlevel=to_number(args.commentlevel)
    stay_in_code=args.stay_in_code
    #Now ensure that the template file can be opened
    try:
        if args.templatefile:
            f=open(args.templatefile,'r')
            f.close
    except OSError:
        print("Error: Could not open template file:", args.templatefile)
        sys.exit(1)
    #And ensure that the output file can be written
    try:
        if args.outfile:
            f=open(args.outfile,'w')
            f.write("\n")
            f.close
    except OSError:
        print("Error: Could not write to output file:", args.outfile)
        sys.exit(1)




def code_output(address, code, display_address, comment="", added_details=""):
    """
    Output a formatted line of code.
    Provides the ability to fine tune what is output (later coding)
    @params:
        address         - Required: Current program counter location
        code            - Required: Decoded opcodes
        display_address - Required: A toggle to handle if address is printed or not
        comments        - Optional: Used for additional information. Currently used for opcode explanations.
        added_details   - Optional: Currently used for text+hex dump
    """
    # print_label(address)
    addr = f"{hexstyle}{address:x}: " if display_address else ""
    if args.style == "asm":
        do_write(f"    {code:25}  ;{addr} {added_details:20} {comment}")
    else:
        do_write(f"{addr} {added_details:20}    {code:25}  ; {comment}")


def add_extra_info(opcode, newline="X"):
    """
    Takes an opcode and returns a hex+text dump of the binary data for that.
    @params:
        opcode  - Required: A small binary data array
        newline - Optional: Print a newline, if needed.
    """
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
    """
    Check to see if an address falls inside the code location
    @params:
        addr    - Required: address to be checked.
    Returns a boolean True if the address is inside the code, otherwise False.
    """
    if (addr>=min(code)) and (addr<=(max(code))):
        return True
    else:
        return False

def mark_handled(start_address, size, data_type):
    """
    Marks the code array to classify what the area is going to be
    @params:
        start_address   - Required: The start address of the area to be marked off.
        size            - Required: Number of bytes to mark
        data_type       - Required: What kind of data is this, eg C or D etc
    """
    # Mark an identified address (or range of addresses) with a data type if it's inside the code
    if is_in_code(start_address):
        update_label_name(start_address,data_type)
        for addr in range(start_address, start_address + size + 1):
            code[addr][1]=data_type


def identified(address):
    """
    Shorthand for code[address][1]
    """
    if(address in code):
        return code[address][1]
    else:
        return ""

def type_lookup(datatype):
    match datatype:
        case "S":
            return "string"
        case "D":
            return "data"
        case "C":
            return "code"


def update_label_name(addr, type):
    """
    Create a label name if the address is inside the code
    @params:
        addr    - Required: Address
        type    - Required: data type C/D
    Returns:
        A string in the format D_1234 or data_1234 is returns
    """

    # if is_in_code(addr):
    #     code[addr][2]=f'{type}_{addr:04X}'
    # addr=int(addr)
    # dump_code_array("update",addr)
    result="error"
    if is_in_code(addr):
        match args.labeltype:
            case "1":
                # case typr
                # debug("--> case 1")
                result = type
                # debug("result=",result)
                # print("-XX->1",result)
            case "2":
                result=type_lookup(type)
                # debug(f"--> case 2 {identified(addr)}")
                # if identified(addr) == "C":
                #     result = "code"
                # elif identified(addr) == "S":
                #     result = "string"
                # else:
                #     result = "data"
                # print("-xx->2",result)
        if asmtype()==2 and args.labeltype==1:
            # This is more of a fixup than anything else
            # z80asm is quirky and doesn't like L_AB12 style labels
            # label style 2 (code_ or data_) is fine because its longer
            code[addr][2]=f'{result}{addr:04X}'
        else:
            code[addr][2]=f'{result}_{addr:04X}'
        # print("--XX-> Writing ",code[addr][2])

def update_xref(addr, xref):
    """
    Add to the xref table. Best to explain this is with an example:
        0xA123: JP 0xB456
    In this example, this function adds 0xA123 to the coress reference address array at 0xB456, and would be used as update_xref(0xB445,0xA123)
    @params:
        addr    - Required: address that will be
        xref    - Required: tracked address from cross reference
    """
    labels[addr].add(xref)

def lookup_label(addr, prettyprint=""):
    """
    Return a hex address if addr is outside the code
    If it's inside the code, then generate the label based on what args.labeltype is
    (Currently 1 = C_89AB and 2 = code_89AB)

    @params:
        addr        - Required: address of label to be looked up
        prettyprint - Optional: add padding to the label

    Returns:
        Formatted String
    """
    if not is_in_code(addr):
        debug("-->Not in code")
        return f'{hexstyle}{addr:x}'
    elif prettyprint != "":
        # f'{result}_{addr:X}:{" ":9}'
        # print(hex(addr))
        # print(code[addr])
        # dump_code_array(f"{is_in_code(addr)} ({addr})",addr)
        if (code[addr][2]!="") and (is_in_code(addr)):
            if asmtype()>1:
                tmp=f'{code[addr][2]}'
                return tmp.lower()
            else:
                return f'{code[addr][2]}'
        else:
            return f'{hexstyle}{addr:x}'
    else:
        debug("---> hit lookup_label end")
        return (
            # f"{result}_{addr:X}"
            f'{code[addr][2]}{" ":9}'
            if (code[addr][2]!="")
            and (is_in_code(addr))
            else f'{hexstyle}{addr:x}'
        )


def handle_data(b):
    """
    Due to how the z80 disassembly library decodes instructions, this function returns the address used in a LD instruction
    The library returns the address  in one of several areas.

    @params:
        b   - a decoded instruction

    Returns:
        address, if it was discovered or None if it was something like "LD (HL),A"

    """

    if b.operands[0][0] is b.operands[0][0].ADDR_DEREF:  # if not a LD (HL)
        return b.operands[0][1]
    elif b.operands[0][0] is b.operands[0][0].ADDR_DEREF:  # is a LD (0x1234),HL
        return b.operands[0][1]
    elif b.operands[1][0] is b.operands[0][0].ADDR_DEREF:  # is a LD HL,(0x1234)
        return b.operands[1][1]
    elif b.operands[1][0] is b.operands[1][0].IMM:  # is a LD (0x1234),HL
        return b.operands[1][1]
    if (b.operands[0][0] is b.operands[0][0].REG) or (
        b.operands[1][0] is b.operands[0][0].REG
    ):
        return None  # b.operands[1][1]
    else:
        return b.operands[1][1]
    return None


def handle_jump(b, current_address,only_relative=False):
    """
    Figure out the actual address of a relative jump, or just return the address.
    The disassembler library decodes a relative jump wierdly:
      >>> b=z80.disasm(b'\x18\xE7\x00', 0)
      >>> print(b)
      JR 0xffe9
      >>> print(b)
      OP.JR
      .operands[0] = (<OPER_TYPE.ADDR: 3>, -23)
      >>> b=z80.disasm(b'\x18\x07\x00', 0)
      >>> print(b)
      JR 0x0009
    So for relative addresses, do the math to get the actual address so we can make it a label

    If its not relative and not JP (HL), return the address

    @params:
        b               - A decoded instruction
        current_address - the program counter address

    Returns:
        A hex address with relative addresses adjusted based on current_address
    """

    if b.op.name in ("JR", "DJNZ"):  # relative
        if b.operands[0][0] is b.operands[0][0].ADDR:
            relative_correction = to_number(b.operands[0][1])
        elif b.operands[1][0] is b.operands[1][0].ADDR:
            relative_correction = to_number(b.operands[1][1])
        if only_relative:
            return relative_correction
        else:
            return current_address+relative_correction
    elif ("(" not in z80.disasm(b)) and b.operands[0][0] is not b.operands[0][0].REG_DEREF:  # if not a JP (HL)
        if b.operands[0][0] is b.operands[0][0].ADDR:
            # print(hex(b.operands[0][1]))
            return to_number(b.operands[0][1])
        elif b.operands[1][0] is b.operands[1][0].ADDR:
            # print(hex(b.operands[1][1]))
            return to_number(b.operands[1][1])
    return None

def print_label(addr):
    debug(f"print_label({addr})")
    global stats_c_labels
    global stats_d_labels
    if (addr in labels) or (addr in template_labels):
        if lookup_label(addr,1)[0]!="0": # Edge case fix. Sometimes I was getting hex codes as a label
            if (code[addr][2]!=""):
                labelname=code[addr][2]+":"
                debug("0: code array",labelname)
            elif (addr in template_labels):
                labelname=template_labels[addr]+":"
                debug("1:",labelname)
            else:
                labelname=lookup_label(addr,1)+":"
                debug("2:",labelname)

            if code[addr][1]=="C":
                stats_c_labels=stats_c_labels+1
            else:
                stats_d_labels=stats_d_labels+1

            if args.style == "asm":
                do_write(";--------------------------------------")
                do_write()
                # print(f'{lookup_label(loc + code_org)}_{loc + code_org:X}:'+f'{" ":23} ; {" ":8}' , end='XREF=')
                tmp_str=f'{labelname:30} ; {" ":8} {xrefstr}'
                # print(labels)
                if args.xref == "on":
                    for tmp in labels[program_counter]:
                        tmp_str=tmp_str+f'{hexstyle}{tmp:X} '
                do_write(tmp_str)
            else:
                do_write(
                    ";----------------------------------------------------------------------------"
                )
                do_write("")
                tmp_str=f'{"":24}     {labelname:30} ; {xrefstr}'
                if args.xref == "on":
                    for tmp in labels[program_counter]:
                        tmp_str=tmp_str+f"0x{tmp:X} "
                do_write(tmp_str)

def split_string(input_string, delimiters):
    # Create a regex pattern with the delimiters
    regex_pattern = '|'.join(map(re.escape, delimiters))
    # Use re.split to split the input_string based on the pattern
    return re.split(regex_pattern, input_string)

def findstring(memstart, memend):
    """
    Regex find strings
    I need to figure out a better way to scan these
    """
    # dump_code_array()

    pattern = re.compile(b"[ -~]{%d,}" % min_length)

    print_progress_bar(0, len(bin_data), prefix='    Progress:', suffix='Complete', length=50)
    for match in pattern.finditer(bin_data):
        start_position, end_position = match.start(), match.end()
        matched_string = (
            match.group()
            .decode("ascii")
            # .replace('"', '",34,"')
            # .replace("\\", '", 0x5c, "')
        )
        found_string = f'"{matched_string}"'
        print_progress_bar(start_position, len(bin_data), prefix='    Progress:', suffix='Complete', length=50)
        strings_with_locations.append((found_string, start_position, end_position))

    print_progress_bar(len(bin_data), len(bin_data), prefix='    Progress:', suffix='Complete', length=50)
    for s, start, end in strings_with_locations:
        if re.search(r"[A-Za-z]{3,}", s):
            for delims in terminator_list:
                if s.count(chr(delims))>1:
                    l=len(s)-1
                    s=s[1:l]
                    # print(f's: ->{s}<-')
                    # print(delims,s.count(chr(delims)),s)
                    res=split_string(s,chr(delims))
                    substr_loc=start
                    for subs in res:
                        # print(subs)

                        str_len=len(subs)
                        if str_len==0:
                            # # print("----Subs location:",hex(code_org + substr_loc))
                            # code[code_org + substr_loc][1]="D" # Mark as data to avoid null string issues
                            # #End of New fix code
                            # print("Subs location:",hex(code_org + substr_loc))
                            str_locations[code_org + substr_loc] = f'{hex(code[code_org+substr_loc][0])}'
                            # print("String (sub): ",hex(code_org+substr_loc),subs)
                            str_sizes[code_org + substr_loc] = 1
                            mark_handled(code_org + substr_loc, str_len, "S")
                        else:
                            # print("Subs location:",hex(code_org + substr_loc))
                            str_locations[code_org + substr_loc] = f'"{subs}"'
                            # print("String (sub): ",hex(code_org+substr_loc),subs)
                            str_sizes[code_org + substr_loc] = str_len
                            mark_handled(code_org + substr_loc, str_len, "S")
                        substr_loc += (str_len+1) # remember we allow for the delimiter
                else:
                    str_locations[code_org + start] = s
                    # print("String: ",hex(code_org+start),s)
                    str_sizes[code_org + start] = end - start
                    mark_handled(code_org + start, end - start-1, "S")


#------============ Main Area ============------
#
display_version_info()

# First, lets get our parameters sorted out:
args = parse_arguments()

# Now check the command line arguments to make sure they are valid
validate_arguments(args)

code_org = to_number(args.loadaddress)

if args.xref == "on":
    xrefstr = "XREF: "
else:
    xrefstr = ""

if to_number(args.endaddress)==0:
    # endaddress=len(bin_data)
    readsize=-1
else:
    # print(hex(code_org))
    endaddress=to_number(args.endaddress)-code_org
    readsize=endaddress
    if (endaddress)<0:
        print("Error: End address is less than start address")
        sys.exit(1)

# Load binary file
print(f"Reading: {readsize} bytes")
try:
    with open(args.filename, "rb") as f:
        bin_data = f.read(readsize)
    print(f"Disassembling {args.filename}: {len(bin_data)} bytes\n")
except:
    print("Error: Could not read file ", args.filename)
    sys.exit(1)

# Recalculate end address
if to_number(args.endaddress)==0:
    endaddress=len(bin_data)
    readsize=-1
else:
    # print(hex(code_org))
    endaddress=to_number(args.endaddress)-code_org
    readsize=endaddress
    if (endaddress)<0:
        print("Error: End address is less than start address")
        sys.exit(1)

# print(f'args.endaddress={args.endaddress} actual={hex(len(bin_data))}  calculated={hex(endaddress)}')
print_progress_bar(0, len(bin_data), prefix='Loading code:', suffix='Complete', length=50)

# Copy the binary file to the proper memory location and for processing
loc=0
while loc < endaddress: #len(bin_data):
    print_progress_bar(loc, endaddress, prefix='Loading code:', suffix='Complete', length=50)
    code[code_org+loc][0]=bin_data[loc] # Binary data
    code[code_org+loc][1]="" # Code Type
    code[code_org+loc][2]="" # Label identification pass 1
    code[code_org+loc][3]="" # Label identification pass 2
    loc += 1
print_progress_bar(loc, endaddress, prefix='Loading code:', suffix='Complete', length=50)
print()
#Add 1 extra line of padding because max(code) causes breaking. Grrr. Grumble, Grumble.
code[code_org+loc][0]=0
code[code_org+loc][1]=""
code[code_org+loc][2]=""
code[code_org+loc][3]=""

print("\nPass 1: Identify addressable areas")
decode_buffer = bytearray(6)
data_locations = {}
jump_locations = {}

loc = min(code)
end_of_code=max(code)
# print_progress_bar(0, endaddress, prefix='    Progress:', suffix='Complete', length=50)
while loc <= end_of_code:
    print_progress_bar(loc, end_of_code, prefix='    Progress:', suffix='Complete', length=50)
    #Build a decoding buffer
    codesize = min(4, end_of_code-loc)
    for loop in range(0,codesize):
        decode_buffer[loop] = code[loop+loc][0]
    b = z80.decode(decode_buffer, 0)
    data_addr = 0
    if b.op.name == "LD":
        # print("LD process")
        data_addr = handle_data(b)
        if data_addr is not None:  # So something like LD A,(BC) or LD A,B
            tmp = z80.disasm(b)
            tmp_data_addr = handle_data(b)
            tmp_addr = hex(handle_data(b))
            # print(hex(tmp_data_addr))
            if is_in_code(tmp_data_addr):
                mark_handled(tmp_data_addr, 1, "D")
                update_xref(tmp_data_addr, loc)
    elif (b.op.name in ("JR", "CALL", "JP", "DJNZ")) and (b.operands[0][0] is not b.operands[0][0].REG_DEREF):
        jump_addr = handle_jump(b, loc)
        # print("jump addr:",hex(jump_addr))
        # debug("JP to ",hex(jump_addr))
        # if b.op.name in ('JR', 'DJNZ'): #relative
        #     relative_correction=code_org + loc
        # else:
        #     relative_correction=0
        # print("jump:",jump_addr)
        if (jump_addr and jump_addr not in labels):  # Its a jump, but area is already data
            # if jump_addr==0xd8dc:
            # print("----> Mark Handled",hex(jump_addr))

            # debug("JP to ",hex(jump_addr))
            jump_locations[jump_addr] = hex(jump_addr)
            # update_label_name(jump_addr,"C")
            mark_handled(jump_addr, 1, "C")
            # mark_handled(loc, 1, "C")
            update_xref(jump_addr, loc)
        elif b.op is b.op.RET:
            mark_handled(loc, 1, "C")
    loc += b.len
    # print(loc,end_of_code)
# if loc>=end_of_code:
print_progress_bar(endaddress, endaddress, prefix='    Progress:', suffix='Complete', length=50)


# dump_code_array("Pre pass 2",0xd8dc)
#//TODO: Reimpliment
print("\nPass 2: Search for strings")
id_sort = sorted(identified_areas)
start = 0
end = endaddress
findstring(start, end)

# dump_code_array("Post pass 2",0xd8dc)
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


print("\nPass 3: Build code structure")
loc = min(code)
last = "C"
print_progress_bar(loc-code_org, endaddress, prefix='    Progress:', suffix='Complete', length=50)
while loc <= max(code):
    print_progress_bar(loc-code_org, endaddress, prefix='    Progress:', suffix='Complete', length=50)
    code[loc][1] = code[loc][1] or last
    last = code[loc][1]
    loc += 1

# dump_code_array()

print("\nPass 4: Validate labels")
code_snapshot = bytearray(8)
loc = 0

# dump_code_array()

if args.templatefile is not None:
    process_template(args.templatefile)


# This is nearly the final assembly.
# In this pass I'm building the final labels but not outputting code
# dump_code_array()
program_counter=min(code)
print_progress_bar(program_counter-code_org, endaddress, prefix='    Progress:', suffix='Complete', length=50)

# dump_code_array()
while program_counter < max(code):
    print_progress_bar(program_counter-code_org, endaddress, prefix='    Progress:', suffix='Complete', length=50)
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
            # print(b)
            # dump_code_array("what?",0xdb7b)
            # # print(z80.decode(b))
            # print(z80.disasm(b))
            debug("lookup label: ",hex(program_counter))
            labelname=lookup_label(program_counter,1)
        code[program_counter][3]=labelname

    if identified(program_counter) == "D" and (program_counter in str_locations):
        #Its a string!
        program_counter += str_sizes[program_counter]
    elif identified(program_counter) == "D":
        if is_in_code(program_counter):
            tmp = get_from_code(program_counter,0) #code[loc][0]
            out_tmp = (
                f'"{chr(tmp)}"'
                if 31 < tmp < 127
                else (
                    f"('{chr(tmp - 0x80)}') + {hexstyle}80" if 31 < (tmp - 0x80) < 127 else hex(tmp)
                )
            )
            program_counter += 1
    elif identified(program_counter) == "C":
        b = z80.decode(decode_buffer, 0)
        conds = z80.disasm(b).split(",")[0] + ","
        if b.op in (b.op.JR, b.op.DJNZ):
            jump_addr = handle_jump(b, program_counter)
            this_opcode = b.op.name
            if len(z80.disasm(b).split(",")) > 1:  # conditional jumps and calls
                this_opcode = z80.disasm(b).split(",")[0] + ","
            if jump_addr:
                tmp = f"{this_opcode} " + lookup_label(jump_addr)
                program_counter += b.len
        elif (b.op in (b.op.JP, b.op.CALL) and b.operands[0][0] is not b.operands[0][0].REG_DEREF):
            jump_addr = handle_jump(b, program_counter)
            if jump_addr is not None:
                this_opcode = b.op.name
                if len(z80.disasm(b).split(",")) > 1:  # conditional jumps and calls
                    this_opcode = z80.disasm(b).split(",")[0] + ","
                tmp = f"{this_opcode} " + lookup_label(jump_addr)
                program_counter += b.len
            else:
                # Things like JP (IX) come here
                program_counter += b.len
        elif b.op is b.op.LD:  # and b.operands[0][0] is not b.operands[0][0].REG_DEREF:
            data_addr = handle_data(b)
            if data_addr is None:  # So something like LD A,(BC) or LD A,B
                program_counter += b.len
            else:
                tmp = z80.disasm(b)
                tmp_data_addr = handle_data(b)
                tmp_addr = hex(handle_data(b))
                if is_in_code(tmp_data_addr):
                    #We only want to mess with strings, ignore all previous instructions
                    if code[tmp_data_addr][1]=="S" and is_terminator(code[tmp_data_addr][0]):
                        mark_handled(tmp_data_addr, 0, "D")
                #End of fix
                if is_in_code(tmp_data_addr):
                # if (tmp_data_addr >= code_org) and (
                #     tmp_data_addr <= code_org + len(bin_data)
                # ):
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
                program_counter += b.len
        else:
            program_counter += b.len
    else:
        # At this point we fell through everything, so its probably a string. Just increment
        program_counter += 1
print_progress_bar(program_counter-code_org, endaddress, prefix='    Progress:', suffix='Complete', length=50)


# -- Pass 5 --
# Now scan for characters that aren't printable but marked as strings.
# I'll reflag these back to data.
for loop in range(min(code),max(code)):
    if code[loop][1]=="S" and code[loop][0]<32 and not is_terminator(code[loop][0]):
        code[loop][1]="D"


print("\nPass 5: Produce final listing")
#Move temp labels into the main labels for output
#Finalise the labelling

for loop in range(min(code),max(code)):
    code[loop][2]=code[loop][3]
    if code[loop][1]=="S" and code[loop][0]<32 and not is_terminator(code[loop][0]):
        code[loop][1]="D"

program_counter=min(code)
if args.style == "asm":
    do_write(f"org {hexstyle}{code_org:x}")
else:
    do_write(f"     org {hexstyle}{code_org:x}")

# print_progress_bar(0, endaddress, prefix='    Progress:', suffix='Complete', length=50)
while program_counter < max(code):
    # if 0xca80 < program_counter <0xca93:
    #     dump_code_array("--->",program_counter)
    print_progress_bar(program_counter, max(code), prefix='    Progress:', suffix='Complete', length=50)
    # Build a decoding buffer
    codesize = min(4, end_of_code - program_counter)
    for loop in range(0,codesize):
        decode_buffer[loop] = code[loop+program_counter][0]
    b = z80.decode(decode_buffer, 0)

    # Next, handle labels
    if (program_counter in labels) or (program_counter in template_labels):
        if (program_counter in template_labels):
            labelname=template_labels[program_counter]
            # if labelname[0]=="0":
            #     print("1 used")
        else:
            labelname=lookup_label(program_counter,1)
            # if labelname[0]=="0":
            #     print("2 used")

        if code[program_counter][1]=="C":
            stats_c_labels=stats_c_labels+1
            # stay_in_code=True
        else:
            stats_d_labels=stats_d_labels+1
            # stay_in_code=False
        # if labelname[0]=="0":
        #     print("------->",program_counter,labelname)
            # dump_code_array("---------->",program_counter)
        tmpl=labelname+":"
        if args.style == "asm":
            do_write(";--------------------------------------")
            # do_write()
            # print(f'{lookup_label(loc + code_org)}_{loc + code_org:X}:'+f'{" ":23} ; {" ":8}' , end='XREF=')

            tmp_str=f'{tmpl:30} ; {" ":8} {xrefstr}'
            if args.xref == "on":
                for tmp in labels[program_counter]:
                    tmp_str=tmp_str+f'{hexstyle}{tmp:X} '
            do_write(tmp_str)
        else:
            do_write(
                ";----------------------------------------------------------------------------"
            )
            do_write("")
            tmp_str=f'{"":24}     {tmpl:30} ; {xrefstr}'
            if args.xref == "on":
                for tmp in labels[program_counter]:
                    tmp_str=tmp_str+f"0x{tmp:X} "
            do_write(tmp_str)

    #Next, process code and data
    known_string=""
    # if  0xfcc0 < program_counter < 0xfffc:
    #     dump_code_array("-->",program_counter)
    #
    if identified(program_counter) == "S":
        # print("1",hex(program_counter),program_counter in str_locations)
        #check for the first way we gathered strings
        if program_counter in str_locations:
            orig=program_counter
            # print("---? ",hex(program_counter),str_locations[program_counter])
            a=str_locations[program_counter]
            l=len(a)-2 #-2 because its quoted
            b=a[0]+a[1:l+1].replace('"', '",34,"').replace("\\", f'", {hexstyle}5c, "')
            # print("---?B ",b)
            m=program_counter+l

            # print(f'pc={hex(program_counter)} l={l} m={hex(m)} str_loc={str_locations[program_counter]}')
            # program_counter=m
            if m<=0xffff:
                # print("2 --- ",a)
                # dump_code_array("---?0-->",program_counter)
                # dump_code_array("---?0-->",m)
                #Now check for end of string being (1) a string, and (2) a terminator
                if identified(m)=="S" and is_terminator(code[m][0]):
                    # print("3")
                    # found terminator, output it
                    # known_string=f'DEFB {b}{decode_terminator(code[m][0])}'
                    code_output(orig,f'DEFB {b}{decode_terminator(code[m][0])}',list_address,f'{hexstyle}{orig:x} to {hexstyle}{(orig+len(a)+1):x}')
                    # print(f'Bump 1 {hex(program_counter)}-->{hex(program_counter+len(a)-1)}')
                    program_counter += len(a)-1
                elif identified(m)=="S" and not is_terminator(code[m][0]):
                    # print("------>>>> 4")
                    # Causing issues with some string endings
                    #No terminator, just dump the string
                    # print("-->", hex(program_counter),b)
                    code_output(orig,f'DEFB {b}"',list_address,f'{hexstyle}{orig:x} to {hexstyle}{orig+len(a)-2:x}')
                    # print(f'Bump 2 {hex(program_counter)}-->{hex(program_counter+len(a)-2)}')
                    program_counter += len(a)-2
                    # program_counter=program_counter+len(b)
                    # str_locations[program_counter]
                else:
                    # print("5")
                    code_output(orig,f'DEFB {b}"',list_address,f'{hexstyle}{orig:x} to {hexstyle}{orig+len(a)-2:x}')
                    # print(f'Bump 3 {hex(program_counter)}-->{hex(program_counter+len(a)-2)}')
                    program_counter += len(a)-2
                    # print(hex(program_counter))
        # elif not stay_in_code:
        else:
            # print("5")
            # It wasn't already handled as a string, so lets try and figure out what it is
            #String area
            # string_counter=program_counter
            # print_label(string_counter)
            tmp_string=''
            # dump_code_array("Check",program_counter)
            strings = []
            current_string = []
            tmp_array = bytearray()
            tmp_array_index=0
            src_array_index=program_counter
            result=""
            # print("1:",hex(src_array_index))
            while (identified(src_array_index) == "S") and not is_terminator(code[src_array_index][0]) and code[src_array_index][2]=="":
                # print("2:",hex(src_array_index))
                # print(tmp_array_index)
                # dump_code_array("String Array:",src_array_index)
                # if  0xf77b < src_array_index < 0xf79c:
                #     print("---->",hex(src_array_index),identified(src_array_index))
                tmp_array.append(code[src_array_index][0])
                src_array_index += 1
                tmp_array_index +=1

                cnt=program_counter
            result=build_strings_from_binary_data(tmp_array)
            # print("-->",result)
            # result=result.replace('"', '",34,"').replace("\\", '", 0x5c, "')
            # print("---->",result,code[src_array_index][1],---code[src_array_index][2],"\n")
            # program_counter=program_counter+len(result)
            str_len=len(result)
            result=result.replace('"', '",34,"').replace("\\", '", 0x5c, "')
            # print("-->",result,(identified(program_counter) == "S"),is_terminator(code[program_counter][0]))
            # dump_code_array("-- term -->",program_counter,)
            # print("-->",result)
            #--------------------------------
            #FIXME: Something in here is breaking labels after a string, probably one of the increments
            # So its adding code area to the string if the string isn't terminated, but the area is marked as code.
            # !!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!
            if result!="":
                # if  0xf77b < program_counter < 0xf79c:
                #     print("----> 1-",hex(program_counter),identified(program_counter))
                # program_counter=program_counter+str_len
                if identified(program_counter)=="S":
                    code_output(program_counter,f'DEFB "{result}{decode_terminator(code[program_counter+str_len][0])}',list_address,f'{hexstyle}{program_counter:x} to {hexstyle}{(program_counter+str_len+1):x}')
                    # Bump for terminator
                    # print(f'Bump 4 {hex(program_counter)}-->{hex(program_counter+str_len)}')
                    program_counter +=str_len+1
                else:
                    #Probably never called, but better safe etc etc
                    code_output(program_counter,f'DEFB "{result}"',list_address)
            elif (identified(program_counter) == "S") and (code[program_counter][0]>0x80) and not is_terminator(code[program_counter][0]):
                # if  0xf77b < program_counter < 0xf79c:
                #     print("----> 2 -",hex(program_counter),identified(program_counter))
                result=result+decode_terminator(code[program_counter][0]).replace('",',"")
                code_output(program_counter-str_len,f'DEFB {result}',list_address)
                # print(f'Bump 5 {hex(program_counter)}-->{hex(program_counter+1)}')
                program_counter +=1 #str_len
            else:
                # print("----> 3 -",hex(program_counter),identified(program_counter))
                code_output(program_counter-str_len,f'DEFB {hexstyle}{(code[program_counter][0]):x}',list_address)
                # print(f'Bump 6 {hex(program_counter)}-->{hex(program_counter+1)}')
                program_counter +=1
    # elif identified(program_counter) == "D" and (program_counter in str_locations) and not stay_in_code:
    elif identified(program_counter) == "D" and (program_counter in str_locations):
        #Its a string!
        code_output(
            program_counter, "DEFB " + str_locations[program_counter], list_address
        )
        # print(f'Bump 7 {hex(program_counter)}-->{hex(program_counter+str_sizes[program_counter])}')
        program_counter += str_sizes[program_counter]
    # elif identified(program_counter) == "D" and not stay_in_code:
    elif identified(program_counter) == "D":
        # dump_code_array("---->",program_counter)

        # debug("D2 - 2")
        if is_in_code(program_counter):
            # debug("D - 3")
            tmp = get_from_code(program_counter,0) #code[loc][0]
            out_tmp = (
                f'"{chr(tmp)}"'
                if 31 < tmp < 127
                else (
                    f"('{chr(tmp - 0x80)}') + {hexstyle}80" if 31 < (tmp - 0x80) < 127 else hex(tmp)
                )
            )
            code_output(program_counter, f"DEFB {hexstyle}{tmp:x}", list_address, out_tmp)
            # debug("PC Bump")
            program_counter += 1 #FIXME - tripping PC too much?
    elif identified(program_counter) == "C": # or (stay_in_code and identified(program_counter)!="C"):
        # debug("C2 - 1")
        b = z80.decode(decode_buffer, 0)
        conds = z80.disasm(b).split(",")[0] + ","
        if b.op in (b.op.JR, b.op.DJNZ):
            # debug("C - 1a")
            # debug("Processing relative jump")
            jump_addr = handle_jump(b, program_counter)
            # print(hex(jump_addr),lookup_label(jump_addr))
            djnz_addr=lookup_label(jump_addr)
            this_opcode = b.op.name
            if len(z80.disasm(b).split(",")) > 1:  # conditional jumps and calls
                this_opcode = z80.disasm(b).split(",")[0] + ","
            if jump_addr is not None:
                if djnz_addr[0]=="0": # It's not a label, so we need to reformat
                    # print(b,f'\nja={hex(jump_addr)}, pc={hex(program_counter)} {program_counter-jump_addr} {handle_jump(b,program_counter,True)}')
                    jump_addr=handle_jump(b,program_counter,True) # The True here requests just the relative offset, no adjusting
                    if jump_addr>=0:
                        oper="+"
                    else:
                        oper=""
                    # Relative addresses are either -127 to +128
                    # Assembler directives are usually something like $+10 or $-15
                    # where $ is the current location, so this code adds the operator
                    # if its positive
                    tmp=f"{this_opcode} ${oper}{handle_jump(b,program_counter,True)} "
                else:
                    tmp = f"{this_opcode} " + lookup_label(jump_addr)
                code_output(
                    program_counter,
                    tmp,
                    list_address,
                    explain.code(tmp,commentlevel),
                    add_extra_info(decode_buffer),
                )
                program_counter += b.len
            else:
                program_counter += b.len
        elif (
            b.op in (b.op.JP, b.op.CALL)
            and b.operands[0][0] is not b.operands[0][0].REG_DEREF
        ):
            # debug("C - 2")
            jump_addr = handle_jump(b, program_counter)
            # debug("Processing jump")
            if jump_addr is not None:
                this_opcode = b.op.name
                if len(z80.disasm(b).split(",")) > 1:  # conditional jumps and calls
                    this_opcode = z80.disasm(b).split(",")[0] + ","
                tmp = f"{this_opcode} " + lookup_label(jump_addr)
                code_output(
                    program_counter,
                    tmp,
                    list_address,
                    explain.code(z80.disasm(b),commentlevel),
                    add_extra_info(decode_buffer),
                )
                program_counter += b.len
            else:
                program_counter += b.len
        elif b.op is b.op.LD:  # and b.operands[0][0] is not b.operands[0][0].REG_DEREF:
            # debug("C2 - 3")
            data_addr = handle_data(b)
            if data_addr is None:  # So something like LD A,(BC) or LD A,B
                tmp=z80.disasm(b)
                if asmtype()==3:
                    tmp=tmp.replace("0x","&")
                code_output(
                    program_counter,
                    tmp,
                    list_address,
                    explain.code(z80.disasm(b),commentlevel),
                    add_extra_info(decode_buffer),
                )
                program_counter += b.len
            else:
                tmp = z80.disasm(b).replace(f'0x{data_addr:04x}',lookup_label(data_addr,1))
                tmp_data_addr = handle_data(b)
                tmp_addr = hex(handle_data(b))
                # mark_handled(tmp_data_addr, 2, "D")
                if is_in_code(tmp_data_addr):
                # if (tmp_data_addr >= code_org) and (
                #     tmp_data_addr <= code_org + len(bin_data)
                # ):
                    ld_label = lookup_label(handle_data(b))
                    # print("---->",hex(program_counter),ld_label,hex(handle_data(b)),code[handle_data(b)][2])
                    labelled = tmp.replace(
                        tmp_addr, ld_label
                    )  # Convert inline hex to L_xxxx label
                    # print(labelled)
                else:
                    if asmtype()==3:
                        tmp=tmp.replace("0x","&")
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
                    explain.code(labelled,commentlevel) + " " + str_for_comment,
                    add_extra_info(decode_buffer),
                )
                program_counter += b.len
        else:
            tmp=z80.disasm(b)
            if asmtype()==3:
                tmp=tmp.replace("0x","&")
            code_output(
                program_counter,
                tmp,
                list_address,
                explain.code(z80.disasm(b),commentlevel),
                add_extra_info(decode_buffer),
            )
            program_counter += b.len
    else:
        # program_counter += b.len
        program_counter += 1
print_progress_bar(max(code), max(code),prefix='    Progress:', suffix='Complete', length=50)
print()
if args.outfile:
    print(args.outfile," created!")

print()
print("Lines of code:",stats_loc)
print("Code Labels:",stats_c_labels)
print("Data Labels:",stats_d_labels)
# dump_code_array()
