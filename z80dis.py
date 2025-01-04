#!/usr/bin/env python3

from z80dis import z80
from collections import defaultdict
import re

# b=z80.disasm(b'\xCB\x00\xE7\xCB\xE7\xCB\xE7\xCB\xE7', 0)
# print(b)
# c=z80.decode(b'\xCB\xE7',0)
# print(c)
# print(c.len)
# print(c.operands[0][1])

def code_output(address,text,display_address):
    if display_address==1:
        addr=hex(address)+": "
    else:
        addr=""
    print(f'{addr}{text}')
    return

def mark_handled(start_address,size,data_type):
    # Data_type is going to be either C for code, D for data (can either be identified strings or data)
    for loop in range(start_address,(start_address+size)+1):
        identified_areas[loop]=data_type
    return

def percent(number,max_value):
    percentage = round((number / max_value) * 100)
    return

def update_labels(addr,xref):
    labels[addr].add(xref)
    return

#Where is the original code running?
# code_org=0x100
code_org=0xc000
list_address=1
min_length=3
identified_areas={}
labels=defaultdict(set)
# Read the file into RAM.
# Ram is cheap these days, this would never work on a 64K machine
# f = open('a.bin', 'rb')
f = open('RODOS219.ROM', 'rb')
try:
    bin = f.read()

finally:
    f.close()

print("Pass 0: Prep")
# indentified_areas={}
loc=0
while (loc<len(bin)+10):
    identified_areas[code_org+loc]="" #For unknown
    loc=loc+1

print("Pass 1: Identify Data areas ",end="")
#Scan code for things like "LD HL,0x1234"
decode_buffer=bytearray(6)
data_locations={}
loc=0
while (loc<len(bin)):
    # The largest op code is 4 bytes - BIT b,(IX+o) - so we'll decode with that
    # How many remaining bytes are left?
    r=len(bin)-loc
    if (r>4):
        # More than 4? use 4!
        codesize=4
    else:
        # otherwise use whats left
        codesize=r
    #Copy the possible opcodes into a buffer for decoding
    for x in range(0,codesize):
        decode_buffer[x]=bin[loc+x]
    #Decode it now
    b=z80.decode(decode_buffer,0)
    # Data location
    data_addr=0
    if b.op.name in ('LD'):
        if b.operands[1][0] is b.operands[1][0].IMM:
            data_addr=b.operands[1][1]
            # print("!")
        elif b.operands[0][0] is b.operands[1][0].ADDR_DEREF:
            data_addr=b.operands[0][1]
            # print("#")
        if (data_addr>code_org and data_addr<code_org+len(bin)):
            #The reference is somewhere inside our program
            data_locations[data_addr]="Found"
            mark_handled(code_org+data_addr,1,"D")
        update_labels(data_addr,loc+code_org)
    loc=loc+b.len
    # print(".",end="")

print("")
# print(data_locations)

print("Pass 2: Identify Strings ")
# def extract_strings_with_locations(file_path, min_length=3):
# Define a regular expression pattern to match printable ASCII characters
pattern = re.compile(b'[ -~]{%d,}' % min_length)
# Open the binary file in read mode
# with open(file_path, 'rb') as file:
# Read the entire file content
binary_data = bin #file.read()

strings_with_locations = []
str_locations={}
str_sizes={}

# Use finditer to get match objects which include the positions
for match in pattern.finditer(binary_data):
    # Get the byte position of the matched string
    start_position = match.start()
    end_position = match.end()

    # Decode the matched bytes to a string
    matched_string = match.group().decode('ascii')
    found_string='\"'+matched_string+'\"'
    # # Now we have a string, check and process how the string is terminated
    # terminator=binary_data[end_position]
    # if terminator==0:
    #     # C style strings
    #     found_string='\"'+matched_string+'\", '+str(terminator)
    #     end_position=end_position
    # elif terminator-0x80>31 and terminator-0x80<127:
    #     # Amstrad style strings (character+0x80)
    #     found_string='\"'+matched_string+'\", \"'+chr(terminator-0x80)+"\" + 0x80"
    #     end_position=end_position


    # Append the string and its position to the result list
    strings_with_locations.append((found_string, start_position, end_position))

# return strings_with_locations
# Print the extracted strings and their locations
for s, start, end in strings_with_locations:
    # print(f"String: '{s}' found at position {hex(start)}-{hex(end)}")
    # pattern = re.compile(r'[A-Za-z].*[A-Za-z]')
    pattern = re.compile(r'[A-Za-z]{3,}')
    match = bool(pattern.search(s))
    # print("...",match)
    if match:
        # print(s)
        str_locations[start]=s
        str_sizes[start]=(end-start)
        mark_handled(code_org+start,(end-start),"D")


# print("Pass 2.2: Scan known data locations ",end="")
# #Lets look at data locations to data locations+255
# loc=0
# for data_area in data_locations:
#     # print(".")
#     strloc=data_addr
#     strfound=0
#     # tmploc=loc
#     foundstring=""
#     search=0
#     str_bytes=[]
#     while ((strfound==0) or (strloc<len(bin))):
#         # print("strfound=",strfound)
#         if (bin[strloc]>31 and bin[strloc]<127):
#             # This is probably something ASCII, so add it to the list
#             # print(hex(strloc),":",bin[strloc])
#             # print(chr(bin[strloc]),end="")
#             str_bytes.append(bin[strloc])
#         elif ((bin[strloc]==0) or ((bin[strloc]>127) and ((bin[strloc]-0x80)>31 and (bin[strloc]-0x80)<127))):
#             # We've hit the potential end of string (ie C-style null terminated, Amstrad-style string+0x80, or just no longer ASCII )
#             # print("0")
#             if str_locations[data_area]!=None:
#                 print(".",end="")
#                 strfound=1
#                 foundstring='"'
#                 for loop in str_bytes:
#                     # print(loop)
#                     foundstring=foundstring+chr(loop)
#                 foundstring=foundstring+'"'
#                 if (bin[strloc]==0):
#                     foundstring=foundstring+", 0"
#                 elif (bin[strloc]>0x79):
#                     foundstring=foundstring+", \""+chr(bin[strloc]-0x80)+"\" + 0x80"
#
#                 # print("Storing:",hex(loc+1),foundstring)
#                 str_locations[loc+1]=foundstring
#                 str_sizes[loc+1]=(strloc-loc)
#                 mark_handled(loc+1,len(foundstring))
#                 loc=strloc
#                 str_bytes=[]
#                 foundstring=""
#         else:
#             # print("Skip at",strloc)
#             loc=strloc
#             str_bytes=[]
#             foundstring=""
#
#         # strloc=strloc+1
#         #strfound=1
#         loc=strloc
#     print("")
#
# print(str_locations)

print("Pass 3: Build call/jump table ",end="")
decode_buffer=bytearray(6)
jump_locations={}
loc=0
incode=0
while (loc<len(bin)):
    # The largest op code is 4 bytes - BIT b,(IX+o) - so we'll decode with that
    # How many remaining bytes are left?
    r=len(bin)-loc
    if (r>4):
        # More than 4? use 4!
        codesize=4
    else:
        # otherwise use whats left
        codesize=r
    #Copy the possible opcodes into a buffer for decoding
    for x in range(0,codesize):
        decode_buffer[x]=bin[loc+x]
    #Decode it now
    b=z80.decode(decode_buffer,0)
    # Print the instruction
    if str_locations.get(loc)!=None:
        loc=loc+str_sizes.get(loc)
    elif b.op.name in ('JR', 'CALL', 'JP', 'DJNZ'):
        if b.op.name in ('JR', 'DJNZ'):
            # Handle relative jumps correctly.
            if b.operands[0][0] is b.operands[0][0].ADDR:
                jump_locations[code_org+loc+b.operands[0][1]]=hex(code_org+loc+b.operands[0][1])
                mark_handled(code_org+loc+b.operands[0][1],1,"C")
                update_labels(code_org+loc+b.operands[0][1],loc)
            elif b.operands[1][0] is b.operands[1][0].ADDR:
                jump_locations[code_org+loc+b.operands[1][1]]=hex(code_org+loc+b.operands[1][1])
                mark_handled(code_org+loc+b.operands[1][1],1,"C")
                update_labels(code_org+loc+b.operands[1][1],loc)
            elif b.operands[0][0] is b.operands[0][0].REG_DEREF:
                #This is jp (hl) or somethng
                # print("We had a JP (HL)")
                nothing=1 #just because
            elif b.op is b.op.RET:
                mark_handled(loc,1,"C")

            else:
                print("Error: Unhandled operator!!")
                print(b)
                exit
            #code_output(loc+code_org,tmp,list_address)
            # jump_dest=code_org+loc+b.operands[0][1]
            # temp=b.operands[0][1]+0
            # print(temp,temp.is_integer)
            # jump_locations[loc]=code_org+loc+b.operands[0][1]
            # q=1
        else:
            # print(b)
            #Handle conditionals properly. (Direct calls eg CALL &bb19 is [0][1] but call nz,&bb19 is [1][1])
            if b.operands[0][0] is b.operands[0][0].ADDR:
                # jump_locations[lb.operands[0][1]]=hex(code_org+b.operands[0][1])
                mark_handled(b.operands[0][1],1,"C")
                update_labels(b.operands[0][1],loc+code_org)
            elif b.operands[0][0] is b.operands[0][0].REG_DEREF:
                #This is jp (hl) or somethng
                # print("We had a CALL (HL) or something")
                nothing=1 #just because
            elif b.operands[1][0] is b.operands[1][0].ADDR:
                mark_handled(b.operands[1][1],1,"C")
                update_labels(b.operands[1][1],loc+code_org)
                jump_locations[code_org+b.operands[1][1]]=hex(code_org+b.operands[1][1])
            else:
                print("Error: Unhandled operator!!")
                print(b)
                exit
            # print(b)
    #Finally, move the program counter to the next instruction
    loc=loc+b.len
    # print(".",end="")
    # print(jump_locations)
    # for code_areas in jump_locations:
    #     mark_handled(code_areas,1,"C")

print("")
# print(jump_locations)

print("Part ??: Tagging all the areas")
#Go though and tag areas where
loc=0
last="C" #Assume we've got code to start
while (loc<len(bin)):
    # Go through the identified area and assume that if the last byte was code, the next would be code, unless it changed to data
    # at which point it will be data until its changed again.
    if identified_areas[code_org+loc]=="":
        identified_areas[code_org+loc]=last
    elif identified_areas[code_org+loc]!=last:
        last=identified_areas[code_org+loc]
    # print(hex(loc),last)
    loc=loc+1


print("Part ??: Code:\n\n")
code_snapshot = bytearray(8)
loc=0
# print(str_sizes)
# print(str_locations)
while (loc<len(bin)):
    if loc+code_org in labels:
        print(f'L_{loc+code_org:X} ;XREF=',end="")
        # print(loc,labels[loc])
        for tmp in labels[loc+code_org]:
            # print(tmp)
            print(f'0x{tmp:X} ',end="")
        print("")



    # print("loc=",loc)
    # The largest op code is 4 bytes - BIT b,(IX+o) - so we'll decode with that
    # How many remaining bytes are left?
    r=len(bin)-loc
    if (r>4):
        # More than 4? use 4!
        codesize=4
    else:
        # otherwise use whats left
        codesize=r
    # print(loc,str_locations.get(loc))
    if identified_areas[code_org+loc]=="D" and str_locations.get(loc)!=None:
        # print("*")
        code_output(loc+code_org,"DEFB "+str_locations.get(loc),list_address)
        loc=loc+str_sizes.get(loc)
    elif identified_areas[code_org+loc]=="D":
        tmp=bin[loc]
        if tmp>31 and tmp<127:
            out_tmp='"'+chr(tmp)+'"'
        elif (tmp-0x80)>31 and (tmp-0x80)<127:
            out_tmp='"'+chr(tmp-0x80)+'" + 0x80'
        else:
            out_tmp=str(hex(tmp))
        code_output(loc+code_org,"DEFB "+out_tmp,list_address)
        loc=loc+1
    if identified_areas[code_org+loc]=="C":
        #Copy the possible opcodes into a buffer for decoding
        for x in range(0,codesize):
            code_snapshot[x]=bin[loc+x]
        #Decode it now
        b=z80.decode(code_snapshot,0)
        # Print the instruction
        if (b.op is b.op.JR):
            # Handle relative jumps correctly.
            if b.operands[0][0] is b.operands[0][0].ADDR:
                tmp="JR "+hex(code_org+loc+b.operands[0][1])
                # jump_locations[code_org+loc+b.operands[0][1]]=hex(code_org+loc+b.operands[0][1])
            elif b.operands[1][0] is b.operands[1][0].ADDR:
                tmp="JR "+hex(code_org+loc+b.operands[1][1])
                # jump_locations[code_org+loc+b.operands[1][1]]=hex(code_org+loc+b.operands[1][1])
            # tmp="JR "+hex(code_org+loc+b.operands[0][1])
            code_output(loc+code_org,tmp,list_address)
        else:
            code_output(loc+code_org,z80.disasm(b),list_address)
        #Finally, move the program counter to the next instruction
        loc=loc+b.len
    # if identified_areas[loc]=="U":
    #     temp="db "+str(bin[loc])
    #     code_output(loc+code_org,temp,list_address)
    #
    #     loc=loc+1


# print(loc)
