#!/usr/bin/env python3

from z80dis import z80
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

#Where is the original code running?
code_org=0x100
list_address=1

# Read the file into RAM.
# Ram is cheap these days, this would never work on a 64K machine
f = open('a.bin', 'rb')
try:
    bin = f.read()

finally:
    f.close()


print("Pass 1: Identify Strings ",end="")
str_bytes=bytearray()
str_locations={}
str_sizes={}
loc=0
min_string_len=2
while (loc<len(bin)):
    # print(".")
    strloc=loc
    strfound=0
    # tmploc=loc
    foundstring=""
    str_bytes=[]
    while ((strfound==0) or (strloc<len(bin))):
        # print("strfound=",strfound)
        if (bin[strloc]>31 and bin[strloc]<127):
            # This is probably something ASCII, so add it to the list
            # print(hex(strloc),":",bin[strloc])
            # print(chr(bin[strloc]),end="")
            str_bytes.append(bin[strloc])
        elif ((bin[strloc]==0) or ((bin[strloc]>127) and ((bin[strloc]-0x80)>31 and (bin[strloc]-0x80)<127))):
            # We've hit the potential end of string (ie C-style null terminated, Amstrad-style string+0x80, or just no longer ASCII )
            # print("0")
            if (min_string_len<len(str_bytes)):
                print(".",end="")
                strfound=1
                foundstring='"'
                for loop in str_bytes:
                    # print(loop)
                    foundstring=foundstring+chr(loop)
                foundstring=foundstring+'"'
                if (bin[strloc]==0):
                    foundstring=foundstring+", 0"
                elif (bin[strloc]>0x79):
                    foundstring=foundstring+", \""+chr(bin[strloc]-0x80)+"\" + 0x80"

                # print("Storing:",hex(loc+1),foundstring)
                str_locations[loc+1]=foundstring
                str_sizes[loc+1]=(strloc-loc)
                loc=strloc
                str_bytes=[]
                foundstring=""
            else:
                #String was too short
                str_bytes=[]
                foundstring=""
                
        else:
            # print("Skip at",strloc)
            loc=strloc
            str_bytes=[]
            foundstring=""

        strloc=strloc+1
        #strfound=1
    loc=strloc
    print("")



code_snapshot = bytearray(8)
loc=0
# print(str_sizes)
# print(str_locations)
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
    if str_locations.get(loc)!=None:
        code_output(loc+code_org,"DEFB "+str_locations.get(loc),list_address)
        loc=loc+str_sizes.get(loc)

    else:
        #Copy the possible opcodes into a buffer for decoding
        for x in range(0,codesize):
            code_snapshot[x]=bin[loc+x]
        #Decode it now
        b=z80.decode(code_snapshot,0)
        # Print the instruction
        code_output(loc+code_org,z80.disasm(b),list_address)
        #Finally, move the program counter to the next instruction
        loc=loc+b.len


print(loc)
