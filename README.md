# z80-smart-disassembler

This is a Z80 disassembler that will try and be smarter about identifying strings data and labels

This was inspired by Sourcer from V Communications (see https://corexor.wordpress.com/2015/12/09/sourcer-and-windows-source/ for more details) which I've used. I liked the simplicity and the "just get it done" attitude of that.

I wanted something similar for Z80 code and this project aims to do this.

# Usage

```
z80-disassembler.py - v0.75 - A Smart Z80 reverse assembler
Visit https://github.com/cormacj/z80-smart-disassembler for updates and to report issues

usage: z80-disassembler.py [-h] [-q] [-o OUTFILE] [-t TEMPLATEFILE] [-s STRINGTERMINATOR] [-a {pyradev,z80asm,maxam,z88}] [--style {lst,asm}] [-l LOADADDRESS] [-e ENDADDRESS]
                           [--xref {off,on}] [--stayincode] [--labeltype {2,1}] [-c {2,1,0}] [--explain {2,1,0}]
                           filename

A Smart Z80 reverse assembler

options:
  -h, --help            show this help message and exit
  -q                    Quiet mode - don't display progress bars.

Required arguments:
  filename              A Z80 binary file.

Recommended arguments, but optional:
  -o OUTFILE            Output file. If omitted, then disassembly will go to the screen.
  -l LOADADDRESS, --load LOADADDRESS
                        Specify where in RAM the code loads
  -e ENDADDRESS, --end ENDADDRESS
                        Specify an address to stop disassembling. See README.md for more details.

Formatting options:
  -t TEMPLATEFILE       Use a template file. This helps decode strings and allows for fine tuning disassembly. See README.md for more details
  -s STRINGTERMINATOR   string terminator value - defaults are [0, 13, 141] and printable characters+0x80. You can supply a number, or a single character. You can repeat this as many times as needed.
  -a {pyradev,z80asm,maxam,z88}, --assembler {pyradev,z80asm,maxam,z88}
                        Format the code for particular assemblers. The default is z88.
  --style {lst,asm}     asm produces a file that can be assembled. lst is a dump style output. The default is asm style.
  --xref {off,on}       Enable or disable cross references for labels
  --stayincode          Don't try to decode data after a RET/JP
  --labeltype {2,1}     1: Uses short name eg D_A123 or C_A345 2: Uses full names, eg data_A123 or code_A123
  -c {2,1,0}, --comments {2,1,0}
                        0: No comments 1: Address 2: (Default) Address+hex and ascii dump
  --explain {2,1,0}     0: (Default) No code explanations 1: Data references only 2: Everything
```

# Decoding options

`-o OUTFILE`

This writes the disassembly to OUTFILE. If this is omitted, then disassembly will go to the screen.

---

`-l LOADADDRESS`, or `--load LOADADDRESS`

Specify where in RAM the code loads. If a program is written to load at address 0x100 then use `-l 0x100` so that calls and other instructions with addresses will be decoded properly.

---

`--end ENDADDRESS`

Specify an address to stop disassembling. See README.md for more details.

Extracting binary files from a .dsk image means that a 18 byte binary file might be 1024 bytes when it's extracted.

For, example, if you have a 18 byte .COM file then the --end value for this would --end 0x118 because the usual load address is 0x100.

For example:
`./z80-disassembler.py --load 0x100 --end 0x118 EXAMPLE.COM`

# Formatting options

`-s STRINGTERMINATOR string terminator value`

The defaults are [0, 13, 0x8d] and any printable characters+0x80.

Repeat this as many times as needed, eg `-s 76 -s 0x81 -s ";"`

You can supply a number, or a single character, eg `-s 0` or `-s "Q"`

---

`-a {pyradev,z80asm,maxam,z88}`

This applies particular formats the code for particular assemblers. The default is z88.

Pyradev requires hex addresses in the format `12cdH`

Maxam uses hex addresses in the format `&12cd`

Both z80asm and z88 are equivalent. The hex number style is `0x12cd`

---

`--style {lst,asm}`
The default is asm style.

asm produces a file that can be assembled:
```
C_0108:                        ;          XREF: 0x11C
LD A,(IX+0)
```
lst is a dump style output:
```
                            C_0108:                        ; XREF: 0x11C
0x108:   dd 7e 00  ".~."        LD A,(IX+0)                ;
```
---

`--xref {off,on}`
This enables or disable cross references for labels. This adds a XREF comment to labels with the addresses that calls this label.

---

`--stayincode`
Don't try to decode data after a RET/JP. Sometimes the disassember will assume that data after a RET or a JP instruction is data, but it's actually code. This forces the disassembler to continue to treat the next bytes as code, unless it's overridden by a template instruction.

---

`--labeltype {1,2}`
This changes the format of generated labels. The default method is short labels.

1: Uses short names eg D_A123 or C_A345

2: Uses full names, eg data_A123 or code_A123

---

`-c {0,1,2}, --comments {0,1,2}`

This changes how generated comments are displayed.

0: No comments
```
LD A,(IX+0)
CP 0x1f
```

1: Address
```
LD A,(IX+0)                ;0x108:
CP 0x1f                    ;0x10b:
```

2: (Default) Address+hex and ascii dump

This is most useful because it displays an ASCII dump of the instructions, so it's easier to tell if a string accidentally was decoded as code.
```
LD A,(IX+0)                ;0x108:   dd 7e 00  ".~."
CP 0x1f                    ;0x10b:   fe 1f  ".."
```

---

`--explain {0,1,2}`

0: (Default) No code explanations
```
LD A,0x2e                  ;0x11f:   3e 2e  ">."
CALL 0xbb5a                ;0x121:   cd 5a bb  ".Z."
```

1: Data references only
```
LD A,0x2e                  ;0x11f:   3e 2e  ">." Load A with 0x2e
CALL 0xbb5a                ;0x121:   cd 5a bb  ".Z."
```

2: Everything
```
LD A,0x2e                  ;0x11f:   3e 2e  ">." Load A with 0x2e
CALL 0xbb5a                ;0x121:   cd 5a bb  ".Z." The current PC value plus three is pushed onto the stack, then PC is loaded with 0xbb5a.
```

# Templates

A template file is a standard text file. The format for the file is as follows:

* Comments start with ";"
* Template lines are formatted as:
    `start address, end address, data type, label`

  data types can be one of these:<br>
    b = byte<br>
    w = word<br>
    s = string<br>
    c = code<br>
    p = pointer<br>

  You can refer to a pointer by enclosing the address in (). When the disassembler sees this, it looks at the word at the pointer location and uses that value instead.

  For example, in Amstrad ROMs 0xc004 is a pointer to the command names table. If a ROM has a value of `0xc123` at location `0xc004`, a template line should look like this:

  `0xc006,(0xc004),c,JUMP_TABLE`

  This is then treated in the disassember as mark locations `0xc006` to `0xc123` as code with the label for this area being `JUMP_TABLE`


# Helper Scripts

* generate_string_locations.sh **(linux only)**

**Description:**
The disassembler will try to automatically identify strings in the code, but it does sometimes fail because it decoded a string as a JP or LD instruction, or treated code as a string. This helper script generally identifies strings more successfully and produces output that can be added as a template file while disassembling.

**Usage:** `./generate_string_locations.sh <filename> <memory load location>`

**Example:** `./generate_string_locations.sh CPMFILE.COM 0x100 >cpmfile_template.txt`


  This script will use the templating function of the disassembler to mark string areas in advance. Once these are marked, the disassembler will ignore those memory locations, assuming that someone knows better than it does.

  This generator can create some false positives, so I recommend reviewing the generated template and commenting out (or removing) anything that doesn't look like a string.

  The output is in this format:

  ```
  ;----
  ;db "Out of memory."
  0x16a,0x178,s,S_16a
  ```
  In this example, the `;----` is a seperator comment for readibility.

  Next you have what it will potentially generate, in this case `;db "Out of memory."`

  Next is the template line, using the format `start address, end address,s for string,label` so the disassembler marks everything between `0x16a` and `0x178` as a string and labels this area as `S_16a`

# Example usage

```
$ ./z80-disassembler.py RODOS219.ROM -l 0xc000 --style lst --xref on -o rodos-listing.lst

./z80-disassembler.py v0.75 - A Smart Z80 reverse assembler

Writing code to  rodos-listing.lst

Loading code: |██████████████████████████████████████████████████| 100.0% Complete

Pass 1: Identify addressable areas
    Progress: |██████████████████████████████████████████████████| 100.0% Complete
Pass 2: Search for strings
    Progress: |██████████████████████████████████████████████████| 100.0% Complete
Pass 3: Build code structure
    Progress: |██████████████████████████████████████████████████| 100.0% Complete
Pass 4: Validate labels
    Progress: |██████████████████████████████████████████████████| 100.0% Complete
Pass 5: Produce final listing
    Progress: |██████████████████████████████████████████████████| 100.0% Complete

rodos-listing.lst  created!

Lines of code: 10181
Code Labels: 735
Data Labels: 54
```
# Example Results

I wrote a simple "hello world" file and compiled it on an Amstrad.

```
org &100

bdos equ &0005 ; BDOS entry point

start:  ld c,9 ; BDOS function output string
  ld de,msg ; address of msg
  call bdos
  ret

msg: db 'Hello, world!$'

end
```

I then copied the HELLO.COM file back to my PC.

First I ran the generate_string_locations script using `./generate_string_locations.sh HELLO.COM 0x100`

The .COM file on the Amstrad 18 bytes long, but when copied off the .dsk image, it was 1024 bytes long. The generate strings also added a lot of extra details that aren't needed, so I only used the first line.

I also ensured the the disassembler treated the rest as code by enforcing in the template.

My template file is:
```
0x100,0x108,c,Hello
;----
;db "Hello, world!"
0x109,0x117,s,S_109
;----
```

Now I disassembled HELLO.COM using `./z80-disassembler.py -l 0x100 -e 0x118 -t h.txt -a maxam hello2.asm` and this was the result:

```
org &100
;--------------------------------------
Hello:                         ;
    LD C,9                     ;&100:   0e 09  ".."
    LD DE,S_109                ;&102:   11 09 01  "..."       - References: "Hello, world!$"
    CALL &5                    ;&105:   cd 05 00  "..."
    RET                        ;&108:   c9  "."
;--------------------------------------
S_109:                         ;
    DEFB "Hello, world!$", &00  ;&109:                       &109 to &11a
```
# Known Issues

* Generated code causes z80asm to crash. This appears to be a z80asm bug relating to LD A,(IX). Most assemblers treat it at LD A,(IX+0) but that crashes z80asm. Changing this to LD A,(IX+0) fixes that.
* The disassembler will generate references to labels that don't exist
* String detection fails oddly towards the end of a ROM and maybe elsewhere, so use the `generate_string_locations.sh` helper script to make a template if this happens.

# ToDo

[ ] - Error handling, everywhere

[ ] - Complete template implimentation (b,w handling)

# Dependencies

I use code from https://github.com/lwerdna/z80dis as the disassembler engine.

This is included in this release.
