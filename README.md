# z80-smart-disassembler

# Summary
This is a Z80 disassembler/reverse engineering tool that takes the effort out of disassembling code. It will try to identify and properly label strings and data areas.

If you need more fine tuning, this includes the ability to use a template file to provide overides, or add special labels.

I wrote this to reverse engineer Amstrad CPC roms and the included templates are aimed towards that but it will handle any Z80 code you throw at it, even if its not an Amstrad file.

This was inspired by Sourcer from V Communications (see https://corexor.wordpress.com/2015/12/09/sourcer-and-windows-source/ for more details) which I've used. I liked the simplicity and the "just get it done" attitude of that.

I wanted something similar for Z80 code and this project aims to do this.

<!-- TOC -->

- [z80-smart-disassembler](#z80-smart-disassembler)
- [Usage](#usage)
- [Decoding options](#decoding-options)
- [Formatting options](#formatting-options)
- [Templates](#templates)
- [Helper Scripts](#helper-scripts)
- [Example usage](#example-usage)
- [Example Results](#example-results)
- [Known Issues](#known-issues)
- [ToDo](#todo)
- [Dependencies](#dependencies)

<!-- /TOC -->

# Usage

```

z80-disassembler.py - v0.80 - A Smart Z80 reverse assembler
Visit https://github.com/cormacj/z80-smart-disassembler for updates and to report issues

usage: z80-disassembler.py [-h] [-q] [-o OUTFILE] [-t TEMPLATEFILE] [--labels LABELS] [-s STRINGTERMINATOR] [-a {maxam,z88,z80asm,pyradev}] [--style {lst,asm}] [-l LOADADDRESS]
                           [-e ENDADDRESS] [--xref {off,on}] [--stayincode] [--labeltype {1,2}] [-c {0,1,2}] [--explain {0,1,2}]
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
  --labels LABELSFILE   Use a label file. This file provides user-defined labels that may be external to the program. See README.md for more details
  -s STRINGTERMINATOR   string terminator value - defaults are [0, 13, 141] and printable characters+0x80. You can supply a number, or a single character. You can repeat this as many times
                        as needed.
  -a {maxam,z88,z80asm,pyradev}, --assembler {maxam,z88,z80asm,pyradev}
                        Format the code for particular assemblers. The default is z88.
  --style {lst,asm}     asm produces a file that can be assembled. lst is a dump style output. The default is asm style.
  --xref {off,on}       Enable or disable cross references for labels
  --stayincode          Don't try to decode data after a RET/JP
  --labeltype {1,2}     1: Uses short label names eg D_A123 or C_A345 2: Uses descriptive label names, eg data_A123 or code_A123
  -c {0,1,2}, --comments {0,1,2}
                        0: No comments 1: Address 2: (Default) Address+hex and ascii dump
  --explain {0,1,2}     0: (Default) No code explanations 1: Data references only 2: Everything

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

z88 and z80asm use number style `0x12cd`

z80asm implies that labeltype is 2 which uses longer labelnames (eg `code_12CD`). This is because z80asm has issues with shorter variable names.

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
# Label file

This is used by adding `--labels LABELSFILE` to the command line.

A label file allows external calls, such as BIOS entry points, to be defined and used in disassembled code. I've included `amstrad-labels.txt` in this repository as an example and for convenience.

You can also add custom code labels in this file, such as those for RSX jump points.

This is defined as follows:

```
;A list of Amstrad CPC BIOS calls.
;Recorded here for use with the disassembler

KL_ROM_SELECT      equ 0xb90f
KL_CURR_SELECTION  equ 0xb912
KL_PROBE_ROM       equ 0xb915
KL_ROM_DESELECT    equ 0xb918
```

Comments start with ';'

Blank lines are ignored.

Labels should be structed as `Labelname equ 0x0000`


# Templates

Template files are a way to specify ways to tell the disassembler how to handle certain areas of memory. This functionality is still under development with some functions still be implimented.



A template file is a standard text file. The format for the file is as follows:

* Comments start with ";"
* Template lines are formatted as:
    `start address, end address, data type, label`

  data types can be one of these:<br>
    b = byte <br>
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

This command disassembles the RODOS219.ROM file and stores the output in rodos.asm

```
$ ./z80-disassembler.py RODOS219.ROM -t amstrad_rom_template.txt -o rodos.asm -l 0xc000 -a z80asm  --labels amstrad-labels.txt

z80-disassembler.py - v0.80 - A Smart Z80 reverse assembler
Visit https://github.com/cormacj/z80-smart-disassembler for updates and to report issues

Writing code to  rodos.asm

Disassembling RODOS219.ROM: 16384 bytes

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
rodos.asm  created!

Lines of code: 9238
Code Labels: 734
Data Labels: 57
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
* The disassembler can generate references to labels that don't exist
* Some labels are generated, but never called.
* String detection fails oddly towards the end of a ROM and maybe elsewhere, so use the `generate_string_locations.sh` helper script to make a template if this happens.
* Some code that gets moved around using LDIR won't get properly decoded, because the disassembler doesn't know if its data or code. The recommended workaround is to tell the disassembler what to do using the template options, eg `0xc300,0xc309,c,RELOCATE_BUILTIN_MSG`. This that cause the disassembler treats the data between 0xc300 and 0xc309 as code and assigns the label `RELOCATE_BUILTIN_MSG`

# ToDo

[ ] - Error handling, everywhere

[ ] - Complete template implimentation (b,w handling)

# Dependencies

I use code from https://github.com/lwerdna/z80dis as the disassembler engine.

This is included in this release.
