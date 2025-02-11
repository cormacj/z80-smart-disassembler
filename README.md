# z80-smart-disassembler

This is a Z80 disassembler that will try and be smarter about identifying strings data and labels

This was inspired by Sourcer from V Communications (see https://corexor.wordpress.com/2015/12/09/sourcer-and-windows-source/ for more details) which I've used. I liked the simplicity and the "just get it done" attitude of that.

I wanted something similar for Z80 code and this project aims to do this.

# Usage
```
usage: z80-disassembler.py [-h] [-v] [-o OUTFILE] [-t TEMPLATEFILE] [--style {asm,lst}] [-l LOADADDRESS] [--xref {off,on}] [--labeltype {2,1}] filename

A Smart Z80 reverse assembler

positional arguments:
  filename

  options:
    -h, --help            show this help message and exit
    -v                    verbose mode
    -q                    quiet mode
    -o OUTFILE            output file
    -t TEMPLATEFILE       template file
    -s STRINGTERMINATOR   string terminator value - defaults are [0, 13, 141] and printable characters+0x80
    --style {lst,asm}     asm produces a file that can be assembled. lst is a dump style output
    -l LOADADDRESS, --load LOADADDRESS
                          Specify where in RAM the code loads
    --xref {off,on}       Enable or disable cross references for labels
    --labeltype {2,1}     1: Uses short name eg D_A123 or C_A345 2: Uses full names, eg data_A123 or code_A123
    -c {0,2,1}, --commentlevel {0,2,1}
                          0: No code explanations 1: Data references only 2: Everything
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

* generate_string_locations.sh

  Usage: `./generate_string_locations.sh` <filename> <memory load location>

  Example: `./generate_string_locations.sh CPMFILE.COM 0x100 >cpmfile_template.txt`

  Description:
  The disassembler will try to identify strings in the code, it does sometimes cause false generation of jump or data locations because it decoded a string as a JP or LD instruction.

  This script will use the templating function of the disassembler to mark string areas in advance. Once these are marked, the disassembler will ignore those memory locations, assuming that someone knows better than it does.

  This generator can create some false positives, so I'd advise looking over the generated template and commenting out (or removing) anything that doesn't look like a string.

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

# Known Issues

* Generated code causes z80asm to crash.
* String detection fails oddly towards the end of a ROM and maybe elsewhere, so use the `generate_string_locations.sh` helper script to make a template if this happens.

# ToDo

[ ] - Error handling, everywhere

# Dependencies

I use code from https://github.com/lwerdna/z80dis as the disassembler engine.

This is included in this release.
