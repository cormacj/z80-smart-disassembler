# z80-smart-disassembler

This is a Z80 disassembler that will try and be smarter about identifying strings data and labels

This was inspired by Sourcer from V Communications (see https://corexor.wordpress.com/2015/12/09/sourcer-and-windows-source/ for more details) which I've used. I liked the simplicity and the "just get it done" attitude of that.

I wanted something similar for Z80 code and this project aims to do this.

# Usage

usage: z80-disassembler.py [-h] [-v] [-o OUTFILE] [-t TEMPLATEFILE] [--style {asm,lst}] [-l LOADADDRESS] [--xref {off,on}] [--labeltype {2,1}] filename
```
A Smart Z80 reverse assembler

positional arguments:
  filename

options:
  -h, --help            show this help message and exit
  -v                    verbose mode
  -o OUTFILE            output file
  -t TEMPLATEFILE       template file
  --style {asm,lst}     asm produces a file that can be assembled. lst is a dump style output
  -l LOADADDRESS, --load LOADADDRESS
                        Specify where in RAM the code loads
  --xref {off,on}       Enable or disable cross references for labels
  --labeltype {2,1}     1: Uses short name eg D_A123 or C_A345 2: Uses full names, eg data_A123 or code_A123
```
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

# Dependencies

I use code from https://github.com/lwerdna/z80dis as the disassembler engine.
