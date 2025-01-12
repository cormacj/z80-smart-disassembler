# z80-smart-disassembler

**WARNING! THIS IS PRE-ALPHA CODE**

This is a Z80 disassembler that will try and be smarter about identifying strings data and labels

This was inspired by Sourcer from V Communications (see https://corexor.wordpress.com/2015/12/09/sourcer-and-windows-source/ for more details) which I've used. I liked the simplicity and the "just get it done" attitude of that.

I wanted something similar for Z80 code and this project aims to do this.

# Current status

* Working, but now with 75% less jank.

# Known Issues

* Generated code causes z80asm to crash.

* Some code areas are still being handled as data and breaking recompilation.

# ToDo

[X] Impliment command line parsing

[X] Add auto commenting (mostly done)

[ ] Built a templating function, eg so Amstrad ROMs can be properly decoded.

[ ] Improve Ssring and data detection methods

# Dependencies

I use code from https://github.com/lwerdna/z80dis as the disassembler engine.
