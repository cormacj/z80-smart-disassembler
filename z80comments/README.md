# z80 code commenting library

# Usage

This library produces explanations about Z80 opcodes.

```
from z80comments import explain

op="call z,0x1234"
commentlevel=2
print(explain.code(op,commentlevel))
```
Returns:
```
Conditional call using the z flag. If test conditions are met, the current PC value plus three is pushed onto the stack, then is loaded with 0x1234
```

`commentlevel` is optional. If it's omitted all opcodes are commented.
`commentlevel=0` - this disables comments. It's used to reduce source size and noise.
`commentlevel=1` - this only comments about LD instructions.
`commentlevel=2` - this comments about everything.
