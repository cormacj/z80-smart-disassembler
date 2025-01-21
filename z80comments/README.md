# z80 code commenting library

# Usage

```
from z80comments import explain

op="call z,0x1234"
print(explain.code(op))
```
Returns:
```
Conditional call using the z flag. If test conditions are met, the current PC value plus three is pushed onto the stack, then is loaded with 0x1234
```
