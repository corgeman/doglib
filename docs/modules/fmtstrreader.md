# format string arbitrary read

TODO TODO


this library contains the ability to make format string payloads for reading arbitrary data  
at its core, it works as follows:
```python
from dog import *
exe = ELF("./fmtstr_vuln.elf")
p = process([exe.path])

# input shows up at index 6, cannot use '\n'
x = FmtStrReader(6,badchars=b'\n')
# i want to read 12 bytes at exe.address
pl = x.payload(exe.address,12)
p.sendline(pl)

leak = p.recv()
x.parse(leak) # b'\x7fELF\x02\x01\x01\x00\x00\x00\x00\x00'
```
but it's worth knowing how it works under the hood.


## the problem
first, i think it's worth explaining the challenges this library has to solve:
- reading *consistent* data. remember that `%s` ends on a null-byte, so when we read an address, we have no idea how much data we're reading
- parsing output. if given a dump of data, how can `.parse()` identify what section of it is the leak?
- bad characters. if our payload can't contain b`\n`, how can we read an address that ends in b`\n`?
- parsing bad-character-leaks. if you've thought of a solution to fix the above, how does `.parse()` still know how to parse it correctly?

## the solution
so here's how the library works. when you create a `.payload()` object to read some object, you get a `FmtStrLeak` object (which subclasses `bytes`).  
that payload looks something like this:
```python
b'FMTLKSTARTAAAAD%23$sFMTLKDLM%24$sFMTLKDLM%25$sFMTLKDLM%26$sFMTLKEND\x00V4\x12\x00W4\x12\x00X4\x12\x00Y4\x12\x00'
```
let's break it down.  
first, the payload is wrapped with `FMTLKSTART` / `FMTLKEND` to delimit where our leak starts and ends.
right after `FMTLKSTART` we place a 5-byte unique identifier (here `AAAAD`) to determine which `.payload()` call this came from. more on why this is necessary later.
then, between a delimiter string (here `FMTLKDLM`) we place multiple `%N$s` payloads that each try to read `addr+1`, `addr+2`, `addr+3`... all the way up to `count`.
when we send this payload, we can split it on `FMTLKDLM`, and get back what each `%N$s` payload leaked!

### bad charcters
one problem is if `addr+N` contains a bad character, we can't read it. we solve this by not putting that address in our payload, and instead try to determine what it contains by looking back at our previous leaks. for instance, if we got two bytes back when we leaked `addr+N-1`, then we know `addr+N` is that second byte. 
but to do that, `.parse()` needs to know we wanted to do that in the first place. that's where that unique identifier i mentioned comes in-- internally, the `FmtStrReader` holds a hashmap of all the payloads it's made, and all the bad characters that showed up in those payloads. so `.parse()` can read that unique idenitifer, grab the payload data from the hashmap, and now it has everything it needs to workwith.

## configuration
here are some useful things you can set on `FmtStrReader`
- `badchars`: previously mentioned, characters your payload can't contain
- `padlen`: like pwntools format string, the amount of bytes prepended to your input (if any)
- `delimiter`, `start_sentinel`, `end_sentinel`: the unique strings that should be used to delimit the payload. you can make these shorter to make the overall payload shorter (at the risk of things breaking, if one of them accidentally shows up in the leaked data)
- `warn`: send warning messages if bad things happen (ex. unable to determine the data at a specific address). defaults to true.

# API

## `#!python FmtStrReader(offset: int, padlen: int = 0, badchars: bytes = b"\n", delimiter: bytes = b"FMTLKDLM", start_sentinel: bytes = b"FMTLKSTART", end_sentinel: bytes = b"FMTLKEND", warn: bool = True)`

TODO

## `#!python single_arb_write(off_1: int, off_2: int, off_3: int, where: int, what: bytes, stack_leak: int) -> Iterator[bytes]`

TODO
