# dogtools
things i always wished were in pwntools  
```python
from dog import *
# start cooking
```

## extelf
very useful extension to pwntools `ELF`.  
by parsing debuginfo, work with structs in python:
```python
from dog import *
libc = ExtendedELF('./libc.so.6')
target_fd = libc.sym_obj['main_arena'].bins[3].fd # correct address of this field

heap_chunk_addr = 0x55555555b000
chunk_struct = libc.cast('malloc_chunk', heap_chunk_addr)
target_fd = chunk_struct.fd # correct address of this field

# craft fake structs
fake_tps = libc.craft('tcache_perthread_struct')
fake_tps.counts[15] = 1
fake_tps.entries[15] = 0x123456
bytes(fake_tps) # payload bytes

# parse leaked structs
parsed = libc.parse('tcache_perthread_struct', bytes(fake_tps))
parsed.entries[15] # 0x123456

# or do all the above from a .h file!
structs = CHeader("./my_header.h")
# or even inline it!
structs = CInline("""
struct foo {
    int a;
    int b;
} foo;
""")
```
and much more! a bunch of basic types are already included in `extelf.C`, `.C32`, and `.C64`, so
you can quickly play around with it yourself:
```python
from doglib.extelf import C64
j = C64.craft("int[3][3]")
j.fill(0x18) # now all indices are 0x18
j[1][1] # 0x18
j[1][1] += 9
j[1][1] # 0x21
j[2] = [3,4,5]
bytes(j) # b'\x18\x00\x00\x00\x18\x00\x00\x00.....'
```
little more at [docs/extelf.md](docs/extelf.md)


## dumpelf
attempt blind elf dumping over remote  
if you have an infinite arbitrary read vuln:  
```python
from doglib.dumpelf import DumpELF

# return 1+ bytes at 'addr'
def leak(addr):
    pass

d = DumpELF(leak, leaked_ptr)
d.dump("./target_dump.elf")  # write reconstructed binary. itll run! maybe.
libc = d.libc # (attempt) getting libc, slightly better than dynelf
```
*warning*: very very hacky barely works on x64/x86

## misc
random stuff. worth reading yourself.

## pow
fastest pow solver for kctf/redpwn to my knowledge
```python
from dog import solve_pow
solution = solve_pow("s.AAATiA==.c5JzfKLC099PHb3WLBaz1g==")
```
auto-selects the fastest backend installed, rust (70x) <-> gmpy2 (8x) <-> python (1x)

## muney
[house of muney](https://maxwelldulin.com/BlogPost/House-of-Muney-Heap-Exploitation) payload generator
```python
from pwn import *
from doglib.muney import house_of_muney
libc = ELF("./libc.so.6")
payload = house_of_muney(libc,{
    'puts': libc.sym['system'],
    'free': libc.sym['puts']
})
print(payload) # b'\x00\x00\x00\x00....'
```

## shellcode
random shellcodez  
- `minshell`: tiny shell as shellcode, useful for seccomp jails

## cli
installed under the 'dog' binary
### `dog solve`
drop-in replacement for pwninit's template generator
### `dog fetch`
given libc/ld, search debian/ubuntu repos for the other, optionally unstrip with `--dbg`  
this checks a few spots pwninit doesn't  

## log
various stuff to assist in logging/debugging
```python
from dog import *
libc = ELF("./libc.so.6")
libc.address = 0x110370

logx(libc.address, libc.sym['system'])
# [*] libc.address=0x110370        (keeps the variable name!)
# [*] libc.sym['system']=0x16c830
```

## asm
basic assembler/disassembler stuff because pwntools is ungodly slow  
access like `casm.x64` / or `kdis.amd64`

## io_file
advanced file stream generator, useful for quick FSOP  
stolen from [pwncli](https://github.com/RoderickChan/pwncli/raw/refs/heads/main/pwncli/utils/io_file.py) with a few personal additions at the bottom

## doglib_rs
optional rust extensions to make certain doglib features MUCH faster. not installed by default, needs maturin. install with `cd ./src/doglib_rs; pip install .`
### dwarf_parser
uses [gimli](https://github.com/gimli-rs/gimli) to parse debug info 20x faster  
note that this only matters on the first parse, afterwards we cache it  
### pow_solver
fastest solver for [redpwn/kctf pow](https://github.com/redpwn/pow) i am aware of  
2nd place is [this](https://anemato.de/blog/kctf-vdf) which is ~10% slower  

## heap
stuff relevant for heap exploitation. currently:
- ptr mangling / demangling
- fake tcache struct crafter

## fmt
work-in-progress library for advanced format string attacks (ex. stackless arb writes)

## ezrop
not very useful module for rop chains

