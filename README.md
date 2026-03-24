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
given libc/ld, search debin/ubuntu repos for the other, optionally unstrip with `--dbg`  
this checks a few spots pwninit doesn't  


## asm
basic assembler/disassembler stuff because pwntools is ungodly slow  
access like `casm.x64` / or `kdis.amd64`

## io_file
advanced file stream generator, useful for quick FSOP  
stolen from [pwncli](https://github.com/RoderickChan/pwncli/raw/refs/heads/main/pwncli/utils/io_file.py) with a few personal additions at the bottom

## heap
stuff relevant for heap exploitation. currently:
- ptr mangling / demangling
- fake tcache struct crafter

## dwarf_parser_rs
optional rust-based parser to make ExtELF faster  
the parser has to look at ALL debug info objects and determine which ones are relevant to us,
which on big libcs can be 1m+ objects. we can cache this to make it near-instant after the first parse,
but that first parse can still take some time (~20s). this uses [gimli](github.com/gimli-rs/gimli) to make that first parse less than a second. not installed by default, needs maturin

## ezrop
not very useful module for rop chains

## fmt
failed attempt at advanced format string utilities. might revisit this in the future










