# dogtools
things i personally wished were in pwntools but aren't
code is a mix of GPT slop and my own stuff

## misc
random stuff. worth reading yourself.

## io_file
advanced file stream generator, useful for quick FSOP
stolen from [pwncli](https://github.com/RoderickChan/pwncli/raw/refs/heads/main/pwncli/utils/io_file.py) with a few personal additions at the bottom

## heap
stuff relevant for heap exploitation. currently:
- ptr mangling / demangling
- fake tcache struct crafter

## fmt
failed attempt at additional format string utilities

## ezrop
stuff to make ropping faster
only notable function right now is `quickrop` which sets up a system('/bin/sh') chain

## extelf
very useful claude-slopped extension to pwntools `ELF`. basically do Cc things in python
- get the address of specific fields in a symbol
- craft your own fake `struct`s to use in payloads
- parse raw bytes into a struct
- determine offsets of fields in structs
```python
libc = ExtendedELF('./libc.so.6')
target_fd = libc.sym_obj['main_arena'].bins[3].fd # correct address of this field

heap_chunk_addr = 0x55555555b000
chunk_struct = libc.cast('malloc_chunk', heap_chunk_addr)
target_fd = chunk_struct.fd # correct address of this field

fake_tps = libc.craft('struct tcache_perthread_struct')
fake_tps.counts[15] = 1
fake_tps.entries[15] = 0x123456
bytes(fake_tps) # payload bytes
```
and many more! a bunch of basic types are already included in `extelf.C`, `.C32`, and `.C64`, so
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
*warning*: this module is nearly 2000+ lines of AI code that i have not thoroughly reviewed.
even on opus 4.6 i am still finding myself fixing simple issues. 
but i am trying my best. there are over 129 test cases.


## asm
basic assembler/disassembler stuff because pwntools is ungodly slow
`asm_x64`, `asm_x86`, `dis_x64`, etc etc