# orc

ORC is a module to work with C structs in every way you've ever dreamt of.  
Let's say you have glibc with debug symbols attached. Here are just a few things you can do:
```python
from dog import *
libc = ELF('./libc.so.6')

# craft structs
b = libc.orc.craft("tcache_perthread_struct")
b.counts[10] = 1; b.entries[10] = 0x123456789
bytes(b) # correct layout!

# parse leaked data into structs
b2 = libc.orc.parse('tcache_perthread_struct', bytes(b))
assert b2.entries[10] == b.entries[10]

# get addresses of struct fields
arena = libc.sym_obj['main_arena'].bins[3].fd # 

# cast arbitrary addresses as structs
ptr = libc.orc.cast('malloc_chunk', 0x55555555b000)
ptr.fd # 0x55555555b010
```
and MUCH more. Let's get into it!

for this library to work, you will need debuginfo. if you're not sure how to get that, or would like some suggestions, see `TODO`.md


# API

## `#!python ORC(path: str, bits: int | None = None)`
the main ORC module

## `#!python ORCHeader(header_path: str, include_dirs: list | None = None, bits: int | None = None)`

TODO

## `#!python ORCInline(source: str, bits: int | None = None)`

TODO
