# _hijack

the `_hijack` module extends some common pwntools features (like `tube` or `ELF`) through monkey-patching.


## `ELF` patches

### `ELF.onegadgets(level=100)`
calls the [one_gadget](https://github.com/david942j/one_gadget) tool on the ELF, returns every onegadget at level `level`, taking into account `ELF.address` if set.
```python
>>> from dog import *
>>> libc = ELF("./libc.so.6")
>>> libc.onegadgets()
[283167, 283174, 283258, 840051, 840264, 983972, 983984, 987719, 1009648]
>>> libc.onegadgets(0) # default onegadget output
[283258, 983972, 987719]
>>>
>>> libc.address = 0x1234000
>>> libc.onegadgets(0)
[19370618, 20071332, 20075079]
>>>
```

### `ELF.gadget(asm)`
scans all executable sections for the assembly snippet `asm`, returns offset if found
```python
>>> from dog import *
>>> libc = ELF("./libc.so.6")
>>> libc.gadget('pop rdi; ret')
1111947
```

### `ELF.binsh`
shorthand for `next(self.search(b"/bin/sh\0"))`, just find the binsh string and return its address.

### `ELF.orc`
return the ELF as an instance of `ORC`

### `ELF.sym_obj`
like `ELF.sym`, but return the symbol as a `DWARFAddress` so you can get the address of values within the struct:
```python
>>> from dog import *
>>> libc = ELF("./libc.so.6")
>>> libc.sym['main_arena']
2112192
>>> int(libc.sym_obj['main_arena'].bins[41])
2112632
>>> int(libc.sym_obj['main_arena'].mutex)
2112192
>>> int(libc.sym_obj['main_arena'].next)
2114352
```

### `ELF.resolve_field`
same as `sym_obj`, but you write the field access syntax as a string
```python
>>> from dog import *
>>> libc = ELF("./libc.so.6")
>>> int(libc.resolve_field('main_arena','bins[41]'))
2112632
```

### shorthands

* `ELF.o` -> `ELF.orc`
* `ELF.symo` -> `ELF.sym_obj`

## `tube` patches

### `tube.recvpointer()`
find and return the value of the first `%p`-style integer printed
```python
>>> from dog import *
>>> p = process("./try")
>>> p.recv()
b'blahblahblahfoo\nhello this is more junk\neven more\n new pointer: 0x7a37e70045c0'
>>> p.unrecv(_)
>>> hex(p.recvpointer())
'0x7a37e70045c0'
```

### todo
todo more

### shorthands

*  `tube.sla` -> `tube.sendlineafter`
*  `tube.sl` -> `tube.sendline`
*  `tube.sa` -> `tube.sendafter`
*  `tube.s` -> `tube.send`
*  `tube.ru` -> `tube.readuntil`
*  `tube.rl` -> `tube.readline`
*  `tube.slc` -> `tube.sendlinecolon`
*  `tube.sc` -> `tube.sendaftercolon`
*  `tube.sic` -> `tube.sendintcolon`
*  `tube.rla` -> `tube.readlineafter`
*  `tube.rld` -> `tube.readlinecolon`
*  `tube.rud` -> `tube.readuntildrop`
*  `tube.ri` -> `tube.readint`
*  `tube.rli` -> `tube.readlineint`
*  `tube.rp` -> `tube.recvpointer`