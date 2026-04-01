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
writeup using this on a real ctf challenge at [dumpelf_writeup.md](docs/dumpelf_writeup.md)
*warning*: very very hacky barely works on x64/x86. use as a last resort!

## misc
random stuff. worth reading yourself.

## pow
semi-universal CTF proof-of-work solver with speed in mind:
```python
from dog import do_pow
p = remote("whatever.pwn.local",11037)
do_pow(p) # auto-detects POW format, solves it, and sends the answer
# ... continue exploiting ...
```
currently the fastest solver of kctf/redpwn-based POWs, and close to hashcat for hash-based ones

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

## _hijack
internal function to add some methods on existing pwntools features. probably worth skimming it's short
```python
p = remote("localhost",1024)
exe = ELF('./foobar')
# shorthands (sample)
p.sl # sendline
p.rl # readline
p.sla # sendlineafter
# new features 
p.readlineint() # int(p.readline(),0)
exe.gadget['pop rdi; ret'] # (&gadget_address)
exe.binsh # (&binsh_address)
```

## asm
basic assembler/disassembler stuff because pwntools is ungodly slow  
access like `kasm.amd64` / or `cdis.arm`

## io_file
advanced file stream generator, useful for quick FSOP  
stolen from [pwncli](https://github.com/RoderickChan/pwncli/raw/refs/heads/main/pwncli/utils/io_file.py) with a few personal additions at the bottom

## doglib_rs
optional rust extensions to make certain doglib features MUCH faster. not installed by default.
### dwarf_parser
uses [gimli](https://github.com/gimli-rs/gimli) to parse debug info 20x faster  
note that this only matters on the first parse, afterwards we cache it  
### pow_solver
two very fast proof-of-work solvers in rust
- sloth: fastest solver for [redpwn/kctf pow](https://github.com/redpwn/pow) i am aware of. 2nd place is [this](https://anemato.de/blog/kctf-vdf) which is ~10% slower
- hash: fast bruteforcer for "find hash with N leading zeros"-based POWs, in my tests it's basically equivalent to hashcat. works on WSL too. requires some additional setup, see [gpu_pow_setup.md](docs/gpu_pow_setup.md). includes cpu fallback (although MUCH slower)

## heap
stuff relevant for heap exploitation. currently:
- ptr mangling / demangling
- fake tcache struct crafter

## fmt
work-in-progress library for advanced format string attacks (ex. stackless arb writes)

## ezrop
not very useful module for rop chains

