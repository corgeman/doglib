# asm

while pwntools `asm()` is quite good, it calls out to an [external compiler](https://github.com/Gallopsled/pwntools/blob/dev/pwnlib/asm.py#L806) which means a simple `asm('pop rdi; ret')` takes upwards of 3 seconds to finish.  
this module offers a much faster assembler/disassembler by making use of the [keystone](https://github.com/keystone-engine/keystone)/[capstone](https://www.capstone-engine.org/) frameworks.  


# API

### `#!python kasm(code: str) -> bytes`
assembler. call directly to assemble assuming `context.arch`, index/getattr to specify a specific architecture
```python
>>> kasm("mov rdi, 133; syscall; ret")
b'H\xc7\xc7\x85\x00\x00\x00\x0f\x05\xc3'
>>> kasm.aarch64("mov x0, #133; svc #0; ret")
b'\xa0\x10\x80\xd2\x01\x00\x00\xd4\xc0\x03_\xd6'
>>>
```

### `#!python cdis(code: bytes, addr: int = 0) -> str`
disassembler. call directly to disassemble assuming `context.arch`, index/getattr to specify a specific architecture
```python
>>> from dog import *
>>> cdis(b'H\xc7\xc7\x85\x00\x00\x00\x0f\x05\xc3')
'mov rdi, 0x85;\nsyscall ;\nret ;'
>>> cdis.aarch64(b'\xa0\x10\x80\xd2\x01\x00\x00\xd4\xc0\x03_\xd6')
'mov x0, #0x85;\nsvc #0;\nret ;'
>>>
```
