# io_file

`io_file` is a very slightly modified version of [io_file.py](https://github.com/RoderickChan/pwncli/blob/main/pwncli/utils/io_file.py#L220) from the `pwncli` library.

# API

### `#!python IO_FILE_plus_struct(null: int = 0)`
the `IO_FILE_plus_struct` from [pwn-cli](https://github.com/RoderickChan/pwncli/blob/main/pwncli/utils/io_file.py#L220), with some of my own personal additions.

#### `#!python def house_of_apple3(self, stdout_addr: int, lock_addr: int, rip: int, rcx=0)`
payload generator for the house of apple3. this payload is smaller than the house of apple2 as it doesn't need to change `vtable`, but slightly more annoying to gain RCE because `*$rdi == NULL` *must* be true.  
since you can control `rcx`, you can get around this with some JOP as described [here](https://niftic.ca/posts/fsop/#__libio_codecvt_in146).

### `#!python hoa2(libc: ELF, file: str = "stdout") -> bytes`
shorthand to generate a house of apple2 payload against the file stream `file` using the libc `libc`. `libc.address` should be correctly set.
```python
>>> from dog import *
>>> libc = ELF("./libc.so.6")
>>> p = process("./fake_vulnerable_process")
>>> libc.address = 0x739b7958b000 # assumed libc leak
>>> payload = hoa2(libc)
>>> arbitrary_write(libc.sym['_IO_2_1_stdout_'], payload) # assumed arbitrary write primitive
>>> p.interactive() # shell!
```
