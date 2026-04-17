# log

the `log` module contains some functions for even better logging.


### `#!python logx(*args, **kwargs) -> None`
`logx` is a 'smart logger' that will print all of the variables passed to it *along with the variable name itself*:
```python
>>> from dog import *
>>> libc.address = 0x123235000
>>> logx(libc.address,libc.sym['system'])
[*] libc.address=0x123235000
[*] libc.sym['system']=0x12328d750
>>>
```

### `#!python log_printf(leaks: list | tuple, start_offset: int = 1) -> None`
`log_printf` is used for analyzing format string leaks:
```python
>>> from dog import *
>>> p = process("./fake_fmtstr_challenge.bin") # assume this has a format string bug
>>> p.sendline("%p!.!" * 50)
>>> output = p.recvS().split("!.!")
>>> log_printf(output) # you'll get something like this
    [1] 0xdeadbeef
    [2] 0x0
    [3] 0xabcdef
    ...
```
