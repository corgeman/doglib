# packer

TODO

this module contains a handful of functions to screw around with bytes, mostly shorthands.  
some of these functions are very close to eachother, only depending on bit width (similar to pwntools `p16`, `p32`, `p64`...)  
these will be described in the documentation like `p{16,32,64}`, and inside the documentation `N` refers to the specific bit width the function deals with.  

### `#!python b(n: int | str) -> bytes`
shorthand for `str(n).encode()`

### `#!python ua(n: bytes) -> int`
unpack an arbitrary-length bytestring `b` into an integer. useful for things that cannot be cleanly unpacked.
```python
>>> libc.address = 0x74ba7a10e000
>>> hex(libc.address)
'0x74ba7a10e000'
>>> p64(libc.address).rstrip(b'\0')
b'\x00\xe0\x10z\xbat'
>>> hex(ua(_))
'0x74ba7a10e000'
```

### `#!python pa(n: int) -> bytes`
reverse of `ua`, convert an arbitrary-length intenger `n` into a bytestring
```python
>>> libc.address = 0x74ba7a10e000
>>> pa(libc.address)
b'\x00\xe0\x10z\xbat'
>>> p64(libc.address)
b'\x00\xe0\x10z\xbat\x00\x00'
>>>
```

### `#!python m{8,12,16,32,64}(n: int) -> int`
shorthand to mask `n` with `2**N-1`. for instance:
```python
def m16(n: int) -> int: return n & 0xffff
```

### `#!python s{16,32,64}(n: int) -> tuple[int, int]`
shorthand to split `n` into two halves:
```python
>>> libc.address = 0x74ba7a10e000
>>> a, b = s64(libc.address)
>>> hex(a), hex(b)
('0x74ba', '0x7a10e000')
>>> a, b = s32(libc.address)
>>> hex(a), hex(b)
('0x7a10', '0xe000')
>>>
```

### `#!python swap{16,32,64}(v: int) -> int`
swap the endianness of `v` and return it.

### `#!python s2u{32,64}(v: int) -> int`
cast `v`, assumed to be a signed integer, as an `N`-bit unsigned integer and return it.

### `#!python u2s{32,64}(v: int) -> int`
cast `v`, assumed to be an unsigned integer, as an `N`-bit signed integer and return it.


### `#!python sp{8,16,32,64}(n: int) -> int`
shorthand for `p{N}(n, signed=True)`. for instance, `sp64` is
```python
def sp64(n: int) -> bytes: return p64(n, signed=True)
```

### `#!python su{8,16,32,64}(n: int) -> int`
shorthand for `u{N}(n, signed=True)`. for instance, `su64` is
```python
def su64(b: bytes) -> int: return u64(b, signed=True)
```

# API

## 

TODO

## 

TODO

## 

TODO

TODO


TODO

## `#!python f2b(f: float | list[float] | tuple[float, ...]) -> bytes`

TODO

## `#!python b2f(b: bytes) -> float | list[float]`

TODO

## `#!python d2b(d: float | list[float] | tuple[float, ...]) -> bytes`

TODO

## `#!python b2d(b: bytes) -> float | list[float]`

TODO

## `#!python f2i(f: float) -> int`

TODO

## `#!python i2f(i: int) -> float`

TODO

## `#!python d2i(d: float) -> int`

TODO

## `#!python i2d(i: int) -> float`

TODO
