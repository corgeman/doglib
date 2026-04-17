# heap

# API

### `#!python protect_ptr(address: int, next: int) -> int`
safe-link a pointer `next` that's to be stored at `address`.

### `#!python reveal_ptr(addr: int) -> int`
''decrypt'' a pointer `addr` encrypted with safe linking.

### `#!python Tcache(pointer_size: int = 8, endian: str = "little", max_bins: int = 64)`
TODO
