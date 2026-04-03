from __future__ import annotations

from typing import Iterator, Tuple, Union

def protect_ptr(address, next) -> int:
    return (address >> 12) ^ next
    
    
def reveal_ptr(addr) -> int:
    _res = addr
    for _ in range(3):
        _res = (_res >> 12) ^ addr
    return _res

# gpt slop fake tcache
class Tcache:
    """Represents a tcache_perthread_struct and renders to bytes.

    Parameters
    - pointer_size: 8 for 64-bit, 4 for 32-bit
    - endian: 'little' (default) or 'big'
    - max_bins: number of bins (default 64)
    """
    def __init__(self, pointer_size: int = 8, endian: str = "little", max_bins: int = 64) -> None:
        if pointer_size not in (4, 8):
            raise ValueError("pointer_size must be 4 or 8")
        if endian not in ("little", "big"):
            raise ValueError("endian must be 'little' or 'big'")
        if max_bins <= 0:
            raise ValueError("max_bins must be positive")

        self.pointer_size: int = pointer_size
        self.endian: str = endian
        self.max_bins: int = max_bins

        # counts: uint16_t per bin; entries: pointer-sized head per bin
        self._counts: list[int] = [0] * self.max_bins
        self._entries: list[int] = [0] * self.max_bins

    # --- Index helpers ---
    @staticmethod
    def _is_size_key(key: int) -> bool:
        return key >= 0x20 and (key % 0x10) == 0

    def _size_to_index(self, size: int) -> int:
        idx = (size - 0x20) // 0x10
        if idx < 0 or idx >= self.max_bins:
            raise KeyError(f"size 0x{size:x} outside supported tcache bins")
        return idx

    def _key_to_index(self, key: int) -> int:
        if not isinstance(key, int):
            raise KeyError("key must be an int (size like 0x30, or bin index 0..63)")
        if self._is_size_key(key):
            return self._size_to_index(key)
        if 0 <= key < self.max_bins:
            return key
        raise KeyError("invalid key: use a size (>=0x20, multiple of 0x10) or bin index (0..63)")

    # --- Mapping protocol ---
    def __setitem__(self, key: int, value: Union[int, None, Tuple[int, int]]) -> None:
        idx = self._key_to_index(key)
        if value is None:
            self._entries[idx] = 0
            self._counts[idx] = 0
            return

        if isinstance(value, tuple):
            if len(value) != 2:
                raise TypeError("tuple assignment must be (pointer, count)")
            ptr, count = value
            if not isinstance(ptr, int) or not isinstance(count, int):
                raise TypeError("(pointer, count) must both be ints")
            if not (0 <= count <= 0xFFFF):
                raise ValueError("count must fit in uint16_t (0..65535)")
            self._entries[idx] = ptr & ((1 << (8 * self.pointer_size)) - 1)
            self._counts[idx] = count
            return

        if isinstance(value, int):
            self._entries[idx] = value & ((1 << (8 * self.pointer_size)) - 1)
            self._counts[idx] = 1
            return

        raise TypeError("value must be int, None, or (int pointer, int count)")

    def __getitem__(self, key: int) -> Tuple[int, int]:
        idx = self._key_to_index(key)
        return self._entries[idx], self._counts[idx]

    # --- Bytes rendering ---
    def __bytes__(self) -> bytes:
        # counts first (uint16_t * max_bins), then entries (pointer * max_bins)
        endian = self.endian
        counts_bytes = b"".join((c & 0xFFFF).to_bytes(2, endian, signed=False) for c in self._counts)
        ptr_mask = (1 << (8 * self.pointer_size)) - 1
        entries_bytes = b"".join((e & ptr_mask).to_bytes(self.pointer_size, endian, signed=False) for e in self._entries)
        return counts_bytes + entries_bytes

    # --- Convenience ---
    def clear(self) -> None:
        for i in range(self.max_bins):
            self._counts[i] = 0
            self._entries[i] = 0

    def __repr__(self) -> str:
        items: Iterator[str] = (
            f"[{i:02d}/0x{0x20 + 0x10*i:02x}]=ptr=0x{self._entries[i]:x},cnt={self._counts[i]}"
            for i in range(self.max_bins)
            if self._counts[i] or self._entries[i]
        )
        summary = ", ".join(items) or "<empty>"
        return f"Tcache(pointer_size={self.pointer_size}, endian='{self.endian}', bins={self.max_bins}): {summary}"


__all__ = ["protect_ptr", "reveal_ptr", "Tcache"]
