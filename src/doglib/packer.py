# packing module that's also not named something that would collide with pwntools
import struct
from pwnlib.context import context as _context
from pwnlib.util.packing import p8, p16, p32, p64, u8, u16, u32, u64

def b(n: int|str) -> bytes:
    return str(n).encode()

def ua(b: bytes) -> int:
    """unpack any: bytes to int, using context endianness"""
    return int.from_bytes(b, byteorder=_context.endian)

def pa(n: int) -> bytes:
    """pack any: int to bytes (auto length), using context endianness"""
    length = (n.bit_length() + 7) // 8 or 1
    return n.to_bytes(length, byteorder=_context.endian)


# --- bitmasks ---

def m8(n: int)  -> int: return n & 0xff
def m12(n: int) -> int: return n & 0xfff
def m16(n: int) -> int: return n & 0xffff
def m32(n: int) -> int: return n & 0xffffffff
def m64(n: int) -> int: return n & 0xffffffffffffffff

# --- splitting ---

def s16(n: int) -> tuple[int, int]: n &= 0xffff;             return (n >> 8,  n & 0xff)
def s32(n: int) -> tuple[int, int]: n &= 0xffffffff;         return (n >> 16, n & 0xffff)
def s64(n: int) -> tuple[int, int]: n &= 0xffffffffffffffff; return (n >> 32, n & 0xffffffff)

# --- float/double <-> bytes ---

def f2b(f: float | list[float] | tuple[float, ...]) -> bytes:
    """float (or list of floats) to bytes (single precision)"""
    if isinstance(f, (list, tuple)):
        return struct.pack(f'<{len(f)}f', *f)
    return struct.pack('<f', f)

def b2f(b: bytes) -> float | list[float]:
    """bytes to float(s) (single precision). returns single float if 4 bytes, else list"""
    n = len(b) // 4
    result = struct.unpack(f'<{n}f', b[:n*4])
    return result[0] if n == 1 else list(result)

def d2b(d: float | list[float] | tuple[float, ...]) -> bytes:
    """double (or list of doubles) to bytes"""
    if isinstance(d, (list, tuple)):
        return struct.pack(f'<{len(d)}d', *d)
    return struct.pack('<d', d)

def b2d(b: bytes) -> float | list[float]:
    """bytes to double(s). returns single double if 8 bytes, else list"""
    n = len(b) // 8
    result = struct.unpack(f'<{n}d', b[:n*8])
    return result[0] if n == 1 else list(result)

# --- float/double <-> int (reinterpret cast) ---

def f2i(f: float) -> int:
    """float bits as uint32"""
    return struct.unpack('<I', struct.pack('<f', f))[0]

def i2f(i: int) -> float:
    """uint32 bits as float"""
    return struct.unpack('<f', struct.pack('<I', i & 0xffffffff))[0]

def d2i(d: float) -> int:
    """double bits as uint64"""
    return struct.unpack('<Q', struct.pack('<d', d))[0]

def i2d(i: int) -> float:
    """uint64 bits as double"""
    return struct.unpack('<d', struct.pack('<Q', i & 0xffffffffffffffff))[0]

# --- endian swaps ---

def swap16(v: int) -> int:
    return struct.unpack('>H', struct.pack('<H', v & 0xffff))[0]

def swap32(v: int) -> int:
    return struct.unpack('>I', struct.pack('<I', v & 0xffffffff))[0]

def swap64(v: int) -> int:
    return struct.unpack('>Q', struct.pack('<Q', v & 0xffffffffffffffff))[0]

# --- signed <-> unsigned ---

def s2u32(v: int) -> int:
    """signed 32-bit int to unsigned"""
    return v & 0xffffffff

def u2s32(v: int) -> int:
    """unsigned 32-bit int to signed"""
    v &= 0xffffffff
    return v - 0x100000000 if v >= 0x80000000 else v

def s2u64(v: int) -> int:
    """signed 64-bit int to unsigned"""
    return v & 0xffffffffffffffff

def u2s64(v: int) -> int:
    """unsigned 64-bit int to signed"""
    v &= 0xffffffffffffffff
    return v - 0x10000000000000000 if v >= 0x8000000000000000 else v

# --- signed pack/unpack shorthands ---

def sp8(n: int)  -> bytes: return p8(n,  signed=True)
def sp16(n: int) -> bytes: return p16(n, signed=True)
def sp32(n: int) -> bytes: return p32(n, signed=True)
def sp64(n: int) -> bytes: return p64(n, signed=True)

def su8(b: bytes)  -> int: return u8(b,  signed=True)
def su16(b: bytes) -> int: return u16(b, signed=True)
def su32(b: bytes) -> int: return u32(b, signed=True)
def su64(b: bytes) -> int: return u64(b, signed=True)

__all__ = [
    "b", "ua", "pa",
    "m8", "m12", "m16", "m32", "m64",
    "s16", "s32", "s64",
    "f2b", "b2f", "d2b", "b2d",
    "f2i", "i2f", "d2i", "i2d",
    "swap16", "swap32", "swap64",
    "s2u32", "u2s32", "s2u64", "u2s64",
    "sp8", "sp16", "sp32", "sp64",
    "su8", "su16", "su32", "su64",
]
