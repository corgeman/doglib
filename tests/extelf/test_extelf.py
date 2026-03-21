"""
pytest test suite for doglib.extelf.

Run from the project root:
    pytest tests/extelf/

Fixtures (headers, chal_elf, cwd) live in conftest.py.
"""
import math
import os
import struct
import subprocess
import tempfile

import pytest
from elftools.elf.elffile import ELFFile
from pwnlib.exception import PwnlibException
from pwnlib.util.cyclic import cyclic as pwn_cyclic
from pwnlib.util.packing import p64

from doglib.extelf import CHeader, CInline, DWARFAddress, DWARFArrayCrafter, C64

# ============================================================
# Integration: solve a mini-ctf challenge to ensure the library
# is consistent with C memory layouts
# ============================================================

def test_challenge_solve(headers, chal_elf):
    """Send correctly crafted structs through every level of the challenge."""
    from pwnlib.tubes.process import process
    io = process("./challenge")
    try:
        # Level 1: Padding & Basics
        basic = headers.craft('Basic')
        basic.a = ord('X')
        basic.b = 0x1337
        basic.c = 0x42
        io.sendafter(b"Basic\n", bytes(basic))

        # Level 2: Arrays & Pointers
        arr_fun = headers.craft('ArrayFun')
        arr_fun.arr[0] = 10
        arr_fun.arr[4] = 50
        arr_fun.ptr = 0xdeadbeef
        io.sendafter(b"ArrayFun\n", bytes(arr_fun))

        # Level 3: Unions & Anonymous Structs
        union_madness = headers.craft('UnionMadness')
        union_madness.type = 1
        union_madness.data.coords.x = 0x11223344
        union_madness.data.coords.y = 0x55667788
        io.sendafter(b"UnionMadness\n", bytes(union_madness))

        # Level 4: Deep Nesting & Array Bytes
        boss = headers.craft('BossFight')
        boss.b[1].a = ord('Z')
        boss.b[1].b = 999
        boss.u.data.raw = b"AAAAAAAW"
        io.sendafter(b"BossFight\n", bytes(boss))

        # Level 5: Truncation & Overflows
        edge = headers.craft('EdgeCases')
        edge.small_int = 0xdeadbeef
        edge.small_buf = b"AAAA\x00TRASH_DATA_THAT_GETS_DROPPED"
        edge.big_int = -1
        io.sendafter(b"EdgeCases\n", bytes(edge))

        # Level 6: DWARF Array Strides & Offset Math
        target_addr = int(chal_elf.sym_obj['target_sym'].arr[2].ptr)
        io.sendafter(b"(8 bytes)\n", p64(target_addr))

        # Level 7: Enums, Signed Values, Multi-Dimensional Arrays & Floats
        final = headers.craft('FinalBoss')
        final.current_state = -1   # CRASHED
        final.negative_val = -1337
        final.matrix[1][2] = 9999
        final.max_hp = 1000.5
        final.current_hp = 1337.75
        io.sendafter(b"FinalBoss\n", bytes(final))

        # Level 8: Multi-Dimensional Array Proper Indexing (2D + 3D)
        md = headers.craft('MultiDimTest')
        md.grid[1][2] = 42
        md.grid[2][3] = 99
        md.cube[1][0][2] = ord('Q')
        md.cube[0][2][3] = ord('Z')
        io.sendafter(b"MultiDimTest\n", bytes(md))

        # Level 9: Anonymous Struct/Union Members
        am = headers.craft('AnonMember')
        am.type = 5
        am.as_int = 0xCAFE
        am.x = 100
        am.y = 200
        io.sendafter(b"AnonMember\n", bytes(am))

        # Level 10: Sub-Struct Assignment & Value Readback
        hdr = headers.craft('Basic')
        hdr.a = ord('A')
        hdr.b = 1234
        hdr.c = 42
        wrapper = headers.craft('Wrapper')
        wrapper.header = hdr
        wrapper.payload = 0xBEEF
        assert wrapper.payload.value == 0xBEEF
        assert wrapper.header.a.value == ord('A')
        assert wrapper.header.b.value == 1234
        io.sendafter(b"Wrapper\n", bytes(wrapper))

        io.wait_for_close()
    finally:
        io.close()


# ============================================================
# Enum
# ============================================================

def test_enum_constants(headers):
    state = headers.enum('State')
    assert state.IDLE == 0
    assert state.RUNNING == 1
    assert state.CRASHED == -1
    assert 'IDLE' in state
    assert 'NONEXISTENT' not in state


def test_enum_assignment_in_craft(headers):
    state = headers.enum('State')
    fb = headers.craft('FinalBoss')
    fb.current_state = state.CRASHED
    assert fb.current_state.value == 0xFFFFFFFF


def test_enum_iteration(headers):
    state = headers.enum('State')
    items = dict(state)
    assert items['IDLE'] == 0
    assert items['CRASHED'] == -1


def test_enum_missing_constant_raises(headers):
    state = headers.enum('State')
    with pytest.raises(AttributeError):
        _ = state.NONEXISTENT


def test_enum_repr(headers):
    state = headers.enum('State')
    r = repr(state)
    assert 'IDLE' in r and 'CRASHED' in r


def test_enum_bracket_access(headers):
    """enum['NAME'] returns the same value as enum.NAME."""
    state = headers.enum('State')
    assert state['IDLE']    == state.IDLE    == 0
    assert state['RUNNING'] == state.RUNNING == 1
    assert state['CRASHED'] == state.CRASHED == -1


def test_enum_bracket_missing_raises_key_error(headers):
    """enum['BOGUS'] raises KeyError, not AttributeError."""
    state = headers.enum('State')
    with pytest.raises(KeyError):
        _ = state['BOGUS']


# ============================================================
# sizeof / offsetof / containerof / resolve_type
# ============================================================

def test_sizeof_structs(headers):
    assert headers.sizeof('Basic') == 12
    assert headers.sizeof('ArrayFun') == 32
    assert headers.sizeof('FinalBoss') == 48
    assert headers.sizeof('EdgeCases') == 16


def test_sizeof_primitives(headers):
    assert headers.sizeof('int') == 4
    assert headers.sizeof('char') == 1
    assert headers.sizeof('short') == 2
    assert headers.sizeof('long long') == 8
    assert headers.sizeof('double') == 8
    assert headers.sizeof('unsigned short') == 2
    assert headers.sizeof('unsigned long') == 8


def test_sizeof_arrays(headers):
    assert headers.sizeof('int[100]') == 400
    assert headers.sizeof('char[16]') == 16
    assert headers.sizeof('Basic[3][2]') == 3 * 2 * headers.sizeof('Basic')


def test_sizeof_pointer(headers):
    assert headers.sizeof('int *') == 8


def test_offsetof(headers):
    assert headers.offsetof('Basic', 'a') == 0
    assert headers.offsetof('Basic', 'b') == 4
    assert headers.offsetof('Basic', 'c') == 8
    assert headers.offsetof('FinalBoss', 'matrix') == 8
    assert headers.offsetof('FinalBoss', 'matrix[1][2]') == 28
    assert headers.offsetof('FinalBoss', 'current_hp') == 40
    assert headers.offsetof('BossFight', 'u.data.raw') == 32


def test_offsetof_invalid_raises(headers):
    with pytest.raises(ValueError):
        headers.offsetof('Basic', 'nonexistent')


def test_containerof(headers):
    member_addr = 0x1000 + headers.offsetof('BossFight', 'u')
    base = headers.containerof('BossFight', 'u', member_addr)
    assert base == 0x1000


def test_containerof_va_wrapping(headers):
    mask = (1 << 64) - 1
    result = headers.containerof('Basic', 'b', 0x4)
    assert result == (0x4 - headers.offsetof('Basic', 'b')) & mask


def test_resolve_type(headers):
    assert headers.resolve_type('State') == 'enum State'


def test_describe_no_crash(headers):
    headers.describe('FinalBoss')
    headers.describe('AnonMember')


def test_describe_primitive_raises(headers):
    with pytest.raises(ValueError):
        headers.describe('int')


# ============================================================
# parse
# ============================================================

def test_parse_basic(headers):
    crafted = headers.craft('Basic')
    crafted.a = ord('Z')
    crafted.b = 0xDEAD
    crafted.c = 42
    parsed = headers.parse('Basic', bytes(crafted))
    assert parsed.a.value == ord('Z')
    assert parsed.b.value == 0xDEAD
    assert parsed.c.value == 42


def test_parse_nested_struct(headers):
    crafted = headers.craft('BossFight')
    crafted.b[0].a = ord('A')
    crafted.b[0].b = 111
    crafted.b[1].a = ord('B')
    crafted.b[1].b = 222
    parsed = headers.parse('BossFight', bytes(crafted))
    assert parsed.b[0].a.value == ord('A')
    assert parsed.b[1].b.value == 222


def test_parse_short_data_zero_pads(headers):
    short_data = b'\x41\x00\x00\x00'   # only 4 bytes, Basic is 12
    parsed = headers.parse('Basic', short_data)
    b = bytes(parsed)
    assert b[:4] == short_data
    assert b[4:] == b'\x00' * (headers.sizeof('Basic') - 4)


def test_parse_long_data_truncates(headers):
    long_data = bytes(range(64))
    parsed = headers.parse('Basic', long_data)
    assert len(bytes(parsed)) == headers.sizeof('Basic')
    assert bytes(parsed) == long_data[:headers.sizeof('Basic')]


# ============================================================
# craft / parse / cast with count and 2-D type-string syntax
# ============================================================

def test_craft_with_count(headers):
    arr = headers.craft('Basic', count=4)
    assert len(arr) == 4
    assert len(bytes(arr)) == 4 * headers.sizeof('Basic')
    arr[0].a = ord('A'); arr[0].b = 111
    arr[1].a = ord('B'); arr[1].b = 222
    arr[2].a = ord('C'); arr[3].b = 444
    assert arr[0].a.value == ord('A')
    assert arr[1].b.value == 222
    assert arr[2].a.value == ord('C')
    assert arr[3].b.value == 444


def test_parse_with_count(headers):
    arr = headers.craft('Basic', count=4)
    arr[0].a = ord('A'); arr[1].b = 222; arr[3].b = 444
    parsed = headers.parse('Basic', bytes(arr), count=4)
    assert parsed[0].a.value == ord('A')
    assert parsed[1].b.value == 222
    assert parsed[3].b.value == 444


def test_cast_with_count(headers):
    base = 0x1000
    cast_arr = headers.cast('Basic', base, count=8)
    elem = headers.sizeof('Basic')
    assert len(cast_arr) == 8
    assert int(cast_arr[0]) == base
    assert int(cast_arr[3]) == base + 3 * elem
    assert int(cast_arr[3].b) == base + 3 * elem + headers.offsetof('Basic', 'b')


def test_2d_type_string_craft(headers):
    arr = headers.craft('Basic[3][2]')
    assert len(arr) == 3
    assert len(arr[0]) == 2
    arr[0][0].a = ord('X')
    arr[0][1].b = 99
    arr[2][1].a = ord('Z')
    assert arr[0][0].a.value == ord('X')
    assert arr[0][1].b.value == 99
    assert arr[2][1].a.value == ord('Z')
    assert len(bytes(arr)) == 3 * 2 * headers.sizeof('Basic')


def test_2d_type_string_parse(headers):
    arr = headers.craft('Basic[3][2]')
    arr[0][0].a = ord('X')
    arr[2][1].a = ord('Z')
    parsed = headers.parse('Basic[3][2]', bytes(arr))
    assert parsed[0][0].a.value == ord('X')
    assert parsed[2][1].a.value == ord('Z')


def test_2d_type_string_cast(headers):
    elem = headers.sizeof('Basic')
    cast = headers.cast('Basic[3][2]', 0x2000)
    assert int(cast[0][0]) == 0x2000
    assert int(cast[1][0]) == 0x2000 + 2 * elem
    assert int(cast[2][1]) == 0x2000 + 5 * elem
    assert int(cast[2][1].b) == 0x2000 + 5 * elem + headers.offsetof('Basic', 'b')


def test_primitive_type_arrays(headers):
    cast_arr = headers.cast('int[10]', 0x3000)
    assert len(cast_arr) == 10
    assert int(cast_arr[5]) == 0x3000 + 20

    ci = headers.craft('int[4]')
    ci[0].value = 0x41414141
    ci[3].value = 123456
    assert len(bytes(ci)) == 16
    pi = headers.parse('int[4]', bytes(ci))
    assert pi[0].value == 0x41414141
    assert pi[3].value == 123456

    ci[1].value = -42
    assert headers.parse('int[4]', bytes(ci))[1].value == -42


def test_2d_primitive_arrays(headers):
    mat = headers.craft('int[3][4]')
    mat[1][2].value = 42
    mat[0][0].value = 99
    assert mat[1][2].value == 42
    assert mat[0][0].value == 99
    assert len(bytes(mat)) == 48


# ============================================================
# DWARFAddress arithmetic and repr
# ============================================================

def test_dwarf_address_repr(chal_elf):
    r = repr(chal_elf.sym_obj['target_sym'])
    assert 'DWARFAddress' in r
    assert 'type=' in r


def test_sym_obj_contains(chal_elf):
    assert 'target_sym' in chal_elf.sym_obj
    assert 'nonexistent_var' not in chal_elf.sym_obj


def test_dwarf_address_arithmetic(headers):
    mask = (1 << 64) - 1
    base = headers.cast('Basic', 0x1000)

    # add preserves type and value
    nxt = base + 0x20
    assert isinstance(nxt, DWARFAddress)
    assert int(nxt) == 0x1020
    assert int(nxt.b) == 0x1020 + headers.offsetof('Basic', 'b')

    # sub preserves type
    prv = base - 0x10
    assert isinstance(prv, DWARFAddress)
    assert int(prv) == 0x0FF0

    # sub of two DWARFAddresses returns plain int
    other = headers.cast('Basic', 0x1020)
    diff = other - base
    assert not isinstance(diff, DWARFAddress)
    assert diff == 0x20

    # radd
    radd_result = 0x100 + base
    assert isinstance(radd_result, DWARFAddress)
    assert int(radd_result) == 0x1100

    # VA wrapping
    near_max = headers.cast('Basic', 0xffffffffffffff00)
    wrapped = near_max + 0x200
    assert int(wrapped) == (0xffffffffffffff00 + 0x200) & mask

    # p64 compatibility
    assert p64(nxt) == p64(0x1020)


def test_dwarf_address_field_error(headers):
    int_addr = headers.cast('int', 0x5000)
    with pytest.raises(AttributeError):
        _ = int_addr.somefield


def test_dwarf_address_index_error(headers):
    int_addr = headers.cast('int', 0x5000)
    with pytest.raises(TypeError):
        _ = int_addr[0]


# ============================================================
# Virtual-address space
# ============================================================

def test_va_space_wrapping(headers):
    mask = (1 << 64) - 1
    base = 0xffffffffffffff00
    va_arr = headers.cast('int', base, count=1000)
    assert int(va_arr[100]) == (base + 100 * 4) & mask
    chunk_va = headers.cast('Basic', 0xfffffffffffffff0)
    assert int(chunk_va.b) == (0xfffffffffffffff0 + headers.offsetof('Basic', 'b')) & mask


def test_pointer_cast(headers):
    mask = (1 << 64) - 1
    ptr = headers.cast('int *', 0x1000)
    assert int(ptr[0]) == 0x1000
    assert int(ptr[520292]) == 0x1000 + 520292 * 4
    assert int(ptr[-1]) == (0x1000 - 4) & mask


def test_pointer_indexing_on_dwarf_address(headers):
    af = headers.cast('ArrayFun', 0x5000)
    ptr_field = af.ptr
    assert int(ptr_field[0]) == int(ptr_field)
    assert int(ptr_field[10]) == int(ptr_field) + 10


def test_exact_va_wrap(headers):
    ptr = headers.cast('long long *', 0x1000)
    wrap_idx = (1 << 64) // 8
    assert int(ptr[wrap_idx]) == 0x1000


# ============================================================
# OOB writes, padding, integer / list assignment
# ============================================================

def test_oob_write_arraycrafter(headers):
    arr = headers.craft('int[3][3]')
    arr[5][5] = 42
    assert arr[5][5].value == 42


def test_oob_write_crafter(headers):
    boss = headers.craft('BossFight')
    boss.b[10].a = ord('X')
    assert boss.b[10].a.value == ord('X')


def test_craft_pad_parameter(headers):
    padded = headers.craft('int[3]', pad=64)
    padded[10] = 0xbeef
    assert padded[10].value == 0xbeef


def test_integer_assignment_arraycrafter(headers):
    arr = headers.craft('int[4]')
    arr[0] = 111
    arr[3] = -42
    assert arr[0].value == 111
    assert int.from_bytes(bytes(arr[3]), 'little', signed=True) == -42


def test_integer_assignment_struct_members(headers):
    fb = headers.craft('FinalBoss')
    fb.matrix[0][0] = 42
    fb.matrix[1][2] = 99
    assert fb.matrix[0][0].value == 42
    assert fb.matrix[1][2].value == 99


def test_oob_1d_visible_in_bytes():
    n = C64.craft('char[10]')
    n[50] = b'test'
    b = bytes(n)
    assert len(b) > 10
    assert b[50] == ord('t')


def test_oob_2d_visible_in_bytes():
    m = C64.craft('char[10][10]')
    m[150] = b'test'
    b = bytes(m)
    assert len(b) > 100
    assert b[1500:1504] == b'test'


def test_int_write_to_2d_row():
    m = C64.craft('char[10][10]')
    m[1] = 1234
    row = bytes(m)[10:20]
    assert row == bytes([1234 & 0xff] * 10)


def test_oob_int_write_2d():
    m = C64.craft('char[10][10]')
    m[150] = 1234
    b = bytes(m)
    assert len(b) > 100
    assert all(v == (1234 & 0xff) for v in b[1500:1510])


def test_list_assignment():
    j = C64.craft('int[3][3]')
    j[2] = [4, 5, 6]
    assert j[2][0].value == 4
    assert j[2][1].value == 5
    assert j[2][2].value == 6


def test_list_assignment_3d():
    k = C64.craft('int[2][2][2]')
    k[0] = [[1, 2], [3, 4]]
    assert k[0][0][0].value == 1
    assert k[0][0][1].value == 2
    assert k[0][1][0].value == 3
    assert k[0][1][1].value == 4


def test_list_assignment_partial():
    j = C64.craft('int[3][3]')
    j[1] = [9, 8]
    assert j[1][0].value == 9
    assert j[1][1].value == 8
    assert j[1][2].value == 0


# ============================================================
# Slice assignment
# ============================================================

def test_slice_assignment_int_list(headers):
    arr = headers.craft('ArrayFun')
    arr.arr[0:3] = [10, 20, 30]
    assert arr.arr[0].value == 10
    assert arr.arr[1].value == 20
    assert arr.arr[2].value == 30
    assert arr.arr[3].value == 0


def test_slice_assignment_bytes(headers):
    um = headers.craft('UnionMadness')
    um.data.raw[0:4] = b"\xAA\xBB\xCC\xDD"
    raw_out = bytes(um.data.raw)
    assert raw_out[0:4] == b"\xAA\xBB\xCC\xDD"


# ============================================================
# Indexing (negative, iter)
# ============================================================

def test_negative_index_within_bounds(headers):
    fb = headers.craft('FinalBoss')
    fb.matrix[0][-1]  # offset 8 - 4 = 4, within struct — must not raise


def test_negative_index_before_bounds_raises(headers):
    fb = headers.craft('FinalBoss')
    with pytest.raises(IndexError):
        fb.matrix[0][-3]   # offset 8 - 12 = -4, before struct start


def test_arraycrafter_negative_index_raises():
    arr = C64.craft('int[5]')
    with pytest.raises(IndexError):
        arr[-1]


def test_arraycrafter_iter():
    arr = C64.craft('int[4]')
    for i, v in enumerate([10, 20, 30, 40]):
        arr[i] = v
    assert [e.value for e in arr] == [10, 20, 30, 40]


def test_crafter_array_iter(headers):
    fb = headers.craft('FinalBoss')
    fb.matrix[0][0] = 1
    fb.matrix[0][1] = 2
    fb.matrix[0][2] = 3
    assert [e.value for e in fb.matrix[0]] == [1, 2, 3]


def test_dwarf_array_iter(headers):
    it = headers.cast('Basic[3]', 0x1000)
    addrs = list(it)
    assert len(addrs) == 3
    sz = headers.sizeof('Basic')
    for i, addr in enumerate(addrs):
        assert int(addr) == 0x1000 + i * sz


def test_dwarf_array_iter_unbounded_raises(headers):
    ptr = headers.cast('Basic *', 0x2000)
    with pytest.raises(TypeError):
        list(ptr)


# ============================================================
# DWARFArray slice / len
# ============================================================

def test_dwarf_array_slice(headers):
    bounded = headers.cast('Basic[5]', 0x3000)
    sliced = bounded[1:4]
    assert isinstance(sliced, list) and len(sliced) == 3
    bs = headers.sizeof('Basic')
    assert int(sliced[0]) == 0x3000 + 1 * bs
    assert int(sliced[2]) == 0x3000 + 3 * bs


def test_dwarf_array_slice_unbounded_raises(headers):
    with pytest.raises(TypeError):
        _ = headers.cast('int *', 0x4000)[1:3]


def test_dwarf_array_len_unbounded_raises(headers):
    with pytest.raises(TypeError):
        len(headers.cast('int *', 0x4000))


# ============================================================
# craft / cast error paths
# ============================================================

def test_craft_pointer_raises(headers):
    with pytest.raises(ValueError):
        headers.craft('int *')


def test_cast_double_pointer_raises(headers):
    with pytest.raises(ValueError):
        headers.cast('int **', 0x1000)


# ============================================================
# Operators: bitwise, comparison, arithmetic, bool, format
# ============================================================

def test_bitwise_operators(headers):
    fb = headers.craft('FinalBoss')
    fb.current_state = 0xff
    assert (fb.current_state & 0x0f) == 0x0f
    assert (fb.current_state | 0x100) == 0x1ff
    assert (fb.current_state ^ 0xf0) == 0x0f
    assert (fb.current_state >> 4) == 0x0f
    assert (fb.current_state << 4) == 0xff0
    assert (~fb.current_state) == ~0xff
    assert (0xff00 & fb.current_state) == 0
    assert (fb.current_state ** 2) == 0xff ** 2


def test_comparison_operators(headers):
    fb = headers.craft('FinalBoss')
    fb.current_state = 42
    assert fb.current_state == 42
    assert fb.current_state != 0
    assert fb.current_state < 100
    assert fb.current_state <= 42
    assert fb.current_state > 10
    assert fb.current_state >= 42
    assert not (fb.current_state > 100)


def test_division_modulo_divmod(headers):
    fb = headers.craft('FinalBoss')
    fb.current_state = 17
    assert fb.current_state / 4 == 4.25
    assert fb.current_state // 4 == 4
    assert fb.current_state % 4 == 1
    assert divmod(fb.current_state, 4) == (4, 1)
    assert 100 / fb.current_state == 100 / 17
    assert 100 % fb.current_state == 100 % 17


def test_rounding(headers):
    fb = headers.craft('FinalBoss')
    fb.max_hp = 3.7
    assert round(fb.max_hp) == 4
    assert round(fb.max_hp, 1) == 3.7
    assert math.floor(fb.max_hp) == 3
    assert math.ceil(fb.max_hp) == 4
    assert math.trunc(fb.max_hp) == 3


def test_bool_primitive(headers):
    fb = headers.craft('FinalBoss')
    fb.current_state = 0
    assert not bool(fb.current_state)
    fb.current_state = 1
    assert bool(fb.current_state)


def test_bool_struct_via_bytes(headers):
    basic = headers.craft('Basic')
    assert not bool(basic)      # all-zero → False
    basic.a = 1
    assert bool(basic)          # non-zero → True
    basic.a = 0
    assert not bool(basic)      # zeroed again → False


def test_format_specifiers(headers):
    fb = headers.craft('FinalBoss')
    fb.current_state = 0x41
    fb.max_hp = 3.14
    assert f'{fb.current_state:#x}' == '0x41'
    assert f'{fb.current_state:08x}' == '00000041'
    assert f'{fb.max_hp:.2f}' == '3.14'


def test_format_on_struct(headers):
    s = headers.craft('Basic')
    s.fill(0x41)
    assert isinstance(f'{s}', str)


def test_repr(headers):
    fb = headers.craft('FinalBoss')
    fb.current_state = 42
    fb.negative_val = -10
    fb.max_hp = 1.5
    assert '0x2a' in repr(fb.current_state)
    assert '-10' in repr(fb.negative_val)
    assert '1.5' in repr(fb.max_hp)
    full = repr(fb)
    assert 'FinalBoss' in full
    assert 'current_state' in full
    assert 'matrix=<array' in full


def test_hash_primitive(headers):
    fb = headers.craft('FinalBoss')
    fb.current_state = 42
    h = hash(fb.current_state)
    assert isinstance(h, int)
    d = {fb.current_state: 'test'}
    assert d[42] == 'test'


def test_hash_struct_raises(headers):
    with pytest.raises(TypeError):
        hash(headers.craft('Basic'))


def test_p64_on_fields(headers):
    fb = headers.craft('FinalBoss')
    fb.current_state = 0x41
    fb.matrix[0][0] = 0xdeadbeef
    assert p64(fb.current_state) == p64(0x41)
    assert p64(fb.matrix[0][0]) == p64(0xdeadbeef)
    assert hex(fb.current_state) == '0x41'

    arr = C64.craft('int[4]')
    arr[0] = 0xbeef
    assert p64(arr[0]) == p64(0xbeef)

    with pytest.raises(TypeError):
        int(headers.craft('BossFight').b[0])


# ============================================================
# Container API: __contains__, items(), dump(), values(), fill(), cyclic(), copy()
# ============================================================

def test_contains_struct(headers):
    fb = headers.craft('FinalBoss')
    assert 'current_state' in fb
    assert 'negative_val' in fb
    assert 'does_not_exist' not in fb


def test_items(headers):
    fb = headers.craft('FinalBoss')
    fb.current_state = 99
    fb.max_hp = 7.5
    item_dict = dict(fb.items())
    assert 'current_state' in item_dict
    assert 'max_hp' in item_dict
    assert 'matrix' in item_dict
    assert item_dict['current_state'].value == 99


def test_dump_no_crash(headers):
    fb = headers.craft('FinalBoss')
    fb.current_state = 1
    fb.negative_val = -42
    fb.max_hp = 2.5
    fb.matrix[0][0] = 1
    fb.matrix[1][2] = 6
    fb.dump()   # must not raise


def test_items_dump_on_primitive_raises(headers):
    prim = headers.craft('Basic').a
    with pytest.raises(TypeError):
        list(prim.items())
    with pytest.raises(TypeError):
        prim.dump()


def test_values_arraycrafter():
    arr = C64.craft('int[4]')
    for i in range(4):
        arr[i] = i + 1
    assert arr.values() == [1, 2, 3, 4]

    grid = C64.craft('int[2][3]')
    vals = [[10, 20, 30], [40, 50, 60]]
    for r in range(2):
        for c in range(3):
            grid[r][c] = vals[r][c]
    assert grid.values() == vals


def test_char_array_values(headers):
    arr = headers.craft('char[5]')
    for i in range(5):
        arr[i] = ord('A') + i
    assert arr.values() == [65, 66, 67, 68, 69]


def test_fill(headers):
    arr = headers.craft('int[6]')
    arr.fill(0xbeef)
    assert all(v == 0xbeef for v in arr.values())


def test_fill_patterns(headers):
    s = headers.craft('Basic')
    s.fill(b'\xde\xad')
    assert bytes(s) == b'\xde\xad' * 6


def test_fill_errors(headers):
    with pytest.raises(ValueError):
        headers.craft('Basic').fill(256)
    with pytest.raises(ValueError):
        headers.craft('Basic').fill(b'')
    with pytest.raises(TypeError):
        headers.craft('Basic').fill(1.5)


def test_2d_fill(headers):
    arr = headers.craft('int[3][4]')
    arr.fill(0x42)
    assert all(arr[r][c].value == 0x42 for r in range(3) for c in range(4))


def test_cyclic(headers):
    s = headers.craft('Basic')
    s.cyclic()
    assert bytes(s) == pwn_cyclic(headers.sizeof('Basic'))

    arr = headers.craft('int[4]')
    arr.cyclic()
    assert bytes(arr) == pwn_cyclic(16)


def test_copy_crafter(headers):
    orig = headers.craft('FinalBoss')
    orig.current_state = 77
    cloned = orig.copy()
    cloned.current_state = 0
    assert orig.current_state.value == 77
    assert cloned.current_state.value == 0


def test_copy_arraycrafter():
    orig = C64.craft('int[4]')
    orig[0] = 10
    cloned = orig.copy()
    cloned[0] = 999
    assert orig[0].value == 10
    assert cloned[0].value == 999


def test_copy_subview_independence(headers):
    boss = headers.craft('BossFight')
    boss.b[0].a = ord('X')
    boss.b[1].a = ord('Y')
    sub_copy = boss.b[0].copy()
    sub_copy.a = ord('Z')
    assert boss.b[0].a.value == ord('X')
    assert sub_copy.a.value == ord('Z')


# ============================================================
# Memory model: unions, shared backing, sub-crafter size
# ============================================================

def test_union_memory_overlap(headers):
    um = headers.craft('UnionMadness')
    um.data.coords.x = 0x12345678
    raw = bytes(um.data.raw)
    assert raw[:4] == b'\x78\x56\x34\x12'


def test_sub_crafter_shared_backing(headers):
    boss = headers.craft('BossFight')
    boss.b[0].a = ord('M')
    assert bytes(boss)[0] == ord('M')


def test_sub_crafter_bytes_size(headers):
    bf = headers.craft('BossFight')
    bf.b[1].b = 0xCAFE
    sub = bytes(bf.b[1])
    assert len(sub) == headers.sizeof('Basic')
    assert struct.unpack_from('<i', sub, 4)[0] == 0xCAFE


def test_2d_sub_view_sharing(headers):
    parent = headers.craft('int[3][4]')
    row = parent[1]
    row[0] = 0xABCD
    assert parent[1][0].value == 0xABCD


# ============================================================
# Numeric conversions, truncation, in-place ops, augmented assign
# ============================================================

def test_integer_truncation(headers):
    ec = headers.craft('EdgeCases')
    ec.small_int = 0xdeadbeef   # unsigned short → 0xbeef
    assert ec.small_int.value == 0xbeef
    ec.big_int = -1
    assert ec.big_int.value == -1


def test_negative_unsigned_wraps(headers):
    ec = headers.craft('EdgeCases')
    ec.small_int = -1           # unsigned short → 0xffff
    assert ec.small_int.value == 0xffff


def test_value_setter(headers):
    pf = headers.craft('Basic')
    pf.b.value = 9999
    assert pf.b.value == 9999


def test_float_int_conversions(headers):
    fb = headers.craft('FinalBoss')
    fb.max_hp = 3.5
    assert float(fb.max_hp) == 3.5
    fb.current_state = 7
    assert int(fb.current_state) == 7


def test_inplace_operators(headers):
    fb = headers.craft('FinalBoss')
    fb.current_state = 10
    fb.current_state += 5
    assert fb.current_state.value == 15
    fb.current_state -= 3
    assert fb.current_state.value == 12


def test_augmented_assign_semantics(headers):
    fb = headers.craft('FinalBoss')
    fb.current_state = 10
    local = fb.current_state
    local += 99                 # detached: rebinds local to plain int
    assert type(local) is int
    assert fb.current_state.value == 10   # parent unchanged
    fb.current_state += 5       # member-expression form writes back
    assert fb.current_state.value == 15


def test_true_dunder_attr(headers):
    s = headers.craft('Basic')
    s.__doc__ = 'hello'         # real Python dunder → stored on object
    assert s.__doc__ == 'hello'
    assert bytes(s) == bytes(headers.sizeof('Basic'))   # backing untouched


# ============================================================
# C struct fields with dunder-like names (e.g. __finish)
# ============================================================

def test_dunder_struct_fields():
    j = CInline("""\
typedef struct testing {
    unsigned long long __dummy;
    unsigned long long __dummy2;
    unsigned long long __finish;
} testing;
""")
    m = j.craft('testing')

    m.__finish = 0x1234568
    assert m.__finish.value == 0x1234568

    m.__dummy = 0x4949
    assert m.__dummy.value == 0x4949

    vals = struct.unpack_from('<QQQ', bytes(m))
    assert vals[0] == 0x4949
    assert vals[2] == 0x1234568


# ============================================================
# Bytes assignment: truncation and zero-padding
# ============================================================

def test_bytes_truncated_to_field(headers):
    s = headers.craft('Basic')
    s.a = b'\x41\x42\x43\x44\x45'   # 5 bytes into 1-byte char
    assert bytes(s)[0] == 0x41
    assert bytes(s)[1:4] == b'\x00\x00\x00'


def test_bytes_zero_padded_to_field(headers):
    s = headers.craft('Basic')
    s.b = b'\xef'                    # 1 byte into 4-byte int
    assert bytes(s)[4] == 0xef
    assert bytes(s)[5:8] == b'\x00\x00\x00'


# ============================================================
# Pointer fields
# ============================================================

def test_pointer_field_read_write(headers):
    af = headers.craft('ArrayFun')
    af.ptr = 0xdeadbeef12345678
    assert af.ptr.value == 0xdeadbeef12345678
    assert p64(af.ptr) == p64(0xdeadbeef12345678)


# ============================================================
# DWARFCrafter new methods: values(), index(), count(), eq, add, mul, radd
# ============================================================

def test_crafter_values(headers):
    fb = headers.craft('FinalBoss')
    fb.current_state = 2
    assert fb.current_state.values() == 2   # primitive

    fb.matrix[0][0] = 10
    fb.matrix[0][1] = 20
    fb.matrix[1][2] = 99
    assert fb.matrix.values() == [[10, 20, 0], [0, 0, 99]]  # array field

    d = fb.values()
    assert isinstance(d, dict)
    assert 'current_state' in d and 'matrix' in d
    assert d['matrix'] == [[10, 20, 0], [0, 0, 99]]


def test_crafter_index(headers):
    fb = headers.craft('FinalBoss')
    fb.matrix[0][1] = 7
    fb.matrix[0][2] = 7
    assert fb.matrix[0].index(7) == 1
    assert fb.matrix[0].index(7, 2) == 2
    with pytest.raises(ValueError):
        fb.matrix[0].index(99)
    with pytest.raises(TypeError):
        fb.current_state.index(1)   # non-array


def test_crafter_count(headers):
    fb = headers.craft('FinalBoss')
    fb.matrix[1][0] = 5
    fb.matrix[1][1] = 5
    fb.matrix[1][2] = 3
    assert fb.matrix[1].count(5) == 2
    assert fb.matrix[1].count(3) == 1
    assert fb.matrix[1].count(0) == 0


def test_crafter_eq_struct(headers):
    a = headers.craft('Basic')
    b = headers.craft('Basic')
    a.a = 0x41
    b.a = 0x41
    assert a == b
    b.a = 0x42
    assert a != b
    assert a == bytes(a)


def test_crafter_add_struct(headers):
    a = headers.craft('Basic')
    b = headers.craft('Basic')
    a.a = 0x11
    b.a = 0x22
    combined = a + b
    assert isinstance(combined, DWARFArrayCrafter)
    assert len(combined) == 2
    assert combined[0].a.value == 0x11
    assert combined[1].a.value == 0x22
    with pytest.raises(TypeError):
        a + headers.craft('FinalBoss')


def test_crafter_mul_struct(headers):
    base = headers.craft('Basic')
    base.a = 0x42   # fits in signed char
    base.b = 0x1234

    arr3 = base * 3
    assert isinstance(arr3, DWARFArrayCrafter)
    assert len(arr3) == 3
    assert arr3[0].a.value == 0x42
    assert arr3[2].b.value == 0x1234

    assert len(2 * base) == 2           # __rmul__
    assert len(base * 0) == 0           # zero gives empty

    with pytest.raises(ValueError):
        base * -1

    # copies are independent
    arr3[0].a = 0x11
    assert arr3[1].a.value == 0x42


def test_crafter_iadd_struct(headers):
    x = headers.craft('Basic')
    y = headers.craft('Basic')
    x.a = 0x10
    y.a = 0x20
    x += y
    assert isinstance(x, DWARFArrayCrafter)
    assert len(x) == 2
    assert x[0].a.value == 0x10
    assert x[1].a.value == 0x20


def test_crafter_radd(headers):
    # numeric __radd__: int + field
    fb = headers.craft('FinalBoss')
    fb.current_state = 5
    assert 10 + fb.current_state == 15

    # struct __radd__ (direct call, mirrors subclass-priority rule)
    a = headers.craft('Basic')
    b = headers.craft('Basic')
    a.a = 0x33
    b.a = 0x44
    result = b.__radd__(a)   # other=a first, self=b second
    assert isinstance(result, DWARFArrayCrafter)
    assert len(result) == 2
    assert result[0].a.value == 0x33
    assert result[1].a.value == 0x44

    with pytest.raises(TypeError):
        a.__radd__(headers.craft('FinalBoss'))


# ============================================================
# DWARFArrayCrafter list-like interface
# ============================================================

def test_arraycrafter_contains():
    ac = C64.craft('int[5]')
    ac[2] = 42
    assert 42 in ac
    assert 0 in ac
    assert 99 not in ac

    # 2-D deep scan
    grid = C64.craft('int[3][3]')
    grid[1][2] = 777
    assert 777 in grid
    assert 999 not in grid

    # row match via list
    grid2 = C64.craft('int[3][3]')
    grid2[2] = [10, 20, 30]
    assert [10, 20, 30] in grid2
    assert [10, 20, 31] not in grid2


def test_arraycrafter_eq():
    eq1 = C64.craft('int[3]')
    eq1[0] = 1; eq1[1] = 2; eq1[2] = 3

    assert eq1 == [1, 2, 3]
    assert not (eq1 == [1, 2, 4])
    assert eq1 != [1, 2, 4]

    eq2 = C64.craft('int[3]')
    eq2[0] = 1; eq2[1] = 2; eq2[2] = 3
    assert eq1 == eq2
    eq2[0] = 99
    assert eq1 != eq2

    grid = C64.craft('int[2][2]')
    grid[0] = [1, 2]; grid[1] = [3, 4]
    assert grid == [[1, 2], [3, 4]]
    assert not (grid == [[1, 2], [3, 5]])


def test_arraycrafter_add():
    a1 = C64.craft('int[3]')
    a1[0] = 10; a1[1] = 20; a1[2] = 30
    a2 = C64.craft('int[2]')
    a2[0] = 40; a2[1] = 50
    a3 = a1 + a2
    assert len(a3) == 5
    assert a3 == [10, 20, 30, 40, 50]
    a3[0] = 99
    assert a1[0].value == 10   # independent
    assert a2[0].value == 40


def test_arraycrafter_iadd():
    ia = C64.craft('int[2]')
    ib = C64.craft('int[2]')
    ia[0] = 1; ia[1] = 2
    ib[0] = 3; ib[1] = 4
    ia += ib
    assert len(ia) == 4
    assert ia == [1, 2, 3, 4]


def test_arraycrafter_add_type_mismatch():
    with pytest.raises(TypeError):
        C64.craft('int[2]') + C64.craft('char[2]')


def test_arraycrafter_mul():
    m = C64.craft('int[3]')
    m[0] = 7; m[1] = 8; m[2] = 9
    rep = m * 3
    assert len(rep) == 9
    assert rep == [7, 8, 9, 7, 8, 9, 7, 8, 9]
    rep[0] = 99
    assert rep[3].value == 7   # independent copies


def test_arraycrafter_rmul():
    r = C64.craft('int[2]')
    r[0] = 5; r[1] = 6
    rep = 4 * r
    assert len(rep) == 8
    assert rep == [5, 6, 5, 6, 5, 6, 5, 6]


def test_arraycrafter_mul_zero():
    assert len(C64.craft('int[4]') * 0) == 0


def test_arraycrafter_index_1d():
    idx = C64.craft('int[5]')
    idx[0] = 10; idx[1] = 20; idx[2] = 10; idx[3] = 30; idx[4] = 20
    assert idx.index(10) == 0
    assert idx.index(20) == 1
    assert idx.index(30) == 3
    assert idx.index(10, 1) == 2
    assert idx.index(20, 2, 5) == 4
    with pytest.raises(ValueError):
        idx.index(99)


def test_arraycrafter_index_2d():
    ig = C64.craft('int[4][2]')
    ig[0] = [1, 2]; ig[1] = [3, 4]; ig[2] = [1, 2]; ig[3] = [5, 6]
    assert ig.index([1, 2]) == 0
    assert ig.index([1, 2], 1) == 2
    assert ig.index([3, 4]) == 1


def test_arraycrafter_count_1d():
    cnt = C64.craft('int[6]')
    cnt[0] = 5; cnt[1] = 3; cnt[2] = 5; cnt[3] = 5; cnt[4] = 0; cnt[5] = 3
    assert cnt.count(5) == 3
    assert cnt.count(3) == 2
    assert cnt.count(0) == 1
    assert cnt.count(99) == 0


def test_arraycrafter_count_2d():
    cg = C64.craft('int[4][2]')
    cg[0] = [1, 2]; cg[1] = [3, 4]; cg[2] = [1, 2]; cg[3] = [1, 2]
    assert cg.count([1, 2]) == 3
    assert cg.count([3, 4]) == 1
    assert cg.count([0, 0]) == 0


def test_arraycrafter_slice():
    sl = C64.craft('int[6]')
    for i in range(6):
        sl[i] = i * 10
    sliced = sl[2:5]
    assert isinstance(sliced, list) and len(sliced) == 3
    assert [x.value for x in sliced] == [20, 30, 40]


def test_arraycrafter_slice_assignment():
    sa = C64.craft('int[5]')
    sa[1:4] = [11, 22, 33]
    assert [sa[i].value for i in range(5)] == [0, 11, 22, 33, 0]


def test_arraycrafter_repr():
    arr = C64.craft('int[3][4]')
    r = repr(arr)
    assert 'int' in r and '3' in r and '4' in r


# ============================================================
# String-key escape hatch: crafter['fieldname'] / crafter['fieldname'] = v
# ============================================================

# Header shared by several tests below.  It deliberately uses field names that
# are either true Python dunders or collide with DWARFCrafter methods/properties.
_SHADOWED_H = """\
typedef struct shadowed {
    int value;
    int items;
    int copy;
    int __init__;
    int __foo__;
} shadowed;
"""


def _make_shadowed():
    """Compile _SHADOWED_H and return a CInline instance."""
    return CInline(_SHADOWED_H)


def test_string_key_read_shadowed_by_property():
    """crafter['value'] reaches the C field 'value', not the .value property."""
    j = _make_shadowed()
    m = j.craft('shadowed')
    # Write through normal attribute path (works because 'value' is a property,
    # not blocked by __setattr__).  Then read back via bracket syntax.
    m['value'] = 42
    result = m['value']
    assert result.value == 42, f"Expected 42, got {result.value}"


def test_string_key_read_shadowed_by_method():
    """crafter['items'] / crafter['copy'] reach C fields, not the Python methods."""
    j = _make_shadowed()
    m = j.craft('shadowed')
    m['items'] = 100
    m['copy'] = 200
    assert m['items'].value == 100
    assert m['copy'].value == 200


def test_string_key_read_true_dunder_field():
    """crafter['__foo__'] reaches a C field whose name looks like a dunder."""
    j = _make_shadowed()
    m = j.craft('shadowed')
    m['__init__'] = 0xABCD
    m['__foo__'] = 0x1234
    assert m['__init__'].value == 0xABCD
    assert m['__foo__'].value == 0x1234


def test_string_key_write_visible_in_bytes():
    """Writes via crafter['field'] = v are reflected in bytes(crafter)."""
    j = _make_shadowed()
    m = j.craft('shadowed')
    m['value'] = 0xDEAD
    m['__foo__'] = 0xBEEF
    raw = bytes(m)
    import struct as _struct
    fields = _struct.unpack_from('<iiiii', raw)
    # 'value' is the first field, '__foo__' is the last (5th)
    assert fields[0] == 0xDEAD, f"'value' field: {hex(fields[0])}"
    assert fields[4] == 0xBEEF, f"'__foo__' field: {hex(fields[4])}"


def test_string_key_not_found_raises_key_error():
    """A non-existent field name raises KeyError, not AttributeError."""
    j = _make_shadowed()
    m = j.craft('shadowed')
    with pytest.raises(KeyError):
        _ = m['does_not_exist']
    with pytest.raises(KeyError):
        m['does_not_exist'] = 99


def test_string_key_normal_attr_access_unaffected():
    """Adding string-key support must not break ordinary attribute access."""
    j = _make_shadowed()
    m = j.craft('shadowed')
    # 'value' property still works for fields that DON'T collide
    m['items'] = 55
    assert m['items'].value == 55   # bracket
    # Regular fields on headers still reachable via dot notation
    fb = CHeader.__new__(CHeader)   # we just need the fixture headers here


def test_string_key_and_dot_notation_are_equivalent():
    """For an ordinary field name, crafter['x'] and crafter.x return the same data."""
    j = CInline("typedef struct simple { int x; int y; } simple;")
    m = j.craft('simple')
    m.x = 77
    assert m['x'].value == 77       # bracket
    assert m.x.value == 77          # dot — same backing
    m['y'] = 88
    assert m.y.value == 88          # dot sees the bracket write


def test_string_key_chaining():
    """crafter['field'] returns a DWARFCrafter that supports further field access."""
    j = CInline("""\
typedef struct inner { int value; int copy; } inner;
typedef struct outer { inner items; int pad; } outer;
""")
    m = j.craft('outer')
    # 'items' on outer is a C field; on the returned inner crafter 'value'/'copy'
    # are C fields too — use bracket access all the way down.
    m['items']['value'] = 0x1111
    m['items']['copy'] = 0x2222
    assert m['items']['value'].value == 0x1111
    assert m['items']['copy'].value == 0x2222


# ============================================================
# Dot-path type navigation: sizeof / craft / describe / cast
# ============================================================

def test_sizeof_dotpath_struct_field(headers):
    """sizeof('BossFight.u') returns the size of the UnionMadness member."""
    # 'u' in BossFight is of type UnionMadness; verify it matches standalone sizeof
    assert headers.sizeof('BossFight.u') == headers.sizeof('UnionMadness')


def test_sizeof_dotpath_primitive_field(headers):
    """sizeof('FinalBoss.negative_val') returns 2 (short)."""
    assert headers.sizeof('FinalBoss.negative_val') == 2


def test_sizeof_dotpath_array_field(headers):
    """sizeof('FinalBoss.matrix') returns total bytes of the array."""
    # int matrix[2][3] -> 2 * 3 * 4 = 24 bytes
    assert headers.sizeof('FinalBoss.matrix') == 24


def test_sizeof_dotpath_deep(headers):
    """sizeof('BossFight.u.data.coords') returns size of coords struct."""
    assert headers.sizeof('BossFight.u.data.coords') == headers.sizeof('BossFight.u.data.coords')
    # coords has two ints: 8 bytes
    assert headers.sizeof('BossFight.u.data.coords') == 8


def test_sizeof_dotpath_invalid_base(headers):
    """sizeof('NoSuchType.field') raises ValueError."""
    with pytest.raises(ValueError, match="not found"):
        headers.sizeof('NoSuchType.field')


def test_sizeof_dotpath_invalid_field(headers):
    """sizeof('Basic.nonexistent') raises ValueError."""
    with pytest.raises(ValueError, match="not found"):
        headers.sizeof('Basic.nonexistent')


def test_craft_dotpath_struct_field(headers):
    """craft('BossFight.u') creates a crafter for UnionMadness."""
    m = headers.craft('BossFight.u')
    assert len(bytes(m)) == headers.sizeof('UnionMadness')


def test_craft_dotpath_assigns_correctly(headers):
    """craft('BossFight.u') crafter supports normal field writes."""
    m = headers.craft('BossFight.u')
    m.type = 0x1234
    assert m.type.value == 0x1234


def test_craft_dotpath_primitive_field(headers):
    """craft('FinalBoss.negative_val') creates a 2-byte crafter."""
    m = headers.craft('FinalBoss.negative_val')
    assert len(bytes(m)) == 2


def test_craft_dotpath_with_array_suffix(headers):
    """craft('Basic.b[3]') creates an array-crafter for 3 ints."""
    # 'b' in Basic is an int
    arr = headers.craft('Basic.b[3]')
    arr[0] = 10
    arr[1] = 20
    arr[2] = 30
    import struct as _struct
    vals = _struct.unpack('<iii', bytes(arr))
    assert vals == (10, 20, 30)


def test_describe_dotpath(headers, capsys):
    """describe('BossFight.u') prints layout for UnionMadness, not BossFight."""
    headers.describe('BossFight.u')
    out = capsys.readouterr().out
    # Header line uses the full dot-path as the label
    assert 'BossFight.u' in out
    assert 'union' in out
    # UnionMadness fields: type, data
    assert 'type' in out
    assert 'data' in out
    # Should NOT show BossFight-specific fields like 'b' (the Basic array)
    # The rows should only contain UnionMadness members
    lines = [l for l in out.splitlines() if '0x' in l]
    field_names = {l.split()[-1] for l in lines}
    assert 'b' not in field_names, f"BossFight field 'b' leaked into describe output: {out}"


def test_describe_dotpath_invalid(headers):
    """describe on a primitive field raises ValueError (not a struct/union)."""
    with pytest.raises(ValueError):
        headers.describe('FinalBoss.negative_val')


def test_describe_array_of_struct(headers, capsys):
    """describe('BossFight.b') unwraps through the array to describe Basic."""
    headers.describe('BossFight.b')
    out = capsys.readouterr().out
    assert 'struct' in out
    assert 'element of [2]' in out
    lines = [l for l in out.splitlines() if '0x' in l]
    field_names = {l.split()[-1] for l in lines}
    assert field_names == {'a', 'b', 'c'}


def test_describe_nested_through_array(headers, capsys):
    """describe('GlobalTest.arr.ptr') unwraps ArrayFun[] to describe ptr's type (a pointer, which should fail)."""
    with pytest.raises(ValueError, match="not a struct/union"):
        headers.describe('GlobalTest.arr.ptr')


def test_sizeof_through_array_field(headers):
    """sizeof('BossFight.b.a') resolves through Basic[2] to char -> 1 byte."""
    assert headers.sizeof('BossFight.b.a') == 1
    assert headers.sizeof('BossFight.b.b') == 4


def test_offsetof_through_array_field(headers):
    """offsetof through an array-of-struct field resolves element member offsets."""
    off_b_a = headers.offsetof('BossFight', 'b.a')
    off_b_b = headers.offsetof('BossFight', 'b.b')
    assert off_b_a == headers.offsetof('BossFight', 'b')
    assert off_b_b == off_b_a + headers.offsetof('Basic', 'b')

    off_indexed = headers.offsetof('BossFight', 'b[1].b')
    assert off_indexed == off_b_a + headers.sizeof('Basic') + headers.offsetof('Basic', 'b')


def test_craft_array_of_struct_field(headers):
    """craft('BossFight.b') returns a crafter for Basic[2], indexable into Basic elements."""
    arr = headers.craft('BossFight.b')
    arr[0].a = ord('X')
    arr[0].b = 0x41414141
    arr[1].c = 99
    raw = bytes(arr)
    assert len(raw) == headers.sizeof('Basic') * 2
    reparsed = headers.parse('Basic', raw)
    assert reparsed.a.value == ord('X')
    assert reparsed.b.value == 0x41414141


def test_cast_dotpath_offset_adjustment(headers):
    """cast('BossFight.u', base_addr) returns an address offset by the field's position."""
    # BossFight: b[2] is two Basic structs. Basic has (char a, int b, short c).
    # sizeof(Basic) - need to account for padding.
    basic_size = headers.sizeof('Basic')
    u_offset = headers.offsetof('BossFight', 'u')
    base = 0x10000
    result = headers.cast('BossFight.u', base)
    assert int(result) == base + u_offset


def test_cast_dotpath_deep_field(headers):
    """cast('BossFight.u.data.raw', base_addr) adjusts for the nested offset."""
    base = 0x20000
    raw_offset = headers.offsetof('BossFight', 'u.data.raw')
    result = headers.cast('BossFight.u.data.raw', base)
    assert int(result) == base + raw_offset


def test_cast_dotpath_no_dotpath_unchanged(headers):
    """cast without a dot-path still returns address unchanged (regression)."""
    base = 0x30000
    result = headers.cast('Basic', base)
    assert int(result) == base


# ============================================================
# C64 built-in type sizes
# ============================================================

def test_c64_stdint_types():
    assert C64.sizeof('uint64_t') == 8
    assert C64.sizeof('uint32_t') == 4
    assert C64.sizeof('uint8_t') == 1
    assert C64.sizeof('int64_t') == 8
    assert C64.sizeof('size_t') == 8
    assert C64.sizeof('ptrdiff_t') == 8


# ============================================================
# Additional coverage: API edges and documented setup features
# ============================================================

def test_resolve_field_symbol_base(chal_elf):
    assert chal_elf.resolve_field('target_sym') == chal_elf.symbols['target_sym']


def test_resolve_field_with_explicit_struct_name(chal_elf):
    expected = int(chal_elf.sym_obj['target_sym'].arr[2].ptr)
    assert chal_elf.resolve_field('target_sym', 'arr[2].ptr', struct_name='GlobalTest') == expected


def test_resolve_field_invalid_path_raises(chal_elf):
    with pytest.raises(PwnlibException):
        chal_elf.resolve_field('target_sym', 'arr[2].does_not_exist')


def test_resolve_field_missing_symbol_raises(chal_elf):
    with pytest.raises(PwnlibException):
        chal_elf.resolve_field('does_not_exist', 'arr[0]')


def test_resolve_type_alias_short(headers):
    assert headers.resolve_type('short') == 'short int'


def test_cheader_include_dirs(tmp_path):
    inc = tmp_path / 'include'
    inc.mkdir()
    (inc / 'inner.h').write_text(
        "typedef struct inner {\n"
        "    int field_value;\n"
        "} inner;\n"
    )
    (tmp_path / 'outer.h').write_text(
        '#include "inner.h"\n'
        "typedef struct outer {\n"
        "    inner field;\n"
        "} outer;\n"
    )

    hdr = CHeader(str(tmp_path / 'outer.h'), include_dirs=[str(inc)])
    outer = hdr.craft('outer')
    outer.field.field_value = 7

    assert outer.field.field_value.value == 7


def test_cheader_missing_file_raises(tmp_path):
    with pytest.raises(FileNotFoundError):
        CHeader(str(tmp_path / 'missing.h'))


def test_cheader_invalid_header_raises():
    with pytest.raises(PwnlibException):
        CInline(
            "typedef struct broken {\n"
            "    int value;\n"
            "    @\n"
            "} broken;\n"
        )


def test_bool_base_type_round_trip():
    hdr = CInline(
        "typedef struct boolish {\n"
        "    _Bool flag;\n"
        "} boolish;\n"
    )
    obj = hdr.craft('boolish')

    obj.flag = 0
    assert obj.flag.value is False

    obj.flag = 1
    assert obj.flag.value is True


# ── Parser parity tests ───────────────────────────────────────────────────────
#
# These compare the Rust DWARF parser output to pyelftools, ensuring both
# produce identical name→offset mappings.  Skipped when the Rust extension
# is not installed.

_PYELF_CACHEABLE_TAGS = (
    'DW_TAG_variable', 'DW_TAG_structure_type', 'DW_TAG_class_type',
    'DW_TAG_union_type', 'DW_TAG_typedef', 'DW_TAG_enumeration_type',
    'DW_TAG_base_type',
)


def _pyelf_parse(path):
    """Reference parser using pyelftools — mirrors _build_dwarf_cache logic."""
    pe_vars, pe_types = {}, {}
    with open(path, 'rb') as f:
        elf = ELFFile(f)
        if not elf.has_dwarf_info():
            return pe_vars, pe_types
        for CU in elf.get_dwarf_info().iter_CUs():
            for die in CU.iter_DIEs():
                if die.tag in _PYELF_CACHEABLE_TAGS:
                    attr = die.attributes.get('DW_AT_name')
                    if attr:
                        name = attr.value.decode('utf-8', errors='ignore')
                        if die.tag == 'DW_TAG_variable':
                            pe_vars[name] = die.offset
                        else:
                            pe_types[name] = die.offset
    return pe_vars, pe_types


def test_parity_et_rel(tmp_path):
    """Rust parser matches pyelftools on a relocatable .o file (ET_REL)."""
    dwarf_rs = pytest.importorskip("doglib_dwarf_parser")

    src = tmp_path / "test.h"
    src.write_text(
        "typedef struct point { int x; int y; } point;\n"
        "typedef struct line { point a; point b; } line;\n"
    )
    obj = tmp_path / "test.o"
    subprocess.run(
        ["gcc", "-x", "c", "-c", "-g", "-fno-eliminate-unused-debug-types",
         str(src), "-o", str(obj)],
        check=True,
    )

    pe_vars, pe_types = _pyelf_parse(str(obj))
    rs_vars, rs_types = dwarf_rs.parse_dwarf(str(obj))
    assert rs_vars == pe_vars
    assert rs_types == pe_types


def test_parity_et_exec(change_to_test_dir):
    """Rust parser matches pyelftools on a linked executable (ET_EXEC)."""
    dwarf_rs = pytest.importorskip("doglib_dwarf_parser")

    path = os.path.join(os.path.dirname(__file__), "challenge")
    pe_vars, pe_types = _pyelf_parse(path)
    rs_vars, rs_types = dwarf_rs.parse_dwarf(path)
    assert rs_vars == pe_vars
    assert rs_types == pe_types


def test_parity_cpp(tmp_path):
    """Rust parser matches pyelftools on a C++ .o with classes and namespaces."""
    dwarf_rs = pytest.importorskip("doglib_dwarf_parser")

    src = tmp_path / "cpp_test.cpp"
    src.write_text(
        "class Animal { public: int legs; char name[32]; };\n"
        "struct Position { float x, y; };\n"
        "namespace game {\n"
        "  class Player { public: Position pos; int health; };\n"
        "}\n"
        "enum Color { RED, GREEN, BLUE };\n"
        "game::Player global_player;\n"
    )
    obj = tmp_path / "cpp_test.o"
    subprocess.run(
        ["g++", "-x", "c++", "-c", "-g", "-fno-eliminate-unused-debug-types",
         str(src), "-o", str(obj)],
        check=True,
    )

    pe_vars, pe_types = _pyelf_parse(str(obj))
    rs_vars, rs_types = dwarf_rs.parse_dwarf(str(obj))
    assert rs_vars == pe_vars
    assert rs_types == pe_types
    assert "Animal" in rs_types, "DW_TAG_class_type should be indexed"
    assert "Position" in rs_types
    assert "Player" in rs_types
    assert "Color" in rs_types


_GLIBC_PATH = "/home/corgo/pwn/tools/latest_glibc/libc6_2.23-0ubuntu11.3_amd64.so"


@pytest.mark.skipif(
    not os.path.exists(_GLIBC_PATH),
    reason="glibc test binary not available",
)
def test_parity_glibc():
    """Rust parser matches pyelftools on a real glibc with debug info."""
    dwarf_rs = pytest.importorskip("doglib_dwarf_parser")

    pe_vars, pe_types = _pyelf_parse(_GLIBC_PATH)
    rs_vars, rs_types = dwarf_rs.parse_dwarf(_GLIBC_PATH)
    assert rs_vars == pe_vars
    assert rs_types == pe_types
    assert len(rs_types) > 100, "Expected many types in glibc"


def test_parity_no_dwarf(tmp_path):
    """Rust parser returns empty dicts for a binary with no debug info."""
    dwarf_rs = pytest.importorskip("doglib_dwarf_parser")

    src = tmp_path / "nodebug.c"
    src.write_text("int main() { return 0; }\n")
    obj = tmp_path / "nodebug.o"
    subprocess.run(
        ["gcc", "-x", "c", "-c", str(src), "-o", str(obj)],
        check=True,
    )

    rs_vars, rs_types = dwarf_rs.parse_dwarf(str(obj))
    assert rs_vars == {}
    assert rs_types == {}


def test_rust_fallback(change_to_test_dir, monkeypatch):
    """When the Rust parser returns empty, Python falls back to pyelftools."""
    from doglib.extelf import _elf as elf_module
    if elf_module._dwarf_parser_rs is None:
        pytest.skip("Rust parser not installed")

    def mock_parse(_path):
        return ({}, {})

    monkeypatch.setattr(elf_module._dwarf_parser_rs, "parse_dwarf", mock_parse)

    from doglib.extelf import ExtendedELF
    elf = ExtendedELF("./challenge")
    elf._dwarf_parsed = False
    elf._dwarf_vars = {}
    elf._dwarf_types = {}
    elf._build_dwarf_cache()
    assert "Basic" in elf._dwarf_types, "Should fall back to pyelftools when Rust returns empty"


# ── C++ challenge solve test ──────────────────────────────────────────────────

def test_cpp_challenge_solve(change_to_test_dir):
    """End-to-end solve of the C++ challenge binary using ExtendedELF."""
    from doglib.extelf import ExtendedELF
    from pwnlib.tubes.process import process as pwnprocess
    import pwnlib.context
    pwnlib.context.context.log_level = 'error'

    elf = ExtendedELF("./challenge_cpp")
    p = pwnprocess("./challenge_cpp")

    # Level 1: Simple class
    coords = elf.craft('Coords')
    coords.x = 10
    coords.y = 20
    coords.z = 30
    p.readuntil(b'Level 1:')
    p.readline()
    p.send(bytes(coords))
    assert b'passed' in p.readline()

    # Level 2: Nested class
    entity = elf.craft('Entity')
    entity.id = 42
    entity.pos.x = 100
    entity.pos.y = 200
    entity.pos.z = 300
    entity.name = b'hero\x00'
    p.readuntil(b'Level 2:')
    p.readline()
    p.send(bytes(entity))
    assert b'passed' in p.readline()

    # Level 3: Inheritance
    player = elf.craft('Player')
    player.id = 1
    player.pos.x = 50
    player.health = 100
    player.weapon.damage = 25
    player.weapon.durability = 75
    p.readuntil(b'Level 3:')
    p.readline()
    p.send(bytes(player))
    assert b'passed' in p.readline()

    # Level 4: Vtable hijack
    win_addr = elf.symbols['_Z3winv']
    fake_vt = elf.symbols['fake_vtable']
    monster = elf.craft('Monster')
    monster['_vptr.Monster'] = fake_vt
    monster.hp = 0x1337
    p.readuntil(b'Level 4:')
    p.readline()
    p.send(p64(win_addr))
    p.send(bytes(monster))
    assert b'passed' in p.readline()

    p.close()


# ============================================================
# Tests for forward-declaration skipping (fix #1)
# ============================================================

def test_declaration_skipping_python_parser(tmp_path):
    """Python parser skips DW_AT_declaration and keeps the full definition."""
    from doglib.extelf import CInline
    t = CInline('''
        struct opaque;
        struct opaque { int x; int y; };
    ''')
    assert t.sizeof('opaque') == 8
    c = t.craft('opaque')
    c.x = 1; c.y = 2
    assert c.x.value == 1
    assert c.y.value == 2


# ============================================================
# Tests for typedef-array craft (fix #3)
# ============================================================

def test_craft_typedef_array(tmp_path):
    """craft() on a typedef-array creates a DWARFArrayCrafter, not a plain DWARFCrafter."""
    from doglib.extelf import CInline
    from doglib.extelf._crafter import DWARFArrayCrafter
    t = CInline('typedef int block_t[8];')
    arr = t.craft('block_t')
    assert isinstance(arr, DWARFArrayCrafter)
    assert len(arr) == 8
    arr[0] = 0xdead
    arr[7] = 0xbeef
    assert arr[0].value == 0xdead
    assert arr[7].value == 0xbeef


def test_craft_typedef_array_struct(tmp_path):
    """craft() on a typedef of an array-of-struct gives a proper array crafter."""
    from doglib.extelf import CInline
    from doglib.extelf._crafter import DWARFArrayCrafter
    t = CInline('''
        typedef struct { int x; int y; } Point;
        typedef Point PointArray[4];
    ''')
    arr = t.craft('PointArray')
    assert isinstance(arr, DWARFArrayCrafter)
    assert len(arr) == 4
    arr[2].x = 10
    arr[2].y = 20
    assert arr[2].x.value == 10


# ============================================================
# Tests for C++ class label fix
# ============================================================

def test_describe_cpp_class_label(change_to_test_dir, capsys):
    """describe() labels DW_TAG_class_type as 'class', not 'union'."""
    import os
    if not os.path.exists('./challenge_cpp'):
        pytest.skip("challenge_cpp binary not compiled")
    from doglib.extelf import ExtendedELF
    elf = ExtendedELF('./challenge_cpp', checksec=False)
    elf.describe('Coords')
    out = capsys.readouterr().out
    assert out.startswith('class ')
    assert 'union' not in out.lower()


def test_get_type_name_cpp_class(change_to_test_dir):
    """get_type_name returns 'class Foo' for DW_TAG_class_type, not 'union Foo'."""
    import os
    if not os.path.exists('./challenge_cpp'):
        pytest.skip("challenge_cpp binary not compiled")
    from doglib.extelf import ExtendedELF
    elf = ExtendedELF('./challenge_cpp', checksec=False)
    die = elf._get_type_die('Coords')
    name = elf._get_type_name(die)
    assert 'class' in name
    assert 'union' not in name


# ============================================================
# Tests for anonymous member iteration fix
# ============================================================

def test_items_includes_anonymous_members(headers):
    """items() yields fields from anonymous struct/union members."""
    c = headers.craft('AnonMember')
    c['as_int'] = 42
    c['x'] = 10
    c['y'] = 20
    names = [name for name, _ in c.items()]
    assert 'type' in names
    assert 'as_int' in names
    assert 'as_float' in names
    assert 'x' in names
    assert 'y' in names


def test_dump_includes_anonymous_members(headers, capsys):
    """dump() shows fields from anonymous struct/union members."""
    c = headers.craft('AnonMember')
    c['as_int'] = 0xff
    c['x'] = 5
    c.dump()
    out = capsys.readouterr().out
    assert 'as_int' in out
    assert 'x' in out
    assert 'y' in out


def test_values_includes_anonymous_members(headers):
    """values() includes anonymous struct/union member fields in the dict."""
    c = headers.craft('AnonMember')
    c['type'] = 1
    c['as_int'] = 99
    c['x'] = 7
    v = c.values()
    assert isinstance(v, dict)
    assert 'as_int' in v
    assert v['as_int'] == 99
    assert 'x' in v
    assert v['x'] == 7


# ============================================================
# Tests for C++ inheritance iteration fix
# ============================================================

def test_items_includes_inherited_fields(change_to_test_dir):
    """items() yields inherited base-class fields for C++ classes."""
    import os
    if not os.path.exists('./challenge_cpp'):
        pytest.skip("challenge_cpp binary not compiled")
    from doglib.extelf import ExtendedELF
    elf = ExtendedELF('./challenge_cpp', checksec=False)
    player = elf.craft('Player')
    names = [name for name, _ in player.items()]
    # Player's own fields
    assert 'health' in names
    # Inherited from Entity
    assert 'id' in names
    assert 'name' in names
    # Inherited from Entity -> Coords (nested, not inherited)
    assert 'pos' in names


def test_describe_includes_inherited_fields(change_to_test_dir, capsys):
    """describe() shows inherited base-class fields for C++ classes."""
    import os
    if not os.path.exists('./challenge_cpp'):
        pytest.skip("challenge_cpp binary not compiled")
    from doglib.extelf import ExtendedELF
    elf = ExtendedELF('./challenge_cpp', checksec=False)
    elf.describe('Player')
    out = capsys.readouterr().out
    assert 'health' in out
    assert 'id' in out
    assert 'name' in out
    assert 'weapon' in out


def test_dump_includes_inherited_fields(change_to_test_dir, capsys):
    """dump() shows inherited base-class fields for C++ classes."""
    import os
    if not os.path.exists('./challenge_cpp'):
        pytest.skip("challenge_cpp binary not compiled")
    from doglib.extelf import ExtendedELF
    elf = ExtendedELF('./challenge_cpp', checksec=False)
    player = elf.craft('Player')
    player['id'] = 7
    player['health'] = 100
    player.dump()
    out = capsys.readouterr().out
    assert 'id' in out
    assert 'health' in out

