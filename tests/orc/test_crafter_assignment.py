"""
Tests for DWARFCrafter / DWARFArrayCrafter: write semantics.

Covers: OOB writes, padding parameter, integer/list/slice/bytes assignment,
indexing (negative, iteration), pointer field read/write, _write_value negative
offset, _resolve_field errors, _resolve_index errors, and iter on non-array.
"""
import pytest

from doglib.orc import C64
from pwnlib.util.packing import p64


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
# Indexing (negative, iteration)
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
# _write_value: negative absolute_offset
# ============================================================

def test_negative_absolute_offset_raises(headers):
    # matrix starts at byte 8 in FinalBoss (enum 4 + short 2 + 2 pad).
    # fb.matrix[0] is the first row; _offset == 8.
    # Indexing [-3] gives elem_offset = -3*4 = -12;
    # absolute_offset = 8 + (-12) = -4  →  IndexError in _write_value.
    fb = headers.craft('FinalBoss')
    with pytest.raises(IndexError, match="Negative offset"):
        fb.matrix[0][-3] = 42


# ============================================================
# _resolve_field: pointer and non-struct errors
# ============================================================

def test_resolve_field_through_pointer_raises(headers):
    af = headers.craft('ArrayFun')
    with pytest.raises(AttributeError, match="Cannot resolve through a pointer"):
        af.ptr.foo = 0


def test_resolve_field_on_non_struct_raises(headers):
    # current_state is DW_TAG_enumeration_type, not a struct/union.
    fb = headers.craft('FinalBoss')
    with pytest.raises(AttributeError, match="not a struct/union"):
        fb.current_state.x = 0


# ============================================================
# _resolve_index: type errors
# ============================================================

def test_index_with_non_int_raises(headers):
    fb = headers.craft('FinalBoss')
    with pytest.raises(TypeError, match="Array indices must be integers"):
        _ = fb.matrix[1.5]


def test_resolve_index_string_key_guard(headers):
    # The str guard inside _resolve_index is unreachable via __getitem__ /
    # __setitem__ (both short-circuit str first), so we call it directly.
    fb = headers.craft('FinalBoss')
    with pytest.raises(TypeError, match="String key"):
        fb.matrix._resolve_index('foo')


def test_index_pointer_raises(headers):
    af = headers.craft('ArrayFun')
    with pytest.raises(TypeError, match="Cannot index a pointer"):
        _ = af.ptr[0]


def test_index_non_array_raises(headers):
    fb = headers.craft('FinalBoss')
    with pytest.raises(TypeError, match="Cannot index into non-array"):
        _ = fb.current_state[0]


# ============================================================
# __iter__: non-array type raises
# ============================================================

def test_iter_non_array_raises(headers):
    with pytest.raises(TypeError, match="Cannot iterate over a non-array"):
        list(headers.craft('Basic'))
