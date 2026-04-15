"""
Tests for ORC dot-path type navigation and resolve_type/describe.

Covers: resolve_type, describe (no-crash/error cases), and dot-path variants
of sizeof/craft/describe/cast/offsetof.
"""
import struct as _struct

import pytest

from doglib.orc import ORCHeader


# ============================================================
# resolve_type / describe
# ============================================================

def test_resolve_type(headers):
    assert headers.resolve_type('State') == 'enum State'


def test_resolve_type_alias_short(headers):
    assert headers.resolve_type('short') == 'short int'


def test_describe_no_crash(headers):
    headers.describe('FinalBoss')
    headers.describe('AnonMember')


def test_describe_primitive_raises(headers):
    with pytest.raises(ValueError):
        headers.describe('int')


# ============================================================
# Dot-path type navigation: sizeof / craft / describe / cast / offsetof
# ============================================================

def test_sizeof_dotpath_struct_field(headers):
    """sizeof('BossFight.u') returns the size of the UnionMadness member."""
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


def test_sizeof_through_array_field(headers):
    """sizeof('BossFight.b.a') resolves through Basic[2] to char -> 1 byte."""
    assert headers.sizeof('BossFight.b.a') == 1
    assert headers.sizeof('BossFight.b.b') == 4


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
    arr = headers.craft('Basic.b[3]')
    arr[0] = 10
    arr[1] = 20
    arr[2] = 30
    vals = _struct.unpack('<iii', bytes(arr))
    assert vals == (10, 20, 30)


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


def test_describe_dotpath(headers, capsys):
    """describe('BossFight.u') prints layout for UnionMadness, not BossFight."""
    headers.describe('BossFight.u')
    out = capsys.readouterr().out
    assert 'BossFight.u' in out
    assert 'union' in out
    assert 'type' in out
    assert 'data' in out
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


def test_offsetof_through_array_field(headers):
    """offsetof through an array-of-struct field resolves element member offsets."""
    off_b_a = headers.offsetof('BossFight', 'b.a')
    off_b_b = headers.offsetof('BossFight', 'b.b')
    assert off_b_a == headers.offsetof('BossFight', 'b')
    assert off_b_b == off_b_a + headers.offsetof('Basic', 'b')

    off_indexed = headers.offsetof('BossFight', 'b[1].b')
    assert off_indexed == off_b_a + headers.sizeof('Basic') + headers.offsetof('Basic', 'b')


def test_cast_dotpath_offset_adjustment(headers):
    """cast('BossFight.u', base_addr) returns an address offset by the field's position."""
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
# _walk_field_path error paths
# ============================================================

def test_offsetof_through_pointer_raises(headers):
    """Walking a field path through a pointer raises ValueError."""
    with pytest.raises(ValueError, match="pointer"):
        headers.offsetof('ArrayFun', 'ptr.something')


def test_offsetof_index_on_non_array_raises(headers):
    """Using an array index on a non-array field raises ValueError."""
    with pytest.raises(ValueError, match="Expected array type"):
        headers.offsetof('Basic', 'b[0]')


def test_offsetof_field_on_primitive_raises(headers):
    """Dot-navigating into a primitive type raises ValueError."""
    with pytest.raises(ValueError, match="Expected struct/union"):
        headers.offsetof('Basic', 'b.x')


# ============================================================
# describe: union label and pointer-to-struct annotation
# ============================================================

def test_describe_union_type_label(capsys):
    """describe() labels a top-level union type as 'union'."""
    from doglib.orc import ORCInline
    t = ORCInline('union MyUnion { int a; float b; };')
    t.describe('MyUnion')
    out = capsys.readouterr().out
    assert out.startswith('union ')


def test_describe_pointer_to_struct(capsys):
    """describe() on a pointer-to-struct shows 'pointee of *' annotation."""
    from doglib.orc import ORCInline
    t = ORCInline(
        'typedef struct Inner { int x; int y; } Inner;'
        'typedef Inner *InnerPtr;'
    )
    t.describe('InnerPtr')
    out = capsys.readouterr().out
    assert 'pointee of *' in out
