"""
Tests for DWARFCrafter / DWARFArrayCrafter: parse, craft, and cast basics.

Covers: craft/parse/cast with count, 2-D type-string syntax, primitive arrays,
pointer-craft/cast validation, __len__, __repr__ branches, __float__.
"""
import pytest

from doglib.orc import ORCInline


# ============================================================
# parse / craft / cast basics
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


def test_craft_pointer_raises(headers):
    with pytest.raises(ValueError):
        headers.craft('int *')


def test_cast_double_pointer_raises(headers):
    with pytest.raises(ValueError):
        headers.cast('int **', 0x1000)


# ============================================================
# __len__
# ============================================================

def test_len_struct(headers):
    assert len(headers.craft('Basic')) == headers.sizeof('Basic')


def test_len_primitive_field(headers):
    basic = headers.craft('Basic')
    assert len(basic.b) == 4   # int is 4 bytes


# ============================================================
# __repr__ branches
# ============================================================

def test_repr_pointer_field(headers):
    af = headers.craft('ArrayFun')
    af.ptr = 0xdeadbeef
    r = repr(af.ptr)
    assert 'deadbeef' in r


def test_repr_array_field(headers):
    fb = headers.craft('FinalBoss')
    r = repr(fb.matrix)
    assert 'array' in r
    # FinalBoss.matrix is int[2][3]; both dims must appear
    assert '2' in r
    assert '3' in r


def test_repr_fallback_on_exception(headers):
    fb = headers.craft('FinalBoss')
    fb.current_state = 7
    orc = fb._orc
    original = orc._get_type_name
    orc._get_type_name = lambda _: 1 / 0   # force ZeroDivisionError inside try
    try:
        r = repr(fb)
        assert r.startswith('<DWARFCrafter size=')
        assert 'data=' in r
    finally:
        orc._get_type_name = original


# ============================================================
# __float__
# ============================================================

def test_float_from_int_field(headers):
    basic = headers.craft('Basic')
    basic.b = 7
    result = float(basic.b)
    assert isinstance(result, float)
    assert result == 7.0


def test_float_on_struct_raises(headers):
    with pytest.raises(TypeError, match="no single numeric value"):
        float(headers.craft('Basic'))
