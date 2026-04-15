"""
Tests for DWARFCrafter / DWARFArrayCrafter: operator overloads and numeric conversions.

Covers: bitwise, comparison, arithmetic, bool, format, repr, hash, p64,
integer truncation, float/int conversion, in-place and augmented assignment,
true dunder attribute passthrough.
"""
import math

import pytest
from pwnlib.util.packing import p64

from doglib.orc import C64


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
