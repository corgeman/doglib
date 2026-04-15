"""
Tests for DWARFCrafter / DWARFArrayCrafter: container API and memory model.

Covers: __contains__, items(), dump(), values(), fill(), cyclic(), copy(),
union memory overlap, shared backing, sub-crafter size, 2-D sub-view sharing,
DWARFCrafter values/index/count/eq/add/mul/iadd/radd, slice read (__getitem__
with slice on DWARFCrafter), dump _fmt_val branches, __bytes__ OOB expose,
and DWARFCrafter.index/count with bytes and DWARFCrafter values.
"""
import struct

import pytest
from pwnlib.util.cyclic import cyclic as pwn_cyclic

from doglib.orc import C64, DWARFArrayCrafter


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
# DWARFCrafter: values(), index(), count(), eq, add, mul, radd
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
# DWARFCrafter.__getitem__ slice
# ============================================================

def test_crafter_slice_read(headers):
    fb = headers.craft('FinalBoss')
    fb.matrix[0][0] = 10
    fb.matrix[0][1] = 20
    fb.matrix[0][2] = 30
    sliced = fb.matrix[0][0:2]
    assert isinstance(sliced, list)
    assert len(sliced) == 2
    assert sliced[0].value == 10
    assert sliced[1].value == 20


# ============================================================
# dump() _fmt_val branches: float, negative int, hex int
# ============================================================

def test_dump_float_and_negative_int(headers, capsys):
    fb = headers.craft('FinalBoss')
    fb.current_state = 3        # positive int → hex (0x3)
    fb.negative_val = -7        # negative int → str (-7)
    fb.max_hp = 1.5             # float → repr (1.5)
    fb.dump()
    out = capsys.readouterr().out
    assert '0x3' in out
    assert '-7' in out
    assert '1.5' in out


# ============================================================
# DWARFCrafter.__bytes__: OOB-extended backing exposed at offset 0
# ============================================================

def test_bytes_of_struct_after_oob_write(headers):
    boss = headers.craft('BossFight')
    orig_size = headers.sizeof('BossFight')
    boss.b[10].a = 0x41   # OOB write — extends shared backing
    b = bytes(boss)
    assert len(b) > orig_size
    assert 0x41 in b


# ============================================================
# DWARFCrafter.index / count: bytes and DWARFCrafter values
# ============================================================

def test_crafter_index_bytes_match(headers):
    fb = headers.craft('FinalBoss')
    fb.matrix[0][1] = 0x41424344
    target = bytes(fb.matrix[0][1])
    assert fb.matrix[0].index(target) == 1


def test_crafter_index_crafter_match(headers):
    boss = headers.craft('BossFight')
    boss.b[1].a = ord('Z')
    boss.b[1].b = 0x1234
    ref = headers.craft('Basic')
    ref.a = ord('Z')
    ref.b = 0x1234
    assert boss.b.index(ref) == 1


def test_crafter_count_bytes_match(headers):
    fb = headers.craft('FinalBoss')
    fb.matrix[0][0] = 99
    fb.matrix[0][2] = 99
    target = bytes(fb.matrix[0][0])   # bytes for value 99
    zero_bytes = bytes(fb.matrix[0][1])   # bytes for 0
    assert fb.matrix[0].count(target) == 2
    assert fb.matrix[0].count(zero_bytes) == 1


def test_crafter_count_crafter_match(headers):
    boss = headers.craft('BossFight')
    boss.b[0].a = ord('X')
    boss.b[0].b = 0xABCD
    boss.b[1].a = ord('X')
    boss.b[1].b = 0xABCD
    ref = headers.craft('Basic')
    ref.a = ord('X')
    ref.b = 0xABCD
    assert boss.b.count(ref) == 2
