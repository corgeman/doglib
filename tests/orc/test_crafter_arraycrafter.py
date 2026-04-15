"""
Tests for DWARFArrayCrafter list-like interface.

Covers: __contains__, __eq__, __add__, __iadd__, __mul__, __rmul__,
index(), count(), slice read/write, repr, __setitem__ edge cases,
__eq__ uncovered branches (diff dims, bytes, wrong-length list, NotImplemented),
__mul__ non-int and negative, and _child_equals bytes branch.
"""
import pytest

from doglib.orc import C64


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
# __setitem__: list-on-scalar and unsupported type
# ============================================================

def test_arraycrafter_setitem_list_on_scalar():
    arr = C64.craft('int[3]')
    arr[0] = [42]       # non-array sub → else: sub.value = value[0]
    assert arr[0].value == 42
    arr[1] = []         # empty list → else: sub.value = 0
    assert arr[1].value == 0


def test_arraycrafter_setitem_unsupported_type_raises():
    arr = C64.craft('int[3]')
    with pytest.raises(TypeError, match="Assign int"):
        arr[0] = {'key': 'val'}


# ============================================================
# __eq__: uncovered branches
# ============================================================

def test_arraycrafter_eq_different_dims():
    a = C64.craft('int[3]')
    b = C64.craft('int[4]')
    assert (a == b) is False


def test_arraycrafter_eq_bytes():
    arr = C64.craft('int[3]')
    arr[0] = 1; arr[1] = 2; arr[2] = 3
    assert arr == bytes(arr)
    assert not (arr == bytearray(12))


def test_arraycrafter_eq_list_wrong_length():
    arr = C64.craft('int[3]')
    assert (arr == [0, 0]) is False     # len 2 != dim 3


def test_arraycrafter_eq_notimplemented():
    arr = C64.craft('int[3]')
    assert arr.__eq__(42) is NotImplemented


# ============================================================
# __mul__: non-int and negative
# ============================================================

def test_arraycrafter_mul_non_int_notimplemented():
    arr = C64.craft('int[3]')
    assert arr.__mul__("abc") is NotImplemented


def test_arraycrafter_mul_negative_raises():
    arr = C64.craft('int[3]')
    with pytest.raises(ValueError, match="non-negative"):
        arr * -1


# ============================================================
# _child_equals: bytes value against DWARFCrafter child
# ============================================================

def test_arraycrafter_contains_bytes():
    arr = C64.craft('char[4]')
    arr[2] = ord('A')
    target = bytes(arr[2])      # b'\x41'
    assert target in arr
    assert b'\xff' not in arr
