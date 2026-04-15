"""
Unit tests for _constants.py helpers.

Covers: inner_count None-dimension early return, va_mask, dims_str.
"""
from doglib.orc._constants import inner_count, va_mask, dims_str


# ============================================================
# inner_count
# ============================================================

def test_inner_count_none_dimension_returns_1():
    """If any dimension after the first is None, inner_count returns 1 early."""
    assert inner_count((3, None)) == 1
    assert inner_count((3, None, 4)) == 1


def test_inner_count_normal():
    assert inner_count((3, 4)) == 4
    assert inner_count((3, 4, 5)) == 20
    assert inner_count((7,)) == 1   # no inner dims → product of empty slice = 1


# ============================================================
# va_mask
# ============================================================

def test_va_mask_32():
    assert va_mask(32) == 0xFFFFFFFF


def test_va_mask_64():
    assert va_mask(64) == 0xFFFFFFFFFFFFFFFF


# ============================================================
# dims_str
# ============================================================

def test_dims_str():
    assert dims_str((2, 3)) == '[2][3]'
    assert dims_str((5,)) == '[5]'
    assert dims_str(()) == ''
