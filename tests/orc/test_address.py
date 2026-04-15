"""
Tests for DWARFAddress and DWARFArray (_address.py).

Covers address arithmetic, VA-space wrapping, pointer indexing,
array iteration and slicing.

Run from the project root:
    pytest tests/orc/test_address.py
"""
import pytest
from pwnlib.util.packing import p64

from doglib.orc import DWARFAddress


# ============================================================
# DWARFAddress repr & sym_obj
# ============================================================

def test_dwarf_address_repr(chal_pwn_elf):
    r = repr(chal_pwn_elf.sym_obj['target_sym'])
    assert 'DWARFAddress' in r
    assert 'type=' in r


def test_sym_obj_contains(chal_pwn_elf):
    assert 'target_sym' in chal_pwn_elf.sym_obj
    assert 'nonexistent_var' not in chal_pwn_elf.sym_obj


# ============================================================
# DWARFAddress arithmetic
# ============================================================

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
# DWARFArray iteration, slice, len
# ============================================================

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
# DWARFAddress.__repr__ exception fallback
# ============================================================

# ============================================================
# DWARFAddress.__getattr__ dunder early-exit guard
# ============================================================

def test_getattr_dunder_guard(headers):
    """__getattr__ raises AttributeError immediately for dunder names."""
    basic = headers.cast('Basic', 0x1000)
    with pytest.raises(AttributeError):
        _ = getattr(basic, '__nonexistent_dunder__')


# ============================================================
# DWARFAddress.__repr__ exception fallback
# ============================================================

def test_dwarf_address_repr_fallback(headers):
    """repr() falls back to type=? when the type DIE offset is invalid."""
    from doglib.orc import DWARFAddress
    bogus = DWARFAddress(0x1000, headers, 0x7FFFFFFF)
    r = repr(bogus)
    assert 'DWARFAddress' in r
    assert 'type=?' in r


# ============================================================
# DWARFAddress.__getattr__ pointer barrier
# ============================================================

def test_getattr_through_pointer_raises(headers):
    """Dot-access through an unresolved pointer raises AttributeError."""
    af = headers.cast('ArrayFun', 0x5000)
    ptr_field = af.ptr   # char* — a pointer-typed DWARFAddress
    with pytest.raises(AttributeError):
        _ = ptr_field.some_subfield


# ============================================================
# DWARFAddress.__getattr__ field not found in struct
# ============================================================

def test_getattr_missing_field_in_struct(headers):
    """AttributeError when field name does not exist in the struct."""
    basic = headers.cast('Basic', 0x1000)
    with pytest.raises(AttributeError, match="not found in struct"):
        _ = basic.not_a_real_field


# ============================================================
# DWARFAddress.__getitem__ non-int index
# ============================================================

def test_getitem_non_int_index_on_dwarf_address(headers):
    """TypeError when indexing a DWARFAddress with a non-integer."""
    basic = headers.cast('Basic', 0x1000)
    # Make it look like an array type via a field so we reach __getitem__
    # Actually use a direct array-type cast to reach the array branch:
    from doglib.orc import ORCInline
    t = ORCInline("struct A { int arr[4]; };")
    a = t.cast('A', 0x1000)
    arr_addr = a.arr   # DWARFAddress pointing at int[4] array type
    with pytest.raises(TypeError, match="Array indices must be integers"):
        _ = arr_addr["x"]


# ============================================================
# DWARFAddress.__getitem__ void* fallback (no element type)
# ============================================================

def test_getitem_void_pointer_fallback():
    """Indexing a void* uses bits//8 as element size and returns a plain int."""
    from doglib.orc import ORCInline
    t = ORCInline("struct S { void *vp; };")
    s = t.cast('S', 0x2000)
    vp = s.vp           # DWARFAddress with DW_TAG_pointer_type, no DW_AT_type
    result = vp[3]
    expected = 0x2000 + 3 * (t.bits // 8)
    assert int(result) == expected
    # Returns a plain int, not a DWARFAddress
    assert type(result) is int


# ============================================================
# DWARFAddress.__getitem__ exhausted subranges (defensive branch)
# ============================================================

def test_getitem_exhausted_subranges_raises(headers):
    """TypeError when subrange_start is beyond the array's actual dimensions.

    This is a defensive branch that is effectively unreachable from the normal
    public API — the normal multi-dim path always transitions to an elem-type
    DWARFAddress before exhausting subranges.
    """
    from doglib.orc import DWARFAddress
    # Get a DWARFAddress pointing at int[3][4] (MultiDimTest.grid field)
    mt = headers.cast('MultiDimTest', 0x1000)
    grid_addr = mt.grid   # DWARFAddress with array type, subrange_start=0
    # Construct one with subrange_start beyond the 2 subranges
    bogus = DWARFAddress(0x1000, headers, grid_addr._type_die_offset, subrange_start=5)
    with pytest.raises(TypeError, match="No more array dimensions"):
        _ = bogus[0]


# ============================================================
# DWARFAddress.__getitem__ multi-dim: the subrange_start+1 branch
# ============================================================

def test_getitem_multidim_intermediate_address(headers):
    """Multi-dim array indexing advances subrange_start on intermediate dims.

    mt.grid is a DWARFAddress over int[3][4]. Indexing it once (remaining_len=2)
    must hit the previously-uncovered 'return DWARFAddress(..., subrange_start+1)'
    branch. The second index then resolves to the final int address.
    """
    mt = headers.cast('MultiDimTest', 0x1000)
    # First index: remaining_len=2 > 1 → hits the new branch
    row = mt.grid[1]
    assert isinstance(row, DWARFAddress)
    # Second index: remaining_len=1 → final element address
    cell = row[2]
    assert isinstance(cell, DWARFAddress)
    # Address should be base + row_stride*1 + elem_size*2
    # int[3][4]: row_stride = 4*4 = 16, elem_size = 4
    assert int(cell) == 0x1000 + 1 * 4 * 4 + 2 * 4

    # Chained form
    cell2 = mt.grid[2][3]
    assert int(cell2) == 0x1000 + 2 * 4 * 4 + 3 * 4


# ============================================================
# DWARFArray.__getitem__ non-int index
# ============================================================

def test_dwarf_array_non_int_index_raises(headers):
    """TypeError when indexing a DWARFArray with a non-integer."""
    arr = headers.cast('int[4]', 0x1000)   # returns DWARFArray
    with pytest.raises(TypeError, match="Array indices must be integers"):
        _ = arr["x"]


# ============================================================
# DWARFArray.__repr__
# ============================================================

def test_dwarf_array_repr_bounded(headers):
    arr = headers.cast('int[4]', 0x1000)
    r = repr(arr)
    assert 'DWARFArray' in r
    assert '[4]' in r


def test_dwarf_array_repr_unbounded(headers):
    ptr = headers.cast('int *', 0x2000)
    r = repr(ptr)
    assert 'DWARFArray' in r
    assert '*' in r
