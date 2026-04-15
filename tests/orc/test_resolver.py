"""
Tests targeting uncovered branches in src/doglib/orc/_resolver.py.

Most tests call the resolver methods directly with lightweight fakes so we
don't need to hand-compile binaries just to exercise a single opcode path.
Fakes are built using types.SimpleNamespace; the resolver only reads
`.tag`, `.attributes`, `.value`, `.form`, and a minimal CU interface.
"""
import types
import pytest

from doglib.orc._resolver import DWARFResolver, _decode_uleb128
from doglib.orc import ORCInline, ORC


# ============================================================
# Helpers / fake-DIE builder
# ============================================================

def _attr(value, form='DW_FORM_data4'):
    return types.SimpleNamespace(value=value, form=form)


def _die(tag, attrs=None, children=None):
    """Minimal DIE-like namespace for resolver unit tests."""
    attributes = attrs or {}
    _children = children or []
    ns = types.SimpleNamespace(
        tag=tag,
        attributes=attributes,
    )
    ns.iter_children = lambda: iter(_children)
    return ns


def _resolver(bits=64):
    return DWARFResolver(dwarfinfo=None, bits=bits)


# ============================================================
# §1 — _decode_uleb128
# ============================================================

def test_uleb128_single_byte():
    assert _decode_uleb128([0x05]) == 5

def test_uleb128_zero():
    assert _decode_uleb128([0x00]) == 0

def test_uleb128_multibyte_canonical():
    # 0xe5 0x8e 0x26 == 624485 (canonical DWARF example)
    assert _decode_uleb128([0xe5, 0x8e, 0x26]) == 624485

def test_uleb128_empty_returns_zero():
    assert _decode_uleb128([]) == 0

def test_uleb128_stops_at_terminator():
    # first byte is terminal (high bit clear), trailing bytes are ignored
    assert _decode_uleb128([0x10, 0xff, 0xff]) == 0x10


# ============================================================
# §2 — get_die_from_attr: missing attribute → None
# ============================================================

def test_get_die_from_attr_missing_returns_none():
    resolver = _resolver()
    die = _die('DW_TAG_structure_type', attrs={})
    assert resolver.get_die_from_attr(die, 'DW_AT_type') is None


# ============================================================
# §4 — bit-field warning in parse_member_offset
# ============================================================

def test_bitfield_warning_emitted(caplog):
    """parse_member_offset warns when DW_AT_bit_size is present."""
    import logging
    resolver = _resolver()
    member = _die('DW_TAG_member', attrs={
        'DW_AT_bit_size': _attr(4),
        'DW_AT_name': _attr(b'x'),
        'DW_AT_data_member_location': _attr(0),
    })
    with caplog.at_level(logging.WARNING):
        offset = resolver.parse_member_offset(member)
    assert offset == 0
    assert any('bit-field' in r.message for r in caplog.records)

def test_bitfield_data_bit_offset_warning(caplog):
    """parse_member_offset warns when DW_AT_data_bit_offset is present."""
    import logging
    resolver = _resolver()
    member = _die('DW_TAG_member', attrs={
        'DW_AT_data_bit_offset': _attr(0),
        'DW_AT_name': _attr(b'y'),
        'DW_AT_data_member_location': _attr(8),
    })
    with caplog.at_level(logging.WARNING):
        offset = resolver.parse_member_offset(member)
    assert offset == 8
    assert any('bit-field' in r.message for r in caplog.records)

def test_bitfield_anonymous_name_in_warning(caplog):
    """Bit-field member with no DW_AT_name uses '<anonymous>' in the warning."""
    import logging
    resolver = _resolver()
    member = _die('DW_TAG_member', attrs={
        'DW_AT_bit_size': _attr(3),
        'DW_AT_data_member_location': _attr(0),
    })
    with caplog.at_level(logging.WARNING):
        resolver.parse_member_offset(member)
    assert any('<anonymous>' in r.message for r in caplog.records)


# ============================================================
# §5 — exprloc / DW_FORM_block in parse_member_offset
# ============================================================

def _member_with_expr(expr):
    """Return a fake member DIE whose data_member_location is a list expr."""
    return _die('DW_TAG_member', attrs={
        'DW_AT_data_member_location': _attr(expr),
    })

def _member_with_bytes_expr(expr_bytes):
    """Same but value is bytes (covers the 'bytes' branch of isinstance)."""
    return _die('DW_TAG_member', attrs={
        'DW_AT_data_member_location': _attr(expr_bytes),
    })

def test_exprloc_empty_list():
    assert _resolver().parse_member_offset(_member_with_expr([])) == 0

def test_exprloc_empty_bytes():
    assert _resolver().parse_member_offset(_member_with_bytes_expr(b'')) == 0

def test_exprloc_plus_uconst_simple():
    # DW_OP_plus_uconst 16  →  [0x23, 0x10]
    assert _resolver().parse_member_offset(_member_with_expr([0x23, 0x10])) == 16

def test_exprloc_plus_uconst_multibyte():
    # DW_OP_plus_uconst 624485  →  [0x23, 0xe5, 0x8e, 0x26]
    assert _resolver().parse_member_offset(_member_with_expr([0x23, 0xe5, 0x8e, 0x26])) == 624485

def test_exprloc_constu():
    # DW_OP_constu 32  →  [0x10, 0x20]
    assert _resolver().parse_member_offset(_member_with_expr([0x10, 0x20])) == 32

def test_exprloc_lit0():
    assert _resolver().parse_member_offset(_member_with_expr([0x30])) == 0

def test_exprloc_lit7():
    assert _resolver().parse_member_offset(_member_with_expr([0x30 + 7])) == 7

def test_exprloc_lit31():
    assert _resolver().parse_member_offset(_member_with_expr([0x4f])) == 31

def test_exprloc_const1u():
    # DW_OP_const1u 0xff  →  [0x08, 0xff]
    assert _resolver().parse_member_offset(_member_with_expr([0x08, 0xff])) == 255

def test_exprloc_const2u():
    # DW_OP_const2u → little-endian [lo, hi]
    assert _resolver().parse_member_offset(_member_with_expr([0x0a, 0x34, 0x12])) == 0x1234

def test_exprloc_const4u():
    assert _resolver().parse_member_offset(_member_with_expr(
        [0x0c, 0x78, 0x56, 0x34, 0x12])) == 0x12345678

def test_exprloc_bytes_plus_uconst():
    # Same as list version but value is bytes
    assert _resolver().parse_member_offset(_member_with_bytes_expr(bytes([0x23, 0x10]))) == 16

def test_exprloc_unknown_op_returns_zero_with_warning(caplog):
    import logging
    with caplog.at_level(logging.WARNING):
        result = _resolver().parse_member_offset(_member_with_expr([0x99]))
    assert result == 0
    assert any('Unhandled' in r.message for r in caplog.records)

def test_exprloc_const2u_truncated_falls_through_to_warning(caplog):
    """const2u with only 1 operand byte misses the len check and hits warning."""
    import logging
    with caplog.at_level(logging.WARNING):
        result = _resolver().parse_member_offset(_member_with_expr([0x0a, 0x34]))
    # Too short for const2u (needs 3 bytes), should warn and return 0
    assert result == 0
    assert any('Unhandled' in r.message or 'Unhandled' in r.message
               for r in caplog.records)


# ============================================================
# §6 — DW_AT_count in get_array_subranges (clang binary)
# ============================================================

def test_clang_array_sizeof(change_to_test_dir, challenge_clang):
    """Clang emits DW_AT_count; verify sizeof/offsetof still work correctly."""
    elf = ORC(f'./{challenge_clang}')
    # ArrayFun: int arr[5] (20 bytes) + char* ptr (8 bytes) + 4 bytes padding = 32
    assert elf.sizeof('ArrayFun') == 32
    assert elf.offsetof('MultiDimTest', 'grid[1][3]') == 28


def test_clang_array_subranges_uses_count(change_to_test_dir, challenge_clang):
    """Directly verify that the DW_AT_count branch is exercised by clang output."""
    elf = ORC(f'./{challenge_clang}')
    elf._build_dwarf_cache()
    # Find the ArrayFun.arr type DIE (an array) and inspect its subranges.
    arr_off = elf._dwarf_types.get('ArrayFun')
    if arr_off is None:
        pytest.skip("ArrayFun not in DWARF types (unexpected)")
    struct_die = elf._get_die(arr_off)
    # Walk children to find the 'arr' member
    arr_member = None
    for child in struct_die.iter_children():
        name_attr = child.attributes.get('DW_AT_name')
        if name_attr and name_attr.value == b'arr':
            arr_member = child
            break
    assert arr_member is not None
    arr_type_die = elf._get_die_from_attr(arr_member, 'DW_AT_type')
    subranges = elf._get_array_subranges(arr_type_die)
    assert subranges == [5]


# ============================================================
# §7 — get_byte_size with None die
# ============================================================

def test_get_byte_size_none_returns_zero_with_warning(caplog):
    import logging
    with caplog.at_level(logging.WARNING):
        result = _resolver().get_byte_size(None)
    assert result == 0
    assert any('None die' in r.message for r in caplog.records)


# ============================================================
# §8 — get_byte_size empty subrange (subrange_start past end)
# ============================================================

def test_get_byte_size_subrange_start_past_end():
    """get_byte_size returns 0 when subrange_start >= number of dimensions."""
    t = ORCInline('struct S { int grid[2][3]; };')
    t._build_dwarf_cache()
    struct_off = t._dwarf_types['S']
    struct_die = t._get_die(struct_off)
    # Find the grid member
    for child in struct_die.iter_children():
        if child.attributes.get('DW_AT_name') and child.attributes['DW_AT_name'].value == b'grid':
            array_die = t._get_die_from_attr(child, 'DW_AT_type')
            break
    # subrange_start=2 means both dims consumed → no remaining dims → 0
    assert t._get_byte_size(array_die, subrange_start=2) == 0


def test_get_byte_size_flexible_array_member():
    """Flexible array member int arr[] has no subrange → get_byte_size returns 0."""
    t = ORCInline('struct F { int x; int arr[]; };')
    t._build_dwarf_cache()
    struct_off = t._dwarf_types['F']
    struct_die = t._get_die(struct_off)
    arr_die = None
    for child in struct_die.iter_children():
        name = child.attributes.get('DW_AT_name')
        if name and name.value == b'arr':
            arr_die = t._get_die_from_attr(child, 'DW_AT_type')
            break
    assert arr_die is not None
    assert t._get_byte_size(arr_die) == 0


# ============================================================
# §9 — get_byte_size fallback for pointer / enum / unknown tag
# ============================================================

def test_get_byte_size_pointer_fallback_64():
    r = _resolver(bits=64)
    die = _die('DW_TAG_pointer_type', attrs={})
    assert r.get_byte_size(die) == 8

def test_get_byte_size_pointer_fallback_32():
    r = _resolver(bits=32)
    die = _die('DW_TAG_pointer_type', attrs={})
    assert r.get_byte_size(die) == 4

def test_get_byte_size_enum_fallback():
    r = _resolver()
    die = _die('DW_TAG_enumeration_type', attrs={})
    assert r.get_byte_size(die) == 4

def test_get_byte_size_unknown_tag_warns(caplog):
    import logging
    r = _resolver()
    die = _die('DW_TAG_subroutine_type', attrs={})
    with caplog.at_level(logging.WARNING):
        result = r.get_byte_size(die)
    assert result == 0
    assert any('Could not determine byte size' in rec.message for rec in caplog.records)


# ============================================================
# §10 — get_type_name(None) → 'void'
# ============================================================

def test_get_type_name_none_is_void():
    assert _resolver().get_type_name(None) == 'void'


# ============================================================
# §11 — get_type_name typedef short-circuit
# ============================================================

def test_get_type_name_typedef_returns_name():
    """get_type_name returns the typedef name before unwrapping."""
    t = ORCInline('typedef int my_t; struct S { my_t x; };')
    t._build_dwarf_cache()
    struct_off = t._dwarf_types['S']
    struct_die = t._get_die(struct_off)
    # Find the member type (a typedef DIE)
    for child in struct_die.iter_children():
        if child.attributes.get('DW_AT_name') and child.attributes['DW_AT_name'].value == b'x':
            member_type = t._get_die_from_attr(child, 'DW_AT_type')
            break
    assert t._get_type_name(member_type) == 'my_t'

def test_describe_shows_typedef_name(capsys):
    """describe() uses the typedef name for member types, not the underlying type."""
    t = ORCInline('typedef int my_t; struct S { my_t x; };')
    t.describe('S')
    out = capsys.readouterr().out
    assert 'my_t' in out


# ============================================================
# §12 + §13 — get_type_name void* (None after unwrap) and pointer branch
# ============================================================

def test_get_type_name_void_pointer():
    """get_type_name of a void* member returns 'void*'."""
    t = ORCInline('struct V { void *p; };')
    t._build_dwarf_cache()
    struct_off = t._dwarf_types['V']
    struct_die = t._get_die(struct_off)
    for child in struct_die.iter_children():
        name = child.attributes.get('DW_AT_name')
        if name and name.value == b'p':
            ptr_die = t._get_die_from_attr(child, 'DW_AT_type')
            break
    assert t._get_type_name(ptr_die) == 'void*'

def test_get_type_name_char_pointer(headers, capsys):
    """describe('ArrayFun') shows 'char*' for the ptr member."""
    headers.describe('ArrayFun')
    out = capsys.readouterr().out
    assert 'char*' in out

def test_get_type_name_pointer_direct(headers):
    """Directly resolve the ptr member type and assert get_type_name returns 'char*'."""
    headers._build_dwarf_cache()
    struct_off = headers._dwarf_types['ArrayFun']
    struct_die = headers._get_die(struct_off)
    for child in struct_die.iter_children():
        name = child.attributes.get('DW_AT_name')
        if name and name.value == b'ptr':
            ptr_die = headers._get_die_from_attr(child, 'DW_AT_type')
            break
    assert headers._get_type_name(ptr_die) == 'char*'
