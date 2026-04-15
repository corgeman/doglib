"""
Tests for DWARFCrafter: string-key escape hatch, dunder-named C fields,
anonymous member iteration, C++ inheritance iteration, and typedef-array regression.

Covers: crafter['field'] read/write, shadowed names (value/items/copy/__init__),
items()/dump()/values() with anonymous members, C++ inherited fields, and
craft() on typedef-array types.
"""
import struct

import pytest

from doglib.orc import ORCInline, DWARFArrayCrafter


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
    """Compile _SHADOWED_H and return an ORCInline instance."""
    return ORCInline(_SHADOWED_H)


def test_string_key_read_shadowed_by_property():
    """crafter['value'] reaches the C field 'value', not the .value property."""
    j = _make_shadowed()
    m = j.craft('shadowed')
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
    fields = struct.unpack_from('<iiiii', raw)
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
    m['items'] = 55
    assert m['items'].value == 55


def test_string_key_and_dot_notation_are_equivalent():
    """For an ordinary field name, crafter['x'] and crafter.x return the same data."""
    j = ORCInline("typedef struct simple { int x; int y; } simple;")
    m = j.craft('simple')
    m.x = 77
    assert m['x'].value == 77       # bracket
    assert m.x.value == 77          # dot — same backing
    m['y'] = 88
    assert m.y.value == 88          # dot sees the bracket write


def test_string_key_chaining():
    """crafter['field'] returns a DWARFCrafter that supports further field access."""
    j = ORCInline("""\
typedef struct inner { int value; int copy; } inner;
typedef struct outer { inner items; int pad; } outer;
""")
    m = j.craft('outer')
    m['items']['value'] = 0x1111
    m['items']['copy'] = 0x2222
    assert m['items']['value'].value == 0x1111
    assert m['items']['copy'].value == 0x2222


# ============================================================
# C struct fields with dunder-like names (e.g. __finish)
# ============================================================

def test_dunder_struct_fields():
    j = ORCInline("""\
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
# Anonymous member iteration (items/dump/values)
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
# C++ inheritance iteration (items on Player)
# ============================================================

def test_dump_includes_inherited_fields(change_to_test_dir, challenge_gpp, capsys):
    """dump() shows inherited base-class fields for C++ classes."""
    from doglib.orc import ORC
    elf = ORC(f'./{challenge_gpp}')
    player = elf.craft('Player')
    player['id'] = 7
    player['health'] = 100
    player.dump()
    out = capsys.readouterr().out
    assert 'id' in out
    assert 'health' in out


def test_items_includes_inherited_fields(change_to_test_dir, challenge_gpp):
    """items() yields inherited base-class fields for C++ classes."""
    from doglib.orc import ORC
    elf = ORC(f'./{challenge_gpp}')
    player = elf.craft('Player')
    names = [name for name, _ in player.items()]
    # Player's own fields
    assert 'health' in names
    # Inherited from Entity
    assert 'id' in names
    assert 'name' in names
    # Inherited from Entity -> Coords (nested, not inherited)
    assert 'pos' in names


# ============================================================
# Regression: typedef-array craft
# ============================================================

def test_craft_typedef_array():
    """craft() on a typedef-array creates a DWARFArrayCrafter, not a plain DWARFCrafter."""
    t = ORCInline('typedef int block_t[8];')
    arr = t.craft('block_t')
    assert isinstance(arr, DWARFArrayCrafter)
    assert len(arr) == 8
    arr[0] = 0xdead
    arr[7] = 0xbeef
    assert arr[0].value == 0xdead
    assert arr[7].value == 0xbeef


def test_craft_typedef_array_struct():
    """craft() on a typedef of an array-of-struct gives a proper array crafter."""
    t = ORCInline('''
        typedef struct { int x; int y; } Point;
        typedef Point PointArray[4];
    ''')
    arr = t.craft('PointArray')
    assert isinstance(arr, DWARFArrayCrafter)
    assert len(arr) == 4
    arr[2].x = 10
    arr[2].y = 20
    assert arr[2].x.value == 10
