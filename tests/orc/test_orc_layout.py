"""
Tests for ORC layout API: sizeof, offsetof, containerof, field_at.

Covers: sizeof for structs/primitives/arrays/pointers, offsetof (including
multi-dim array paths and nested structs), containerof with VA wrapping,
and field_at (basic fields, mid-field, padding holes, arrays, multidim,
nested structs, unions, anonymous members, OOB, and round-trip inverse).
"""
import pytest


# ============================================================
# sizeof / offsetof / containerof
# ============================================================

def test_sizeof_structs(headers):
    assert headers.sizeof('Basic') == 12
    assert headers.sizeof('ArrayFun') == 32
    assert headers.sizeof('FinalBoss') == 48
    assert headers.sizeof('EdgeCases') == 16


def test_sizeof_primitives(headers):
    assert headers.sizeof('int') == 4
    assert headers.sizeof('char') == 1
    assert headers.sizeof('short') == 2
    assert headers.sizeof('long long') == 8
    assert headers.sizeof('double') == 8
    assert headers.sizeof('unsigned short') == 2
    assert headers.sizeof('unsigned long') == 8


def test_sizeof_arrays(headers):
    assert headers.sizeof('int[100]') == 400
    assert headers.sizeof('char[16]') == 16
    assert headers.sizeof('Basic[3][2]') == 3 * 2 * headers.sizeof('Basic')


def test_sizeof_pointer(headers):
    assert headers.sizeof('int *') == 8


def test_offsetof(headers):
    assert headers.offsetof('Basic', 'a') == 0
    assert headers.offsetof('Basic', 'b') == 4
    assert headers.offsetof('Basic', 'c') == 8
    assert headers.offsetof('FinalBoss', 'matrix') == 8
    assert headers.offsetof('FinalBoss', 'matrix[1][2]') == 28
    assert headers.offsetof('FinalBoss', 'current_hp') == 40
    assert headers.offsetof('BossFight', 'u.data.raw') == 32


def test_offsetof_invalid_raises(headers):
    with pytest.raises(ValueError):
        headers.offsetof('Basic', 'nonexistent')


def test_containerof(headers):
    member_addr = 0x1000 + headers.offsetof('BossFight', 'u')
    base = headers.containerof('BossFight', 'u', member_addr)
    assert base == 0x1000


def test_containerof_va_wrapping(headers):
    mask = (1 << 64) - 1
    result = headers.containerof('Basic', 'b', 0x4)
    assert result == (0x4 - headers.offsetof('Basic', 'b')) & mask


# ============================================================
# field_at
# ============================================================

def test_field_at_basic_fields(headers):
    assert headers.field_at('Basic', 0) == 'a'
    assert headers.field_at('Basic', 4) == 'b'
    assert headers.field_at('Basic', 8) == 'c'


def test_field_at_mid_field(headers):
    assert headers.field_at('Basic', 5) == 'b+1'
    assert headers.field_at('Basic', 7) == 'b+3'
    assert headers.field_at('Basic', 9) == 'c+1'


def test_field_at_struct_padding_hole(headers):
    # Basic has a 3-byte padding hole between 'a' (offset 0..1) and 'b' (offset 4)
    assert headers.field_at('Basic', 1) == '+1'
    # ArrayFun has padding between int[5] (ends at 20) and char* ptr (at 24)
    assert headers.field_at('ArrayFun', 22) == '+22'


def test_field_at_array_indexing(headers):
    assert headers.field_at('ArrayFun', 0) == 'arr[0]'
    assert headers.field_at('ArrayFun', 4) == 'arr[1]'
    assert headers.field_at('ArrayFun', 16) == 'arr[4]'
    assert headers.field_at('ArrayFun', 19) == 'arr[4]+3'
    assert headers.field_at('ArrayFun', 24) == 'ptr'


def test_field_at_multidim_array(headers):
    assert headers.field_at('FinalBoss', 8) == 'matrix[0][0]'
    assert headers.field_at('FinalBoss', 28) == 'matrix[1][2]'
    assert headers.field_at('FinalBoss', 40) == 'current_hp'
    assert headers.field_at('MultiDimTest', 0) == 'grid[0][0]'
    assert headers.field_at('MultiDimTest', 28) == 'grid[1][3]'
    assert headers.field_at('MultiDimTest', 48) == 'cube[0][0][0]'
    assert headers.field_at('MultiDimTest', 62) == 'cube[1][0][2]'


def test_field_at_nested_struct(headers):
    assert headers.field_at('BossFight', 0) == 'b[0].a'
    assert headers.field_at('BossFight', 16) == 'b[1].b'
    # offset 28 is 4 bytes into u (which is UnionMadness), inside u.type (long)
    assert headers.field_at('BossFight', 28) == 'u.type+4'


def test_field_at_union(headers):
    # UnionMadness.data starts at offset 8; the union has overlapping members
    result = headers.field_at('UnionMadness', 8)
    assert isinstance(result, list)
    assert 'data.coords.x' in result
    assert 'data.raw[0]' in result

    result = headers.field_at('UnionMadness', 12)
    assert isinstance(result, list)
    assert 'data.coords.y' in result
    assert 'data.raw[4]' in result


def test_field_at_anonymous_members(headers):
    # AnonMember has a top-level int 'type', then an anonymous union, then an anonymous struct
    assert headers.field_at('AnonMember', 0) == 'type'
    result = headers.field_at('AnonMember', 4)
    assert isinstance(result, list)
    assert 'as_int' in result
    assert 'as_float' in result
    # the anonymous struct's named members are reachable directly
    assert headers.field_at('AnonMember', 8) == 'x'
    assert headers.field_at('AnonMember', 10) == 'y'


def test_field_at_out_of_bounds(headers):
    with pytest.raises(ValueError):
        headers.field_at('Basic', headers.sizeof('Basic'))
    with pytest.raises(ValueError):
        headers.field_at('Basic', 999)
    with pytest.raises(ValueError):
        headers.field_at('Basic', -1)


def test_field_at_union_bitfield_skip():
    """field_at skips bitfield members in a union and finds the regular member."""
    from doglib.orc import ORCInline
    t = ORCInline('union U { int x:4; int raw; };')
    result = t.field_at('U', 0)
    results = [result] if isinstance(result, str) else result
    assert any('raw' in r for r in results)
    assert not any('x' in r for r in results)


def test_field_at_cpp_inheritance(change_to_test_dir, challenge_gpp):
    """field_at resolves fields inherited from a base class via DW_TAG_inheritance."""
    from doglib.orc import ORC
    elf = ORC(f'./{challenge_gpp}')
    # Player inherits Entity; Entity.id is at offset 0
    assert elf.field_at('Player', 0) == 'id'
    # Entity.pos starts at offset 4; pos.x is the first field of Coords
    assert elf.field_at('Player', 4) == 'pos.x'


def test_describe_skips_non_member_children(change_to_test_dir, challenge_gpp, capsys):
    """describe() skips DW_TAG_subprogram children (C++ methods)."""
    from doglib.orc import ORC
    elf = ORC(f'./{challenge_gpp}')
    elf.describe('Monster')
    out = capsys.readouterr().out
    assert 'hp' in out
    # 'attack' is a method, not a data member -- must not appear as a field row
    field_lines = [l for l in out.splitlines() if '0x' in l]
    field_names = {l.split()[-1] for l in field_lines}
    assert 'attack' not in field_names


def test_field_at_inverse_of_offsetof(headers):
    """For each known (type, field), feed offsetof's result into field_at and
    confirm at least one returned path round-trips back to the same offset."""
    cases = [
        ('Basic', 'a'), ('Basic', 'b'), ('Basic', 'c'),
        ('ArrayFun', 'arr[0]'), ('ArrayFun', 'arr[3]'), ('ArrayFun', 'ptr'),
        ('FinalBoss', 'current_state'), ('FinalBoss', 'matrix[0][0]'),
        ('FinalBoss', 'matrix[1][2]'), ('FinalBoss', 'current_hp'),
        ('MultiDimTest', 'grid[2][3]'), ('MultiDimTest', 'cube[1][0][2]'),
        ('BossFight', 'b[0].a'), ('BossFight', 'b[1].c'),
        ('UnionMadness', 'type'),
    ]
    for type_name, path in cases:
        offset = headers.offsetof(type_name, path)
        result = headers.field_at(type_name, offset)
        results = [result] if isinstance(result, str) else result
        # at least one returned path should map back to the same offset
        assert any(headers.offsetof(type_name, r.split('+')[0]) == offset
                   for r in results if not r.startswith('+')), \
            f"field_at({type_name!r}, {offset}) = {result!r} did not round-trip {path!r}"
