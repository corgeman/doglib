"""
Tests for ORC setup, built-in types, and ELF hijack patches.

Covers: C64 stdint type sizes, ELF.sym_obj / ELF.resolve_field hijack,
ORCHeader include-dirs / missing-file / invalid-header, _Bool round-trip,
C++ class type labels (DW_TAG_class_type), forward-declaration skipping,
and supplementary DWARF build-ID verification.
"""
import os

import pytest
from elftools.elf.elffile import ELFFile
from pwnlib.exception import PwnlibException

from doglib.orc import ORCHeader, ORCInline, C64


# ============================================================
# C64 built-in type sizes
# ============================================================

def test_c64_stdint_types():
    assert C64.sizeof('uint64_t') == 8
    assert C64.sizeof('uint32_t') == 4
    assert C64.sizeof('uint8_t') == 1
    assert C64.sizeof('int64_t') == 8
    assert C64.sizeof('size_t') == 8
    assert C64.sizeof('ptrdiff_t') == 8


# ============================================================
# ELF hijack patches: sym_obj / resolve_field
# ============================================================

def test_resolve_field_symbol_base(chal_pwn_elf):
    assert chal_pwn_elf.resolve_field('target_sym') == chal_pwn_elf.symbols['target_sym']


def test_resolve_field_with_explicit_struct_name(chal_pwn_elf):
    expected = int(chal_pwn_elf.sym_obj['target_sym'].arr[2].ptr)
    assert chal_pwn_elf.resolve_field('target_sym', 'arr[2].ptr', struct_name='GlobalTest') == expected


def test_resolve_field_invalid_path_raises(chal_pwn_elf):
    with pytest.raises(PwnlibException):
        chal_pwn_elf.resolve_field('target_sym', 'arr[2].does_not_exist')


def test_resolve_field_missing_symbol_raises(chal_pwn_elf):
    with pytest.raises(PwnlibException):
        chal_pwn_elf.resolve_field('does_not_exist', 'arr[0]')


# ============================================================
# ORCHeader / ORCInline setup
# ============================================================

def test_cheader_include_dirs(tmp_path):
    inc = tmp_path / 'include'
    inc.mkdir()
    (inc / 'inner.h').write_text(
        "typedef struct inner {\n"
        "    int field_value;\n"
        "} inner;\n"
    )
    (tmp_path / 'outer.h').write_text(
        '#include "inner.h"\n'
        "typedef struct outer {\n"
        "    inner field;\n"
        "} outer;\n"
    )

    hdr = ORCHeader(str(tmp_path / 'outer.h'), include_dirs=[str(inc)])
    outer = hdr.craft('outer')
    outer.field.field_value = 7

    assert outer.field.field_value.value == 7


def test_cheader_missing_file_raises(tmp_path):
    with pytest.raises(FileNotFoundError):
        ORCHeader(str(tmp_path / 'missing.h'))


def test_cheader_invalid_header_raises():
    import subprocess
    with pytest.raises(subprocess.CalledProcessError):
        ORCInline(
            "typedef struct broken {\n"
            "    int value;\n"
            "    @\n"
            "} broken;\n"
        )


def test_bool_base_type_round_trip():
    hdr = ORCInline(
        "typedef struct boolish {\n"
        "    _Bool flag;\n"
        "} boolish;\n"
    )
    obj = hdr.craft('boolish')

    obj.flag = 0
    assert obj.flag.value is False

    obj.flag = 1
    assert obj.flag.value is True


# ============================================================
# C++ class type labels (DW_TAG_class_type)
# ============================================================

def test_describe_cpp_class_label(change_to_test_dir, challenge_gpp, capsys):
    """describe() labels DW_TAG_class_type as 'class', not 'union'."""
    from doglib.orc import ORC
    elf = ORC(f'./{challenge_gpp}')
    elf.describe('Coords')
    out = capsys.readouterr().out
    assert out.startswith('class ')
    assert 'union' not in out.lower()


def test_get_type_name_cpp_class(change_to_test_dir, challenge_gpp):
    """get_type_name returns 'class Foo' for DW_TAG_class_type, not 'union Foo'."""
    from doglib.orc import ORC
    elf = ORC(f'./{challenge_gpp}')
    die = elf._get_type_die('Coords')
    name = elf._get_type_name(die)
    assert 'class' in name
    assert 'union' not in name


def test_describe_includes_inherited_fields(change_to_test_dir, challenge_gpp, capsys):
    """describe() shows inherited base-class fields for C++ classes."""
    from doglib.orc import ORC
    elf = ORC(f'./{challenge_gpp}')
    elf.describe('Player')
    out = capsys.readouterr().out
    assert 'health' in out
    assert 'id' in out
    assert 'name' in out
    assert 'weapon' in out


# ============================================================
# Context manager / close protocol
# ============================================================

def test_context_manager_protocol(change_to_test_dir, challenge_gcc):
    """__enter__ and __exit__ work; close() clears internal state."""
    from doglib.orc import ORC
    with ORC(f'./{challenge_gcc}') as orc:
        assert orc.sizeof('int') == 4
    assert orc._dwarfinfo is None
    assert orc._resolver is None


def test_get_resolver_no_dwarf_raises(change_to_test_dir, challenge_gcc, monkeypatch):
    """_get_resolver raises RuntimeError when _get_dwarfinfo returns None."""
    from doglib.orc import ORC
    orc = ORC(f'./{challenge_gcc}')
    monkeypatch.setattr(orc, '_get_dwarfinfo', lambda: None)
    monkeypatch.setattr(orc, '_resolver', None)
    with pytest.raises(RuntimeError, match="No DWARF info"):
        orc._get_resolver()


def test_stale_cache_triggers_rebuild(change_to_test_dir, challenge_gcc):
    """A cache file with an old cache_version is discarded and rebuilt."""
    import json
    from pwnlib.context import context
    from doglib.orc import ORC

    elf = ORC(f'./{challenge_gcc}')
    elf._build_dwarf_cache()

    # Locate the cache file using the same key logic as _build_dwarf_cache
    orc_cache_dir = os.path.join(context.cache_dir, 'orc_cache')
    if elf.buildid:
        bid = elf.buildid.hex()
    else:
        import hashlib
        with open(elf.path, 'rb') as f:
            bid = hashlib.sha256(f.read()).hexdigest()[:16]
    cache_file = os.path.join(orc_cache_dir, f'dwarf_{bid}.json')

    # Overwrite with a stale version
    with open(cache_file, 'w') as f:
        json.dump({'cache_version': -1, 'vars': {}, 'types': {}}, f)

    elf._dwarf_parsed = False
    elf._dwarf_vars = {}
    elf._dwarf_types = {}
    elf._build_dwarf_cache()

    assert 'Basic' in elf._dwarf_types


# ============================================================
# Regression: forward-declaration skipping
# ============================================================

def test_declaration_skipping_python_parser():
    """Python parser skips DW_AT_declaration and keeps the full definition."""
    t = ORCInline('''
        struct opaque;
        struct opaque { int x; int y; };
    ''')
    assert t.sizeof('opaque') == 8
    c = t.craft('opaque')
    c.x = 1; c.y = 2
    assert c.x.value == 1
    assert c.y.value == 2


