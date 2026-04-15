"""
Tests for supplementary DWARF support (.gnu_debugaltlink / dwz -m).

All tests require ``dwz`` on PATH; the ``type_zoo_dwz`` fixture skips
automatically when it is not available.

Checks that the ORC Python-fallback path, the Rust parser, and the crafter
all work correctly when type information lives in a .dwz supplementary file.
"""
import pytest

from doglib.orc import ORC


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

_SRC_SUP = 1


def _is_from_sup(ref) -> bool:
    """DieRef tuples/lists are (offset, source); source==1 means supplementary."""
    return ref[1] == _SRC_SUP


def _parse_both(path, tmp_path):
    """Return (py_types, py_vars, rs_types, rs_vars) via both production paths."""
    import pwnlib.context as ctx
    import os, contextlib

    # Redirect the cache dir so both runs start cold and don't share state.
    cache_dir = str(tmp_path / "orc_cache_both")
    os.makedirs(cache_dir, exist_ok=True)

    def _fresh_orc(use_rust: bool):
        orc = ORC(path)
        orc._dwarf_parsed = False
        orc._dwarf_vars = {}
        orc._dwarf_types = {}

        if not use_rust:
            import doglib.orc._orc as mod
            orig = mod._dwarf_parser_rs
            mod._dwarf_parser_rs = None
            try:
                with ctx.context.local(cache_dir=cache_dir + ("_py" if not use_rust else "_rs")):
                    orc._build_dwarf_cache()
            finally:
                mod._dwarf_parser_rs = orig
        else:
            with ctx.context.local(cache_dir=cache_dir + "_rs"):
                orc._build_dwarf_cache()
        return orc._dwarf_types.copy(), orc._dwarf_vars.copy()

    try:
        from doglib_rs import dwarf_parser as _rs  # noqa: F401
        rs_available = True
    except ImportError:
        rs_available = False

    py_types, py_vars = _fresh_orc(use_rust=False)
    if rs_available:
        rs_types, rs_vars = _fresh_orc(use_rust=True)
    else:
        rs_types, rs_vars = None, None

    return py_types, py_vars, rs_types, rs_vars


# ---------------------------------------------------------------------------
# Structure tests
# ---------------------------------------------------------------------------

def test_has_debugaltlink_section(type_zoo_dwz):
    """Fixture binary must actually have .gnu_debugaltlink (sanity check)."""
    import subprocess
    result = subprocess.run(["readelf", "-S", type_zoo_dwz], capture_output=True, text=True)
    assert ".gnu_debugaltlink" in result.stdout


def test_supplementary_types_present(type_zoo_dwz):
    """Core types from type_zoo.c should appear in the DWARF cache."""
    orc = ORC(type_zoo_dwz)
    orc._build_dwarf_cache()
    for name in ("Simple", "Bitfield", "Node"):
        assert name in orc._dwarf_types, f"'{name}' not found in _dwarf_types"


def test_supplementary_offsets_are_tagged(type_zoo_dwz):
    """Supplementary type refs must carry source == SRC_SUP."""
    orc = ORC(type_zoo_dwz)
    orc._build_dwarf_cache()
    for name in ("Simple", "Bitfield", "Node"):
        ref = orc._dwarf_types[name]
        assert _is_from_sup(ref), (
            f"'{name}' ref {ref!r} is not tagged as supplementary — "
            "_get_die routing will fail"
        )


def test_supplementary_vars_present(type_zoo_dwz):
    """Top-level variables declared in type_zoo.c should appear in _dwarf_vars."""
    orc = ORC(type_zoo_dwz)
    orc._build_dwarf_cache()
    for name in ("g_simple", "g_bitfield"):
        assert name in orc._dwarf_vars, f"'{name}' not found in _dwarf_vars"


# ---------------------------------------------------------------------------
# sizeof / describe
# ---------------------------------------------------------------------------

def test_sizeof_simple(type_zoo_dwz):
    orc = ORC(type_zoo_dwz)
    assert orc.sizeof("Simple") == 8


def test_sizeof_bitfield(type_zoo_dwz):
    orc = ORC(type_zoo_dwz)
    assert orc.sizeof("Bitfield") == 4


def test_sizeof_node(type_zoo_dwz):
    orc = ORC(type_zoo_dwz)
    assert orc.sizeof("Node") == 16


def test_describe_simple(type_zoo_dwz, capsys):
    orc = ORC(type_zoo_dwz)
    orc.describe("Simple")
    out = capsys.readouterr().out
    assert "Simple" in out
    assert "int" in out
    assert "x" in out
    assert "y" in out


# ---------------------------------------------------------------------------
# craft / assign
# ---------------------------------------------------------------------------

def test_craft_simple_basic(type_zoo_dwz):
    orc = ORC(type_zoo_dwz)
    c = orc.craft("Simple")
    assert len(c) == 8
    c.x = 42
    c.y = 99
    assert c.x.value == 42
    assert c.y.value == 99


def test_craft_simple_bytes(type_zoo_dwz):
    import struct as _struct
    orc = ORC(type_zoo_dwz)
    c = orc.craft("Simple")
    c.x = 1
    c.y = 2
    raw = bytes(c)
    assert len(raw) == 8
    x, y = _struct.unpack_from("<ii", raw)
    assert x == 1
    assert y == 2


def test_craft_bitfield_size(type_zoo_dwz):
    orc = ORC(type_zoo_dwz)
    c = orc.craft("Bitfield")
    assert len(c) == 4


def test_craft_node_next_field(type_zoo_dwz):
    """Node.next is a pointer — crafter should reflect pointer size (8 bytes)."""
    orc = ORC(type_zoo_dwz)
    c = orc.craft("Node")
    assert len(c) == 16
    # 'val' is an int at offset 0; 'next' is a pointer at offset 8
    c.val = 7
    assert c.val.value == 7


# ---------------------------------------------------------------------------
# Parity: Python fallback vs Rust parser
# ---------------------------------------------------------------------------

def test_parity_type_names(type_zoo_dwz, tmp_path):
    """Python and Rust parsers must discover exactly the same type names."""
    py_types, _, rs_types, _ = _parse_both(type_zoo_dwz, tmp_path)
    if rs_types is None:
        pytest.skip("doglib_rs not installed")

    only_py = set(py_types) - set(rs_types)
    only_rs = set(rs_types) - set(py_types)
    assert not only_py, f"Types only in Python parser: {only_py}"
    assert not only_rs, f"Types only in Rust parser: {only_rs}"


def test_parity_var_names(type_zoo_dwz, tmp_path):
    """Python and Rust parsers must discover exactly the same variable names."""
    _, py_vars, _, rs_vars = _parse_both(type_zoo_dwz, tmp_path)
    if rs_vars is None:
        pytest.skip("doglib_rs not installed")

    only_py = set(py_vars) - set(rs_vars)
    only_rs = set(rs_vars) - set(py_vars)
    assert not only_py, f"Vars only in Python parser: {only_py}"
    assert not only_rs, f"Vars only in Rust parser: {only_rs}"


def test_parity_offsets(type_zoo_dwz, tmp_path):
    """Type offsets from both parsers must agree (including SUP_OFFSET_BIT tag)."""
    py_types, _, rs_types, _ = _parse_both(type_zoo_dwz, tmp_path)
    if rs_types is None:
        pytest.skip("doglib_rs not installed")

    mismatches = [
        (name, py_types[name], rs_types[name])
        for name in set(py_types) & set(rs_types)
        if py_types[name] != rs_types[name]
    ]
    assert not mismatches, (
        f"{len(mismatches)} offset mismatch(es); first 5: {mismatches[:5]}"
    )
