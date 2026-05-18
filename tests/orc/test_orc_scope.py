"""Tests for ORC.scope() — per-function type scoping.

A struct/union/typedef declared inside a function body used to land in the
flat global type index, where it could shadow a file-scope type with the same
name. The indexer now routes those to _dwarf_local_types[funcname] instead,
and ORC.scope(funcname) returns a view that resolves type names against that
function's locals first, then falls back to the global index.
"""
import pytest

from doglib.orc import ORC, ScopedORC


# ── func_scope.c — file-scope `struct point`, plus f1 and f2 each declare
#    their own locally-scoped `struct point` with a different layout. ───────

def test_local_types_indexed_per_function(change_to_test_dir, func_scope_gcc):
    orc = ORC(f"./{func_scope_gcc}")
    orc._build_dwarf_cache()
    assert "f1" in orc._dwarf_local_types
    assert "f2" in orc._dwarf_local_types
    assert "point" in orc._dwarf_local_types["f1"]
    assert "point" in orc._dwarf_local_types["f2"]
    # The file-scope point is still globally indexed.
    assert "point" in orc._dwarf_types
    # f1's and f2's local points are distinct DIEs.
    assert orc._dwarf_local_types["f1"]["point"] != orc._dwarf_local_types["f2"]["point"]


def test_scope_returns_scoped_orc(change_to_test_dir, func_scope_gcc):
    orc = ORC(f"./{func_scope_gcc}")
    inner = orc.scope("f1")
    assert isinstance(inner, ScopedORC)


def test_scope_resolves_local_type(change_to_test_dir, func_scope_gcc):
    orc = ORC(f"./{func_scope_gcc}")
    # f1's local point is { char r; } → 1 byte.
    assert orc.scope("f1").sizeof("point") == 1
    # f2's local point is { double d; } → 8 bytes.
    assert orc.scope("f2").sizeof("point") == 8
    # Verify f2's point really has the `d` member.
    assert orc.scope("f2").offsetof("point", "d") == 0


def test_scope_falls_back_to_globals(change_to_test_dir, func_scope_gcc):
    orc = ORC(f"./{func_scope_gcc}")
    inner = orc.scope("f1")
    # `int` isn't a local in f1, so this must fall back to the parent's
    # global type index where the base type lives.
    assert inner.sizeof("int") == 4


def test_unscoped_lookup_hits_file_scope_point(change_to_test_dir, func_scope_gcc):
    """Plain orc.sizeof('point') should resolve to the file-scope struct."""
    orc = ORC(f"./{func_scope_gcc}")
    # struct point { int x; int y; } → 8 bytes
    assert orc.sizeof("point") == 8
    assert orc.offsetof("point", "x") == 0
    assert orc.offsetof("point", "y") == 4


def test_scope_unknown_raises_with_discovery_hint(change_to_test_dir, func_scope_gcc):
    """KeyError message lists real scope names so users can recover from typos."""
    orc = ORC(f"./{func_scope_gcc}")
    with pytest.raises(KeyError, match="f1"):
        orc.scope("nonexistent_function_name")


def test_scoped_orc_repr(change_to_test_dir, func_scope_gcc):
    orc = ORC(f"./{func_scope_gcc}")
    inner = orc.scope("f1")
    r = repr(inner)
    assert "ScopedORC" in r and "f1" in r


def test_scope_shares_state_with_parent(change_to_test_dir, func_scope_gcc):
    """ScopedORC should reuse the parent's cache and DWARFInfo, not duplicate."""
    orc = ORC(f"./{func_scope_gcc}")
    orc._build_dwarf_cache()
    inner = orc.scope("f1")
    assert inner._dwarf_vars is orc._dwarf_vars
    assert inner._dwarf_types is orc._dwarf_types
    assert inner.path == orc.path
    assert inner.bits == orc.bits


def test_rescope_through_parent(change_to_test_dir, func_scope_gcc):
    """Calling .scope() on a ScopedORC rescopes via the parent ORC."""
    orc = ORC(f"./{func_scope_gcc}")
    first = orc.scope("f1")
    second = first.scope("f2")
    assert isinstance(second, ScopedORC)
    assert second._scope == "f2"
    assert second.sizeof("point") == 8  # f2's double, not f1's char


# ── var_shadow.c — local *variable* shadowing (not a local type) ────────────
#
# var_shadow.c declares both `struct globalty` and `struct localty` at file
# scope, and only the *variable* `initial` inside use_local() is local. This
# test ensures the local-var indexing path doesn't regress.

def test_var_shadow_local_var_indexed_under_function(change_to_test_dir, var_shadow_gcc):
    orc = ORC(f"./{var_shadow_gcc}")
    orc._build_dwarf_cache()
    # The local `initial` variable inside use_local should appear under that
    # scope's local_vars (we don't expose this via API in v1, but it must be
    # present for future use).
    assert "use_local" in orc._dwarf_local_vars
    assert "initial" in orc._dwarf_local_vars["use_local"]
    # The file-scope `initial` global is the only one in the global var index.
    assert "initial" in orc._dwarf_vars
