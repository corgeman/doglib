"""Regression test for variable-name shadowing between file-scope globals
and function-local variables. See ``var_shadow.c``.

The DWARF tree puts the file-scope ``initial`` (``struct globalty``) at
CU scope and the local ``initial`` (``struct localty``) inside the
``use_local`` subprogram.  Before the fix, the parser indexed both into
a flat name -> DIE map with last-write-wins, so ``_dwarf_vars['initial']``
could resolve to the local — meaning ``ELF.symo['initial']`` returned the
right address but the wrong type.
"""
from pwnlib.elf.elf import ELF
from doglib.orc import ORC
import doglib._hijack  # noqa: F401 — patches symo onto ELF

from test_rust_parser import _parse_both_paths


def _resolve_var_type_name(orc: ORC, name: str) -> str:
    orc._build_dwarf_cache()
    ref = orc._dwarf_vars[name]
    var_die = orc._get_die(ref)
    type_die = orc._get_die_from_attr(var_die, 'DW_AT_type')
    return orc._get_type_name(orc._unwrap_type(type_die))


def test_var_shadow_parity(change_to_test_dir, var_shadow_gcc):
    """Both parsers agree, and 'initial' is indexed under the global type."""
    (py_vars, py_types, _py_lv, _py_lt,
     rs_vars, rs_types, _rs_lv, _rs_lt) = _parse_both_paths(f"./{var_shadow_gcc}")
    assert py_vars == rs_vars
    assert py_types == rs_types
    assert "initial" in py_vars
    assert "globalty" in py_types
    assert "localty" in py_types  # type is still indexed even though the var isn't


def test_var_shadow_type_python(change_to_test_dir, var_shadow_gcc, monkeypatch):
    """Python fallback resolves 'initial' to struct globalty, not localty."""
    from doglib.orc import _orc as orc_mod
    monkeypatch.setattr(orc_mod, "_dwarf_parser_rs", None)
    orc = ORC(f"./{var_shadow_gcc}")
    assert _resolve_var_type_name(orc, "initial") == "struct globalty"


def test_var_shadow_type_rust(change_to_test_dir, var_shadow_gcc):
    """Rust parser resolves 'initial' to struct globalty, not localty."""
    from doglib.orc import _orc as orc_mod
    if orc_mod._dwarf_parser_rs is None:
        import pytest
        pytest.skip("doglib_rs not installed")
    orc = ORC(f"./{var_shadow_gcc}")
    assert _resolve_var_type_name(orc, "initial") == "struct globalty"


def test_var_shadow_symo(change_to_test_dir, var_shadow_gcc):
    """User-visible bug: ELF.symo['initial'] returns the globalty type."""
    elf = ELF(f"./{var_shadow_gcc}", checksec=False)
    addr_obj = elf.symo["initial"]
    type_die = elf.orc._get_die(addr_obj._type_die_offset)
    type_name = elf.orc._get_type_name(elf.orc._unwrap_type(type_die))
    assert type_name == "struct globalty"
