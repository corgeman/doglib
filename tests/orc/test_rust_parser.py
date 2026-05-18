"""
Parser-parity tests: Rust DWARF parser vs pyelftools fallback.

For every input binary we run both production code paths of
``ORC._build_dwarf_cache`` and assert that the resulting
``(_dwarf_vars, _dwarf_types)`` dicts are identical:

  1. Python path  — ``_orc._dwarf_parser_rs`` is temporarily set to ``None``
                    so the fallback pyelftools walk runs.
  2. Rust path    — ``_orc._dwarf_parser_rs`` holds the real extension module.

Running the test through the *production* path (rather than a shadow
re-implementation) means declaration filtering, CACHEABLE_TAGS, and any
future logic changes are automatically covered by both sides.

Test inputs
-----------
- Tier 1 (always): synthetic type-zoo sources covering every notable DWARF
  construct (compiled at session start by conftest fixtures).
- Tier 2 (network, cached): Ubuntu debug packages downloaded from
  ddebs.ubuntu.com; skipped when offline or SKIP_NETWORK_TESTS=1.
- Legacy (preserved): the small inline point/line .o, the challenge.elf
  executable, and the C++ inline .o from the original test suite.

Run from the project root:
    pytest tests/orc/test_rust_parser.py -v
"""
import os
import subprocess
import tempfile
import unittest.mock

import pytest
from pwnlib.context import context


# ── helper: run both production code paths ───────────────────────────────────

def _parse_both_paths(path: str):
    """
    Parse ``path`` via both ``_build_dwarf_cache`` code paths.

    Returns ``(py_vars, py_types, py_local_vars, py_local_types,
               rs_vars, rs_types, rs_local_vars, rs_local_types)``.

    Each run uses an isolated cache directory so neither run reads a stale
    on-disk JSON from the other.

    Calls ``pytest.skip()`` if ``doglib_rs`` is not installed.
    """
    from doglib.orc import _orc as orc_mod
    from doglib.orc import ORC

    if orc_mod._dwarf_parser_rs is None:
        pytest.skip("doglib_rs not installed")

    def _snapshot(elf):
        return (
            dict(elf._dwarf_vars),
            dict(elf._dwarf_types),
            {k: dict(v) for k, v in elf._dwarf_local_vars.items()},
            {k: dict(v) for k, v in elf._dwarf_local_types.items()},
        )

    with tempfile.TemporaryDirectory() as tmp:
        py_cache = os.path.join(tmp, "py")
        rs_cache = os.path.join(tmp, "rs")
        os.makedirs(py_cache)
        os.makedirs(rs_cache)

        # Python fallback path
        with unittest.mock.patch.object(orc_mod, "_dwarf_parser_rs", None):
            with context.local(cache_dir=py_cache):
                elf = ORC(path)
                elf._build_dwarf_cache()
                py_snap = _snapshot(elf)

        # Rust fast path
        with context.local(cache_dir=rs_cache):
            elf = ORC(path)
            elf._build_dwarf_cache()
            rs_snap = _snapshot(elf)

    return (*py_snap, *rs_snap)


def _assert_parity(path: str, label: str = ""):
    """Run parity check and produce a useful diff on failure."""
    (py_vars, py_types, py_lv, py_lt,
     rs_vars, rs_types, rs_lv, rs_lt) = _parse_both_paths(path)
    tag = f" [{label}]" if label else f" [{os.path.basename(path)}]"

    only_py_vars  = set(py_vars)  - set(rs_vars)
    only_rs_vars  = set(rs_vars)  - set(py_vars)
    only_py_types = set(py_types) - set(rs_types)
    only_rs_types = set(rs_types) - set(py_types)

    msgs = []
    if only_py_vars:
        msgs.append(f"vars only in Python{tag}: {sorted(only_py_vars)[:10]}")
    if only_rs_vars:
        msgs.append(f"vars only in Rust{tag}: {sorted(only_rs_vars)[:10]}")
    if only_py_types:
        msgs.append(f"types only in Python{tag}: {sorted(only_py_types)[:20]}")
    if only_rs_types:
        msgs.append(f"types only in Rust{tag}: {sorted(only_rs_types)[:20]}")

    # Also check that offsets agree for the shared keys
    var_offset_diff = {
        k for k in py_vars if k in rs_vars and py_vars[k] != rs_vars[k]
    }
    type_offset_diff = {
        k for k in py_types if k in rs_types and py_types[k] != rs_types[k]
    }
    if var_offset_diff:
        msgs.append(f"var offset mismatch{tag}: {sorted(var_offset_diff)[:10]}")
    if type_offset_diff:
        msgs.append(f"type offset mismatch{tag}: {sorted(type_offset_diff)[:10]}")

    # Local (per-function) maps: both the set of scope names and the entries
    # within each scope must match.
    only_py_scopes = set(py_lt) - set(rs_lt)
    only_rs_scopes = set(rs_lt) - set(py_lt)
    if only_py_scopes:
        msgs.append(f"local-type scopes only in Python{tag}: {sorted(only_py_scopes)[:10]}")
    if only_rs_scopes:
        msgs.append(f"local-type scopes only in Rust{tag}: {sorted(only_rs_scopes)[:10]}")
    for scope in set(py_lt) & set(rs_lt):
        if py_lt[scope] != rs_lt[scope]:
            diff = sorted(set(py_lt[scope]) ^ set(rs_lt[scope]))[:10]
            msgs.append(f"local-type contents differ{tag} in scope '{scope}': {diff}")
    for scope in set(py_lv) & set(rs_lv):
        if py_lv[scope] != rs_lv[scope]:
            diff = sorted(set(py_lv[scope]) ^ set(rs_lv[scope]))[:10]
            msgs.append(f"local-var contents differ{tag} in scope '{scope}': {diff}")

    assert not msgs, "\n".join(msgs)


# ── Tier 1: synthetic type zoo ───────────────────────────────────────────────

def test_parity_type_zoo_c(change_to_test_dir, type_zoo_gcc):
    """Parity on type_zoo.c: bitfields, flex arrays, atomics, fn ptrs, etc."""
    path = os.path.join(os.path.dirname(__file__), type_zoo_gcc)
    _assert_parity(path, "type_zoo_c")


def test_parity_type_zoo_cpp(change_to_test_dir, type_zoo_gpp):
    """Parity on type_zoo.cpp: templates, virtual inheritance, enum class, etc."""
    path = os.path.join(os.path.dirname(__file__), type_zoo_gpp)
    _assert_parity(path, "type_zoo_cpp")


# ── Tier 1: legacy inline binaries (kept from original suite) ────────────────

def test_parity_et_rel(tmp_path):
    """Parity on a relocatable .o (ET_REL) with simple nested structs."""
    pytest.importorskip("doglib_rs")

    src = tmp_path / "test.h"
    src.write_text(
        "typedef struct point { int x; int y; } point;\n"
        "typedef struct line { point a; point b; } line;\n"
    )
    obj = tmp_path / "test.o"
    subprocess.run(
        ["gcc", "-x", "c", "-c", "-g", "-fno-eliminate-unused-debug-types",
         str(src), "-o", str(obj)],
        check=True,
    )
    _assert_parity(str(obj), "et_rel")


def test_parity_et_exec(change_to_test_dir, challenge_gcc):
    """Parity on the compiled challenge.elf (ET_EXEC)."""
    path = os.path.join(os.path.dirname(__file__), challenge_gcc)
    _assert_parity(path, "et_exec")


def test_parity_cpp_inline(tmp_path):
    """Parity on an inline C++ .o with classes, namespaces, and enums."""
    pytest.importorskip("doglib_rs")

    src = tmp_path / "cpp_test.cpp"
    src.write_text(
        "class Animal { public: int legs; char name[32]; };\n"
        "struct Position { float x, y; };\n"
        "namespace game {\n"
        "  class Player { public: Position pos; int health; };\n"
        "}\n"
        "enum Color { RED, GREEN, BLUE };\n"
        "game::Player global_player;\n"
    )
    obj = tmp_path / "cpp_test.o"
    subprocess.run(
        ["g++", "-x", "c++", "-c", "-g", "-fno-eliminate-unused-debug-types",
         str(src), "-o", str(obj)],
        check=True,
    )
    (py_vars, py_types, _py_lv, _py_lt,
     rs_vars, rs_types, _rs_lv, _rs_lt) = _parse_both_paths(str(obj))
    assert rs_vars  == py_vars
    assert rs_types == py_types
    assert "Animal"   in rs_types, "DW_TAG_class_type should be indexed"
    assert "Position" in rs_types
    assert "Player"   in rs_types
    assert "Color"    in rs_types


def test_parity_no_dwarf(tmp_path):
    """Both paths return empty dicts for a binary compiled without -g."""
    pytest.importorskip("doglib_rs")

    src = tmp_path / "nodebug.c"
    src.write_text("int main() { return 0; }\n")
    obj = tmp_path / "nodebug.o"
    subprocess.run(
        ["gcc", "-x", "c", "-c", str(src), "-o", str(obj)],
        check=True,
    )
    (py_vars, py_types, _py_lv, _py_lt,
     rs_vars, rs_types, _rs_lv, _rs_lt) = _parse_both_paths(str(obj))
    assert rs_vars  == py_vars  == {}
    assert rs_types == py_types == {}


# ── Tier 2: Ubuntu ddeb debug packages ───────────────────────────────────────

def _ddeb_params(ddeb_suite):
    """Build pytest parametrize IDs from the ddeb_suite fixture."""
    return [(label, path) for label, path in ddeb_suite]


def test_parity_ddeb(change_to_test_dir, ddeb_suite, request):
    """
    Parametrized parity check over downloaded Ubuntu ddeb debug libraries.

    Each entry in ``ddeb_suite`` is a (label, .so path) pair.  The test is
    skipped entirely when ``ddeb_suite`` is empty (offline or non-Debian host).
    """
    pytest.importorskip("doglib_rs")
    if not ddeb_suite:
        pytest.skip("no ddeb packages available (offline or non-Debian host)")

    failures = []
    for label, path in ddeb_suite:
        try:
            _assert_parity(path, label)
        except AssertionError as exc:
            failures.append(str(exc))

    if failures:
        pytest.fail("\n\n".join(failures))


# Individual ddeb parametrize variant (verbose mode expands each package)
@pytest.mark.parametrize("label,path", [], indirect=False)
def _test_parity_ddeb_parametrized(label, path):  # pragma: no cover
    _assert_parity(path, label)


# ── Fallback-behaviour tests (unchanged from original suite) ─────────────────

def test_rust_parser_exception_fallback(change_to_test_dir, challenge_gcc, monkeypatch):
    """When the Rust parser raises an exception, Python falls back to pyelftools."""
    from doglib.orc import _orc as elf_module
    if elf_module._dwarf_parser_rs is None:
        pytest.skip("Rust parser not installed")

    def mock_parse_raises(_path):
        raise RuntimeError("simulated parser failure")

    monkeypatch.setattr(elf_module._dwarf_parser_rs, "parse_dwarf", mock_parse_raises)

    from doglib.orc import ORC
    elf = ORC(f"./{challenge_gcc}")
    elf._dwarf_parsed = False
    elf._dwarf_vars   = {}
    elf._dwarf_types  = {}
    elf._build_dwarf_cache()
    assert "Basic" in elf._dwarf_types, "Should fall back to pyelftools when Rust raises"


def test_rust_fallback(change_to_test_dir, challenge_gcc, monkeypatch):
    """When the Rust parser returns empty dicts, Python falls back to pyelftools."""
    from doglib.orc import _orc as elf_module
    if elf_module._dwarf_parser_rs is None:
        pytest.skip("Rust parser not installed")

    monkeypatch.setattr(
        elf_module._dwarf_parser_rs, "parse_dwarf", lambda _path: ({}, {}, {}, {})
    )

    from doglib.orc import ORC
    elf = ORC(f"./{challenge_gcc}")
    elf._dwarf_parsed = False
    elf._dwarf_vars   = {}
    elf._dwarf_types  = {}
    elf._build_dwarf_cache()
    assert "Basic" in elf._dwarf_types, "Should fall back to pyelftools when Rust returns empty"
