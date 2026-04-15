"""
Tests for the Rust DWARF parser (doglib_rs.dwarf_parser).

Verifies that the Rust parser's output matches pyelftools across
ET_REL, ET_EXEC, C++, and glibc inputs. Also tests the Python
fallback path when the Rust parser returns empty results.

Run from the project root:
    pytest tests/orc/test_rust_parser.py
"""
import os
import subprocess

import pytest
from elftools.elf.elffile import ELFFile


_PYELF_CACHEABLE_TAGS = (
    'DW_TAG_variable', 'DW_TAG_structure_type', 'DW_TAG_class_type',
    'DW_TAG_union_type', 'DW_TAG_typedef', 'DW_TAG_enumeration_type',
    'DW_TAG_base_type',
)


def _pyelf_parse(path):
    """Reference parser using pyelftools — mirrors _build_dwarf_cache logic."""
    pe_vars, pe_types = {}, {}
    with open(path, 'rb') as f:
        elf = ELFFile(f)
        if not elf.has_dwarf_info():
            return pe_vars, pe_types
        for CU in elf.get_dwarf_info().iter_CUs():
            for die in CU.iter_DIEs():
                if die.tag in _PYELF_CACHEABLE_TAGS:
                    attr = die.attributes.get('DW_AT_name')
                    if attr:
                        name = attr.value.decode('utf-8', errors='ignore')
                        if die.tag == 'DW_TAG_variable':
                            pe_vars[name] = die.offset
                        else:
                            pe_types[name] = die.offset
    return pe_vars, pe_types


def test_parity_et_rel(tmp_path):
    """Rust parser matches pyelftools on a relocatable .o file (ET_REL)."""
    doglib_rs = pytest.importorskip("doglib_rs")
    dwarf_rs = doglib_rs.dwarf_parser

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

    pe_vars, pe_types = _pyelf_parse(str(obj))
    rs_vars, rs_types = dwarf_rs.parse_dwarf(str(obj))
    assert rs_vars == pe_vars
    assert rs_types == pe_types


def test_parity_et_exec(change_to_test_dir, challenge_gcc):
    """Rust parser matches pyelftools on a linked executable (ET_EXEC)."""
    doglib_rs = pytest.importorskip("doglib_rs")
    dwarf_rs = doglib_rs.dwarf_parser

    path = os.path.join(os.path.dirname(__file__), challenge_gcc)
    pe_vars, pe_types = _pyelf_parse(path)
    rs_vars, rs_types = dwarf_rs.parse_dwarf(path)
    assert rs_vars == pe_vars
    assert rs_types == pe_types


def test_parity_cpp(tmp_path):
    """Rust parser matches pyelftools on a C++ .o with classes and namespaces."""
    doglib_rs = pytest.importorskip("doglib_rs")
    dwarf_rs = doglib_rs.dwarf_parser

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

    pe_vars, pe_types = _pyelf_parse(str(obj))
    rs_vars, rs_types = dwarf_rs.parse_dwarf(str(obj))
    assert rs_vars == pe_vars
    assert rs_types == pe_types
    assert "Animal" in rs_types, "DW_TAG_class_type should be indexed"
    assert "Position" in rs_types
    assert "Player" in rs_types
    assert "Color" in rs_types


_GLIBC_PATH = "/home/corgo/pwn/tools/latest_glibc/libc6_2.23-0ubuntu11.3_amd64.so"


@pytest.mark.skipif(
    not os.path.exists(_GLIBC_PATH),
    reason="glibc test binary not available",
)
def test_parity_glibc():
    """Rust parser matches pyelftools on a real glibc with debug info."""
    doglib_rs = pytest.importorskip("doglib_rs")
    dwarf_rs = doglib_rs.dwarf_parser

    pe_vars, pe_types = _pyelf_parse(_GLIBC_PATH)
    rs_vars, rs_types = dwarf_rs.parse_dwarf(_GLIBC_PATH)
    assert rs_vars == pe_vars
    assert rs_types == pe_types
    assert len(rs_types) > 100, "Expected many types in glibc"


def test_parity_no_dwarf(tmp_path):
    """Rust parser returns empty dicts for a binary with no debug info."""
    doglib_rs = pytest.importorskip("doglib_rs")
    dwarf_rs = doglib_rs.dwarf_parser

    src = tmp_path / "nodebug.c"
    src.write_text("int main() { return 0; }\n")
    obj = tmp_path / "nodebug.o"
    subprocess.run(
        ["gcc", "-x", "c", "-c", str(src), "-o", str(obj)],
        check=True,
    )

    rs_vars, rs_types = dwarf_rs.parse_dwarf(str(obj))
    assert rs_vars == {}
    assert rs_types == {}


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
    elf._dwarf_vars = {}
    elf._dwarf_types = {}
    elf._build_dwarf_cache()
    assert "Basic" in elf._dwarf_types, "Should fall back to pyelftools when Rust raises"


def test_rust_fallback(change_to_test_dir, challenge_gcc, monkeypatch):
    """When the Rust parser returns empty, Python falls back to pyelftools."""
    from doglib.orc import _orc as elf_module
    if elf_module._dwarf_parser_rs is None:
        pytest.skip("Rust parser not installed")

    def mock_parse(_path):
        return ({}, {})

    monkeypatch.setattr(elf_module._dwarf_parser_rs, "parse_dwarf", mock_parse)

    from doglib.orc import ORC
    elf = ORC(f"./{challenge_gcc}")
    elf._dwarf_parsed = False
    elf._dwarf_vars = {}
    elf._dwarf_types = {}
    elf._build_dwarf_cache()
    assert "Basic" in elf._dwarf_types, "Should fall back to pyelftools when Rust returns empty"
