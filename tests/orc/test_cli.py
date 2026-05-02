"""
Tests for the `dog orc` CLI subcommand.

Drives the registered argparse handlers directly via `args.func(args)`,
capturing stdout/stderr. The handlers are wrapped by `_safe`, so user-input
errors call `sys.exit(2)` — those tests use pytest.raises(SystemExit).
"""
import argparse
import io
import sys

import pytest

from doglib.commandline import orc as orc_cli


def _build_parser():
    parser = argparse.ArgumentParser()
    sub = parser.add_subparsers(dest="command")
    orc_cli.register(sub)
    return parser


def _run(argv, monkeypatch=None, stdin=None):
    """Parse `argv` (under the 'orc' subcommand) and dispatch.
    Returns (stdout, stderr). Re-raises SystemExit so callers can assert."""
    parser = _build_parser()
    args = parser.parse_args(["orc"] + argv)

    out = io.StringIO()
    err = io.StringIO()
    old_out, old_err = sys.stdout, sys.stderr
    sys.stdout, sys.stderr = out, err
    try:
        if stdin is not None:
            old_stdin = sys.stdin
            sys.stdin = io.StringIO(stdin)
        try:
            args.func(args)
        finally:
            if stdin is not None:
                sys.stdin = old_stdin
    finally:
        sys.stdout, sys.stderr = old_out, old_err
    return out.getvalue(), err.getvalue()


# ============================================================
# CTypes default (no source flag)
# ============================================================

def test_sizeof_primitive_ctypes():
    out, _ = _run(["sizeof", "int[100]"])
    assert out.strip() == "400"


def test_sizeof_bits_override():
    out, _ = _run(["sizeof", "-b", "32", "long"])
    assert out.strip() == "4"


def test_offsetof_one_arg_dotpath():
    out, _ = _run(["offsetof", "_IO_FILE._fileno"])
    assert out.strip() == "0x70"


def test_describe_ctypes_FILE():
    out, _ = _run(["describe", "FILE"])
    assert "struct FILE" in out
    assert "_fileno" in out
    assert "0x70" in out


def test_field_at_ctypes():
    out, _ = _run(["field_at", "_IO_FILE", "0x70"])
    assert out.strip() == "_fileno"


def test_resolve_type():
    out, _ = _run(["resolve_type", "size_t"])
    assert "long unsigned int" in out


def test_containerof():
    # base = member_addr - offsetof
    # _IO_FILE._fileno is at 0x70; given 0x1070, base should be 0x1000
    out, _ = _run(["containerof", "_IO_FILE._fileno", "0x1070"])
    assert out.strip() == "0x1000"


# ============================================================
# Inline source (-c)
# ============================================================

def test_inline_source_describe():
    out, _ = _run(["describe", "-c", "struct foo { int a; long b; };", "foo"])
    assert "struct foo" in out
    assert " a" in out and " b" in out


def test_inline_source_stdin():
    out, _ = _run(
        ["describe", "-c", "-", "bar"],
        stdin="struct bar { long x; };",
    )
    assert "struct bar" in out


# ============================================================
# Header source (-f file.h)
# ============================================================

def test_header_source_auto_detected():
    # complex_structs.h is in the test dir; auto-detection sees no ELF magic
    # and routes to ORCHeader.
    out, _ = _run(["sizeof", "-f", "complex_structs.h", "Basic"])
    assert out.strip() == "12"


# ============================================================
# ELF source (-f ELF) and types/vars listing
# ============================================================

def test_types_glob_against_elf(challenge_gcc):
    out, _ = _run(["types", f"./{challenge_gcc}", "-p", "*Boss*"])
    names = [n for n in out.strip().splitlines() if n]
    assert "BossFight" in names
    assert "FinalBoss" in names


def test_types_long_columns():
    out, _ = _run(["types", "-l", "-p", "*FILE*"])
    assert "FILE" in out
    line = next(ln for ln in out.splitlines() if ln.startswith("FILE "))
    parts = line.split()
    assert len(parts) >= 3
    assert parts[1].isdigit()


def test_types_default_ctypes_no_source():
    out, _ = _run(["types", "-p", "*FILE*"])
    assert "FILE" in out


def test_vars_against_elf(challenge_gcc):
    out, _ = _run(["vars", f"./{challenge_gcc}"])
    names = [n for n in out.strip().splitlines() if n]
    assert "boss" in names
    assert "final" in names


def test_vars_long_against_elf(challenge_gcc):
    out, _ = _run(["vars", f"./{challenge_gcc}", "-l", "-p", "boss"])
    line = out.strip()
    assert line.startswith("boss")
    assert "BossFight" in line


def test_vars_rejects_non_elf():
    with pytest.raises(SystemExit) as ex:
        _run(["vars", "complex_structs.h"])
    assert ex.value.code == 2


def test_vars_requires_source_arg():
    parser = _build_parser()
    with pytest.raises(SystemExit):
        parser.parse_args(["orc", "vars"])


# ============================================================
# --sym ELF symbol resolution
# ============================================================

def test_sym_describe_against_elf(challenge_gcc):
    out, _ = _run(["describe", "-s", "-f", f"./{challenge_gcc}", "boss"])
    assert "struct BossFight" in out
    assert "u" in out


def test_sym_offsetof_prints_field_offset(challenge_gcc):
    out, _ = _run(["offsetof", "-s", "-f", f"./{challenge_gcc}", "boss.u"])
    assert "field offset:" in out
    assert "0x18" in out


def test_sym_field_at_against_elf(challenge_gcc):
    # boss is a BossFight; offset 16 falls inside b[1]
    out, _ = _run(["field_at", "-s", "-f", f"./{challenge_gcc}", "boss", "16"])
    assert "b[1]" in out


def test_sym_rejected_on_non_elf_source():
    with pytest.raises(SystemExit) as ex:
        _run(["describe", "-s", "-c", "struct x { int y; };", "x"])
    assert ex.value.code == 2


def test_sym_unknown_symbol_clean_error(challenge_gcc):
    with pytest.raises(SystemExit) as ex:
        _run(["sizeof", "-s", "-f", f"./{challenge_gcc}", "no_such_global"])
    assert ex.value.code == 2


# ============================================================
# Error paths
# ============================================================

def test_unknown_type_clean_error():
    with pytest.raises(SystemExit) as ex:
        _run(["describe", "totally_nonexistent_type"])
    assert ex.value.code == 2


def test_no_subcommand_prints_help():
    parser = _build_parser()
    args = parser.parse_args(["orc"])
    with pytest.raises(SystemExit):
        args.func(args)
