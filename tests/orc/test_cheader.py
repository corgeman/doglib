"""
Tests for ORCHeader / ORCInline compilation branches in _cheader.py.

Covers:
  - context.bits is used when the user has set context.arch/bits explicitly
  - bits != host_bits appends -m<bits> to the gcc command
  - FileNotFoundError when gcc is not on PATH
"""
import struct
import subprocess

import pytest
from pwnlib.context import context

import doglib.orc._cheader as _cheader_mod
from doglib.orc import ORCHeader, ORCInline


# ============================================================
# context.bits path
# ============================================================

def test_orcheader_uses_context_bits():
    """ORCHeader respects an explicitly-set context.bits when bits= is omitted.

    We set context.bits=64 so that 'bits' appears in vars(context). The inline
    source is unique so that we exercise the path rather than hitting cache.
    After the with-block, pwntools restores the context.
    """
    with context.local(bits=64):
        assert 'bits' in vars(context), \
            "pwntools should populate vars(context) with 'bits' after context.local(bits=...)"
        orc = ORCInline("/* ctx_bits_test */ struct CtxBitsS { int x; };")
        assert orc.sizeof('CtxBitsS') == 4


# ============================================================
# bits != host_bits → -m<bits> flag
# ============================================================

def test_orcheader_cross_compile_flag():
    """Constructing ORCInline with bits=32 on a 64-bit host appends -m32.

    Skipped automatically when gcc-multilib is not installed, since the
    compile step will raise CalledProcessError in that case.
    """
    host_bits = struct.calcsize('P') * 8
    cross_bits = 32 if host_bits == 64 else 64
    try:
        orc = ORCInline("struct CrossBitsS { int x; };", bits=cross_bits)
        assert orc.sizeof('CrossBitsS') == 4
    except subprocess.CalledProcessError:
        pytest.skip(f"gcc -{cross_bits} not available (install gcc-multilib)")


# ============================================================
# FileNotFoundError when gcc is missing
# ============================================================

def test_orcheader_include_dir_oserror(tmp_path):
    """OSError while reading an include-dir file is silently ignored during hashing.

    Creates a file in the include directory, then makes it unreadable so that
    the hash-input loop hits the except OSError: pass branch.
    """
    import os
    inc = tmp_path / 'inc'
    inc.mkdir()
    secret = inc / 'secret.h'
    secret.write_text("typedef int myint;")
    secret.chmod(0o000)  # unreadable → triggers OSError in hash loop

    main_h = tmp_path / 'main.h'
    main_h.write_text("typedef struct OSErrS { int x; } OSErrS;")

    try:
        orc = ORCHeader(str(main_h), include_dirs=[str(inc)])
        assert orc.sizeof('OSErrS') == 4
    finally:
        secret.chmod(0o644)  # restore so tmp_path cleanup can delete it


def test_orcheader_gcc_not_found(monkeypatch):
    """ORCHeader re-raises FileNotFoundError when gcc is not on PATH."""
    def _fake_run(*args, **kwargs):
        raise FileNotFoundError("gcc: command not found")

    monkeypatch.setattr(_cheader_mod.subprocess, 'run', _fake_run)

    with pytest.raises(FileNotFoundError):
        # Unique source guarantees no cache hit → compile branch is entered.
        ORCInline("/* gcc_missing_test_unique_xyzzy */ struct GccMissing { int x; };")
