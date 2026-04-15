"""
Tests for __init__.py singleton cache (__getattr__).

Covers the C and C32 branches (C64 is already exercised in test_orc_setup.py).
"""
import doglib.orc as orc_mod
from doglib.orc import C64


def test_c_singleton():
    """'C' resolves to a CTypes instance (host-native bits) and is cached."""
    c1 = orc_mod.C
    c2 = orc_mod.C
    assert c1 is c2
    # Native CTypes should understand basic stdint types
    assert c1.sizeof('int') == 4


def test_c32_singleton():
    """'C32' resolves to a 32-bit CTypes instance and is cached."""
    c32a = orc_mod.C32
    c32b = orc_mod.C32
    assert c32a is c32b
    assert c32a.bits == 32
    assert c32a.sizeof('int') == 4


def test_getattr_unknown_raises():
    """Accessing an unknown name via __getattr__ raises AttributeError."""
    import pytest
    with pytest.raises(AttributeError):
        _ = orc_mod.CNONEXISTENT
