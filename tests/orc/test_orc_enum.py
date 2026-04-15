"""
Tests for ORC enum API.

Covers: constant access (.NAME, ['NAME']), iteration, __contains__,
repr, missing-key errors.
"""
import pytest

from doglib.orc import ORCHeader


# ============================================================
# Enum
# ============================================================

def test_enum_constants(headers):
    state = headers.enum('State')
    assert state.IDLE == 0
    assert state.RUNNING == 1
    assert state.CRASHED == -1
    assert 'IDLE' in state
    assert 'NONEXISTENT' not in state


def test_enum_assignment_in_craft(headers):
    state = headers.enum('State')
    fb = headers.craft('FinalBoss')
    fb.current_state = state.CRASHED
    assert fb.current_state.value == 0xFFFFFFFF


def test_enum_iteration(headers):
    state = headers.enum('State')
    items = dict(state)
    assert items['IDLE'] == 0
    assert items['CRASHED'] == -1


def test_enum_missing_constant_raises(headers):
    state = headers.enum('State')
    with pytest.raises(AttributeError):
        _ = state.NONEXISTENT


def test_enum_repr(headers):
    state = headers.enum('State')
    r = repr(state)
    assert 'IDLE' in r and 'CRASHED' in r


def test_enum_bracket_access(headers):
    """enum['NAME'] returns the same value as enum.NAME."""
    state = headers.enum('State')
    assert state['IDLE']    == state.IDLE    == 0
    assert state['RUNNING'] == state.RUNNING == 1
    assert state['CRASHED'] == state.CRASHED == -1


def test_enum_bracket_missing_raises_key_error(headers):
    """enum['BOGUS'] raises KeyError, not AttributeError."""
    state = headers.enum('State')
    with pytest.raises(KeyError):
        _ = state['BOGUS']


def test_enum_on_non_enum_type_raises(headers):
    """enum() on a struct type raises ValueError."""
    with pytest.raises(ValueError, match="not an enum"):
        headers.enum('Basic')
