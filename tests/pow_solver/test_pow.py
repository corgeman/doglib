"""Tests for the pow module (Python API) and the underlying Rust solver."""

import base64
import secrets

import pytest

from doglib.pow import (
    solve_pow,
    verify_pow,
    get_challenge,
    backend,
    _decode_challenge,
    _encode_challenge,
    _sloth_square,
    MODULUS,
)

# ---------------------------------------------------------------------------
# Known-answer tests
# The Sloth VDF has two valid square roots for each input. The Rust solver
# and the Python/gmpy2 fallback may pick different roots, but both verify.
# ---------------------------------------------------------------------------

CHALLENGE_D1 = "s.AAAAAQ==.H+fPiuL32DPbfN97cpd0nA=="
EXPECTED_D1_RUST = (
    b"s.SehdFNCoMtQI4d9JBXsmzWdYk77jtb36Io5acLmjB6l/Vr1VUUsegi3CNbUf7lgUI5kGux"
    b"gdleSh+poE/BCGoAoaTNGVBC14jl+W0D7wg8R2IPDCUSTueG0JNCtJL8OeNPiReJ+CBFcqcR"
    b"0Ntc9Qakzm8sZaBjGld1Rh3FK6gresUqjpnxGS4SgIg/lp/iZ+2EetM94ewJHsXghGaWQYkg=="
)

CHALLENGE_D50 = "s.AAAAMg==.H+fPiuL32DPbfN97cpd0nA=="
EXPECTED_D50_RUST = (
    b"s.O5X5tBMcDT3O2E/32edB/FqCuws5LuvMKGGAkqVc9Wak/gJmwkUpUvYWOlr9x+tsccb6/K"
    b"cNCQTym1Jzclv+aXE49pu5RkukYgijK8gbuuQrfp+YIJ6OFHId2tCIAdV/QYFIrhUy1pVUZ6mG"
    b"CCCRjGqMVSo6QGDAS59tKKbnGjdZYRLSku30L9GWpSx9Sdjas/PzTxOsN6rjlCBE/qgGHg=="
)


def test_solve_difficulty_1():
    result = solve_pow(CHALLENGE_D1)
    assert verify_pow(CHALLENGE_D1, result)


def test_solve_difficulty_50():
    result = solve_pow(CHALLENGE_D50)
    assert verify_pow(CHALLENGE_D50, result)


def test_exact_output_rust():
    """When the Rust backend is active, we expect a specific root."""
    if backend() != "rust":
        pytest.skip("Rust backend not available")
    assert solve_pow(CHALLENGE_D1) == EXPECTED_D1_RUST
    assert solve_pow(CHALLENGE_D50) == EXPECTED_D50_RUST


def test_verify_known():
    assert verify_pow(CHALLENGE_D1, EXPECTED_D1_RUST)
    assert verify_pow(CHALLENGE_D50, EXPECTED_D50_RUST)


def test_solve_bad_input():
    with pytest.raises((ValueError, Exception)):
        solve_pow("x.bad.input")


# ---------------------------------------------------------------------------
# Round-trip: solve then verify
# ---------------------------------------------------------------------------

@pytest.mark.parametrize("difficulty", [1, 2, 5, 10, 50])
def test_roundtrip(difficulty):
    challenge = get_challenge(difficulty)
    solution = solve_pow(challenge)
    assert verify_pow(challenge, solution), (
        f"verify failed for d={difficulty}: {challenge} -> {solution}"
    )


def test_roundtrip_d500():
    """Higher difficulty round-trip to stress the squaring kernel."""
    challenge = get_challenge(500)
    solution = solve_pow(challenge)
    assert verify_pow(challenge, solution)


# ---------------------------------------------------------------------------
# Bulk random challenges
# ---------------------------------------------------------------------------

def test_random_challenges_d1():
    """Generate 500 random challenges at d=1, solve and verify each."""
    for _ in range(500):
        chal = get_challenge(1)
        sol = solve_pow(chal)
        assert verify_pow(chal, sol), f"failed: {chal}"


def test_random_challenges_d10():
    """Generate 300 random challenges at d=10, solve and verify each."""
    for _ in range(300):
        chal = get_challenge(10)
        sol = solve_pow(chal)
        assert verify_pow(chal, sol), f"failed: {chal}"


# ---------------------------------------------------------------------------
# Cross-verify: Rust solver vs Python fallback squaring
# ---------------------------------------------------------------------------

def test_cross_verify_rust_vs_python():
    """Solve with the main solver, then verify the solution using
    the pure-Python squaring (not the same code path as the solver)."""
    for d in [1, 5, 25]:
        chal = get_challenge(d)
        sol = solve_pow(chal)

        diff, x = _decode_challenge(chal)
        (y,) = _decode_challenge(sol)
        res = _sloth_square(y, diff, MODULUS)
        assert x == res or MODULUS - x == res, (
            f"cross-verify failed at d={d}"
        )


# ---------------------------------------------------------------------------
# Encoding edge cases
# ---------------------------------------------------------------------------

def test_encode_decode_roundtrip():
    for val in [0, 1, 42, 2**128 - 1, 2**1279 - 2]:
        encoded = _encode_challenge([val])
        (decoded,) = _decode_challenge(encoded)
        assert decoded == val


def test_backend_reports():
    b = backend()
    assert b in ("rust", "gmpy2", "python")
