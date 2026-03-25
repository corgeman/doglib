"""
Proof-of-work solver for kctf/redpwn-style Sloth VDF challenges.

Backends (in priority order):
  1. doglib_rs.pow_solver  — AVX512 IFMA Rust implementation (~8x faster than gmpy2)
  2. gmpy2                 — C-backed arbitrary precision (~8x faster than pure Python)
  3. Pure Python           — works everywhere, ~70x slower than doglib_rs

Usage:
    from doglib.pow import solve_pow, verify_pow, get_challenge

    solution = solve_pow("s.AAATiA==.c5JzfKLC099PHb3WLBaz1g==")
    assert verify_pow(challenge, solution)
"""

import base64
import secrets
import sys

VERSION = b"s"
MODULUS = 2**1279 - 1
CHALSIZE = 2**128

# --------------------------------------------------------------------------- #
# Backend selection
# --------------------------------------------------------------------------- #

_BACKEND = "python"

try:
    from doglib_rs import pow_solver as _rs_pow
    _BACKEND = "rust"
except ImportError:
    _rs_pow = None

try:
    import gmpy2
    if _BACKEND != "rust":
        _BACKEND = "gmpy2"
except ImportError:
    gmpy2 = None

if _BACKEND == "python":
    sys.stderr.write(
        "[doglib.pow] running in pure-Python mode (~70x slower than optimal).\n"
        "             pip install gmpy2          — ~8x faster\n"
        "             cd src/doglib_rs; pip install .       — ~70x faster (requires AVX512)\n"
    )
elif _BACKEND == "gmpy2":
    sys.stderr.write(
        "[doglib.pow] running with gmpy2 (~8x slower than optimal).\n"
        "             cd src/doglib_rs; pip install .       — ~8x faster (requires AVX512)\n"
    )


def backend():
    """Return the name of the active solver backend."""
    return _BACKEND


# --------------------------------------------------------------------------- #
# Encoding helpers
# --------------------------------------------------------------------------- #

def _encode_number(num):
    size = (num.bit_length() // 24) * 3 + 3
    return base64.b64encode(num.to_bytes(size, "big"))


def _decode_number(enc):
    return int.from_bytes(base64.b64decode(enc), "big")


def _decode_challenge(chal):
    parts = chal.split(b".")
    if parts[0] != VERSION:
        raise ValueError(f"Unknown challenge version: {parts[0]!r}")
    return [_decode_number(p) for p in parts[1:]]


def _encode_challenge(arr):
    return b".".join([VERSION] + [_encode_number(v) for v in arr])


# --------------------------------------------------------------------------- #
# Sloth VDF primitives
# --------------------------------------------------------------------------- #

def _python_sloth_root(x, diff, p):
    exponent = (p + 1) // 4
    for _ in range(diff):
        x = pow(x, exponent, p) ^ 1
    return x


def _python_sloth_square(y, diff, p):
    for _ in range(diff):
        y = pow(y ^ 1, 2, p)
    return y


def _gmpy_sloth_root(x, diff, p):
    exponent = (p + 1) // 4
    x = gmpy2.mpz(x)
    for _ in range(diff):
        x = gmpy2.powmod(x, exponent, p).bit_flip(0)
    return int(x)


def _gmpy_sloth_square(y, diff, p):
    y = gmpy2.mpz(y)
    for _ in range(diff):
        y = gmpy2.powmod(y.bit_flip(0), 2, p)
    return int(y)


def _sloth_root(x, diff, p):
    if gmpy2 is not None:
        return _gmpy_sloth_root(x, diff, p)
    return _python_sloth_root(x, diff, p)


def _sloth_square(x, diff, p):
    if gmpy2 is not None:
        return _gmpy_sloth_square(x, diff, p)
    return _python_sloth_square(x, diff, p)


# --------------------------------------------------------------------------- #
# Public API
# --------------------------------------------------------------------------- #

def get_challenge(difficulty):
    """Generate a fresh PoW challenge at the given difficulty."""
    x = secrets.randbelow(CHALSIZE)
    return _encode_challenge([difficulty, x])


def solve_pow(challenge):
    """Solve a PoW challenge, returning the solution as bytes.

    Automatically picks the fastest available backend.
    Accepts both str and bytes.
    """
    challenge = challenge.encode() if isinstance(challenge, str) else challenge
    if _rs_pow is not None:
        return _rs_pow.solve(challenge)

    diff, x = _decode_challenge(challenge)
    y = _sloth_root(x, diff, MODULUS)
    return _encode_challenge([y])


def verify_pow(challenge, solution):
    """Verify that *solution* is correct for *challenge*. Accepts str or bytes."""
    challenge = challenge.encode() if isinstance(challenge, str) else challenge
    solution = solution.encode() if isinstance(solution, str) else solution
    diff, x = _decode_challenge(challenge)
    (y,) = _decode_challenge(solution)
    res = _sloth_square(y, diff, MODULUS)
    return x == res or MODULUS - x == res
