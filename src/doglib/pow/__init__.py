"""
Proof-of-work solvers for common CTF challenge formats.

Supports:
  - Sloth VDF (kctf/redpwn)
  - sosette/FCSC (SHA-256, leading zero bits, printable suffix)
  - hxp (SHA-256, trailing zero bits, raw byte suffix)
  - hashcash (SHA-1, leading zero bits, hex counter)
  - argon2id (kctf/ctfwithbirds "bbb" a2id.v2; needs argon2-cffi or the CUDA ext)

Usage:
    from doglib.pow import do_pow
    do_pow(tube)  # auto-detects PoW type, solves, and sends the answer

    # Or solve individual formats directly:
    from doglib.pow import solve_sloth, solve_sosette, solve_hxp, solve_hashcash
    from doglib.pow import solve_argon2
"""

import re

from doglib.pow._sloth import (
    sloth_challenge,
    solve_sloth,
    verify_sloth,
    MODULUS,
    _decode_challenge,
    _encode_challenge,
    _sloth_square,
)
from doglib.pow._hash import (
    solve_sosette,
    solve_hxp,
    solve_hashcash,
)
from doglib.pow._argon2 import solve_argon2

# ---- PoW detection patterns (each used for both detection and extraction) ---

_RE_SOSETTE = re.compile(rb"SHA256\(([a-zA-Z0-9]+)\s+.*?(\d+)\s+bits")
_RE_HXP = re.compile(rb'sha256\(unhex\("([0-9a-f]+)".*?(\d+)\s+zero', re.IGNORECASE)
_RE_HASHCASH = re.compile(rb'hashcash\s+-mCb(\d+)\s+"([^"]+)"')
_RE_SLOTH = re.compile(rb"(s\.[A-Za-z0-9+/=]+\.[A-Za-z0-9+/=]+)")
_RE_ARGON2 = re.compile(rb"a2id\.v2\.\d+\.[0-9a-fA-F]{32}")


def _solve_sloth_from_data(data):
    m = _RE_SLOTH.search(data)
    if m:
        return solve_sloth(m.group(1))
    return None


def _solve_sosette_from_data(data):
    m = _RE_SOSETTE.search(data)
    if m:
        prefix = m.group(1)
        difficulty = int(m.group(2))
        return solve_sosette(prefix, difficulty)
    return None


def _solve_hxp_from_data(data):
    m = _RE_HXP.search(data)
    if m:
        prefix_hex = m.group(1).decode()
        bits = int(m.group(2))
        result = solve_hxp(prefix_hex, bits)
        return result.encode()
    return None


def _solve_hashcash_from_data(data):
    m = _RE_HASHCASH.search(data)
    if m:
        bits = int(m.group(1))
        resource = m.group(2).decode()
        result = solve_hashcash(resource, bits)
        return result.encode()
    return None


def _solve_argon2_from_data(data):
    m = _RE_ARGON2.search(data)
    if m:
        return solve_argon2(m.group(0).decode())
    return None


_DETECTORS = [
    (_RE_ARGON2, _solve_argon2_from_data),
    (_RE_SOSETTE, _solve_sosette_from_data),
    (_RE_HXP, _solve_hxp_from_data),
    (_RE_HASHCASH, _solve_hashcash_from_data),
    (_RE_SLOTH, _solve_sloth_from_data),
]


def detect_and_solve(data: bytes | str) -> bytes | None:
    """Auto-detect PoW type from server output and solve it.

    Args:
        data: Raw bytes received from the server.

    Returns:
        Solution bytes, or None if no known PoW format was detected.
    """
    if isinstance(data, str):
        data = data.encode()
    for pattern, solver in _DETECTORS:
        if pattern.search(data):
            result = solver(data)
            if result is not None:
                return result
    return None


def do_pow(p: 'pwnlib.tubes.tube.tube') -> 'pwnlib.tubes.tube.tube':
    """Auto-detect and solve a PoW from a pwntools tube.

    Polls data from the tube incrementally, checking for a known PoW
    pattern after each chunk. Solves and sends the solution once found.
    """
    data = b""
    for _ in range(50):
        try:
            chunk = p.recv(timeout=0.1)
        except EOFError:
            break
        if not chunk:
            continue
        data += chunk
        solution = detect_and_solve(data)
        if solution is not None:
            if isinstance(solution, str):
                solution = solution.encode()
            p.sendline(solution)
            return p
    raise ValueError(f"Could not detect PoW format in received data: {data!r}")


__all__ = [
    "detect_and_solve",
    "do_pow",
]
