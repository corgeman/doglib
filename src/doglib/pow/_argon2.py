"""
Argon2id proof-of-work solver (kCTF / ctfwithbirds "bbb" format).

Challenge:  a2id.v2.<D>.<P_hex>     (P = 16 random bytes, D = total difficulty bits)
Solution :  <c_hex>[.<c_hex>...]    (one winning counter per chained sub-proof)

The challenge splits into ``proof_count = 2**min(3, D-1)`` (capped at 8) chained
sub-proofs, each needing a digest with ``proof_difficulty = D - split_bits``
leading zero bits.  Sub-proofs are chained — each one's winning digest seeds the
next one's input — so we parallelise *within* a sub-proof, never across.

Three tiers, fastest available wins:
  - the doglib_rs CUDA extension, then
  - the doglib_rs AVX-512 extension, then
  - argon2-cffi + multiprocessing (``pip install argon2-cffi``).

There is deliberately no pure-Python compute fallback: a hand-rolled Argon2 in
Python runs at seconds-per-hash, which is unusable at real difficulties.
"""

import multiprocessing as mp
import os
import sys

try:
    from doglib_rs import pow_solver as _rs_pow
except ImportError:
    _rs_pow = None

_warned_slow = False


def _warn_slow_once():
    """Warn once when neither accelerated backend is available."""
    global _warned_slow
    if _warned_slow:
        return
    _warned_slow = True
    sys.stderr.write(
        "[doglib.pow] running with argon2-cffi (CUDA/AVX-512 unavailable).\n"
        "see docs/tutorials/gpu_pow_setup.md\n"
    )

# ---- fixed parameters of the bbb a2id.v2 scheme ----------------------------

TAG = "a2id"
VERSION = "v2"
PASSWORD_LEN = 16
HASH_LEN = 32
COUNTER_LEN = 8
MAX_COUNTER = (1 << (8 * COUNTER_LEN)) - 1
MAX_DIFFICULTY = 63
MAX_SPLIT_BITS = 3

# argon2id cost parameters (constant for this PoW)
M_KIB = 4096
T_COST = 1
P_LANES = 1


def _leading_zero_bits(b: bytes) -> int:
    n = 0
    for byte in b:
        if byte:
            return n + (8 - byte.bit_length())
        n += 8
    return n


def proof_shape(difficulty: int) -> tuple[int, int]:
    """(proof_count, proof_difficulty) for a given total difficulty."""
    split_bits = min(MAX_SPLIT_BITS, max(0, difficulty - 1))
    return 1 << split_bits, difficulty - split_bits


def proof_password(password: bytes, index: int, chain: bytes) -> bytes:
    """The 52-byte argon2 secret (also the salt prefix) for sub-proof ``index``."""
    return password + index.to_bytes(4, "big") + chain


def proof_salt(password: bytes, index: int, chain: bytes, counter: int) -> bytes:
    return proof_password(password, index, chain) + counter.to_bytes(COUNTER_LEN, "big")


def decode_challenge(chal: str) -> tuple[int, bytes]:
    """Parse ``a2id.v2.<D>.<P_hex>`` into ``(difficulty, password)``."""
    parts = chal.strip().split(".")
    if len(parts) != 4 or parts[0] != TAG or parts[1] != VERSION:
        raise ValueError(f"not an a2id.v2 challenge: {chal!r}")
    if not parts[2].isdigit():
        raise ValueError(f"bad difficulty: {parts[2]!r}")
    difficulty = int(parts[2])
    if not 0 <= difficulty <= MAX_DIFFICULTY:
        raise ValueError(f"difficulty out of range: {difficulty}")
    password = bytes.fromhex(parts[3])
    if len(password) != PASSWORD_LEN:
        raise ValueError(f"bad password length: {len(password)} bytes")
    return difficulty, password


def _argon2id_raw(secret: bytes, salt: bytes) -> bytes:
    from argon2.low_level import Type, hash_secret_raw

    return hash_secret_raw(
        secret=secret, salt=salt,
        time_cost=T_COST, memory_cost=M_KIB, parallelism=P_LANES,
        hash_len=HASH_LEN, type=Type.ID,
    )


# ---- argon2-cffi multiprocessing solver ------------------------------------


def _worker(args):
    """Sweep counters ``start, start+step, ...`` for one sub-proof.

    Module-level so the fork pool can dispatch it.  ``prefix`` is both the argon2
    secret and the salt prefix (they share the same 52 bytes in this scheme).
    """
    index, prefix, difficulty, counter, step, stop = args
    from argon2.low_level import Type, hash_secret_raw

    while not stop.is_set():
        digest = hash_secret_raw(
            secret=prefix, salt=prefix + counter.to_bytes(COUNTER_LEN, "big"),
            time_cost=T_COST, memory_cost=M_KIB, parallelism=P_LANES,
            hash_len=HASH_LEN, type=Type.ID,
        )
        if _leading_zero_bits(digest) >= difficulty:
            stop.set()
            return index, counter, digest
        counter += step
    return None


def solve(challenge: str, workers: int = 0) -> bytes:
    """Solve via argon2-cffi across ``workers`` processes (0 = all CPUs)."""
    difficulty, password = decode_challenge(challenge)
    proof_count, proof_difficulty = proof_shape(difficulty)
    if workers <= 0:
        workers = max(1, os.cpu_count() or 1)

    ctx = mp.get_context("fork") if "fork" in mp.get_all_start_methods() else mp.get_context()
    results: list[str] = []
    chain = bytes(HASH_LEN)

    with ctx.Manager() as mgr, ctx.Pool(workers) as pool:
        for i in range(proof_count):
            stop = mgr.Event()
            prefix = proof_password(password, i, chain)
            proof_args = [
                (i, prefix, proof_difficulty, start, workers, stop)
                for start in range(workers)
            ]
            for result in pool.imap_unordered(_worker, proof_args):
                if result is not None:
                    _, counter, digest = result
                    results.append(f"{counter:x}")
                    chain = digest
                    break

    if len(results) != proof_count:
        raise RuntimeError("argon2 solve failed: a sub-proof returned no counter")
    return ".".join(results).encode()


# ---- verification (used by tests and to sanity-check GPU results) ----------


def verify(challenge: str | bytes, solution: str | bytes) -> bool:
    """Check a solution against a challenge.  Requires argon2-cffi."""
    if isinstance(challenge, bytes):
        challenge = challenge.decode()
    if isinstance(solution, bytes):
        solution = solution.decode()
    difficulty, password = decode_challenge(challenge)
    proof_count, proof_difficulty = proof_shape(difficulty)

    parts = solution.strip().split(".")
    if len(parts) != proof_count:
        return False
    try:
        counters = [int(p, 16) for p in parts]
    except ValueError:
        return False
    if any(c > MAX_COUNTER for c in counters):
        return False

    chain = bytes(HASH_LEN)
    for i, counter in enumerate(counters):
        digest = _argon2id_raw(
            proof_password(password, i, chain),
            proof_salt(password, i, chain, counter),
        )
        if _leading_zero_bits(digest) < proof_difficulty:
            return False
        chain = digest
    return True


# ---- public entry point ----------------------------------------------------


def _argon2_cffi_available() -> bool:
    try:
        import argon2.low_level  # noqa: F401
        return True
    except ImportError:
        return False


def solve_argon2(challenge: str | bytes, workers: int | None = None) -> bytes:
    """Solve an ``a2id.v2`` Argon2id PoW, returning the dotted-hex solution bytes.

    Dispatches through CUDA, AVX-512, then argon2-cffi. Raises ``RuntimeError``
    if no backend is available.
    """
    if isinstance(challenge, bytes):
        challenge = challenge.decode()
    challenge = challenge.strip()
    decode_challenge(challenge)  # validate early

    native_backend = "unavailable"
    if _rs_pow is not None:
        try:
            native_backend = _rs_pow.argon2_backend_info()
        except Exception:
            pass
    if native_backend in ("cuda", "avx512"):
        try:
            sol = _rs_pow.solve_argon2(challenge, workers or 0)
            sol = sol.encode() if isinstance(sol, str) else sol
            # Best-effort guard against a faulty accelerated result.
            if _argon2_cffi_available() and not verify(challenge, sol):
                raise RuntimeError(
                    f"accelerated argon2 solution failed verification: {sol!r}"
                )
            return sol
        except Exception as error:
            sys.stderr.write(
                "[doglib.pow] accelerated argon2 solve failed "
                f"({error}); falling back to argon2-cffi.\n"
            )

    if not _argon2_cffi_available():
        raise RuntimeError(
            "argon2id PoW solver needs argon2-cffi (`pip install argon2-cffi`) "
            "or doglib_rs on a CUDA/AVX-512-capable host."
        )
    _warn_slow_once()
    return solve(challenge, workers=workers or 0)


__all__ = [
    "solve_argon2",
    "solve",
    "verify",
    "decode_challenge",
    "proof_shape",
]
