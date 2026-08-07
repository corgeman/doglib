"""Tests for the argon2id (a2id.v2) proof-of-work solver."""

import secrets

import pytest

pytest.importorskip("argon2")  # argon2-cffi is required for these tests

from doglib.pow import detect_and_solve, solve_argon2
from doglib.pow._argon2 import decode_challenge, proof_shape, verify


def _make_challenge(difficulty: int) -> str:
    return f"a2id.v2.{difficulty}.{secrets.token_bytes(16).hex()}"


class TestArgon2:
    """argon2id: chained sub-proofs, each needing N leading zero bits."""

    def test_solve_basic(self):
        chal = _make_challenge(8)
        sol = solve_argon2(chal)
        assert isinstance(sol, bytes)
        assert verify(chal, sol)

    @pytest.mark.parametrize("difficulty", [1, 6, 10])
    def test_various_difficulties(self, difficulty):
        chal = _make_challenge(difficulty)
        sol = solve_argon2(chal)
        assert verify(chal, sol)

    def test_solution_shape(self):
        # D=10 -> split_bits=3 -> 8 chained sub-proofs -> 8 dotted hex counters
        chal = _make_challenge(10)
        proof_count, _ = proof_shape(10)
        parts = solve_argon2(chal).decode().split(".")
        assert len(parts) == proof_count
        assert all(int(p, 16) >= 0 for p in parts)

    def test_accepts_bytes_challenge(self):
        chal = _make_challenge(8)
        sol = solve_argon2(chal.encode())
        assert verify(chal, sol)


class TestVerify:
    def test_verify_rejects_wrong_count(self):
        # D=8 -> 8 sub-proofs; a single-counter solution must be rejected.
        chal = _make_challenge(8)
        assert not verify(chal, "deadbeef")

    def test_verify_rejects_non_hex(self):
        assert not verify(_make_challenge(4), "zz.zz.zz.zz.zz.zz.zz.zz")

    def test_decode_rejects_garbage(self):
        with pytest.raises(ValueError):
            decode_challenge("not.a.challenge.xx")


def _cuda_argon2_available() -> bool:
    try:
        from doglib_rs import pow_solver as p
        return p.argon2_backend_info() == "cuda"
    except Exception:
        return False


def _avx512_argon2_available() -> bool:
    try:
        from doglib_rs import pow_solver as p
        return p.argon2_backend_info() == "avx512"
    except Exception:
        return False


class TestGpu:
    """Drive the Rust/CUDA solver directly and cross-check with argon2-cffi.

    Skipped when the CUDA backend is not built/available.
    """

    @pytest.mark.parametrize("difficulty", [1, 7, 11])
    def test_gpu_solution_verifies(self, difficulty):
        if not _cuda_argon2_available():
            pytest.skip("CUDA argon2 backend not available")
        from doglib_rs import pow_solver as p

        chal = _make_challenge(difficulty)
        sol = p.solve_argon2(chal)
        assert verify(chal, sol), f"GPU solution failed verification for D={difficulty}"


class TestAvx512:
    """Drive the Rust/AVX-512 solver directly and cross-check with argon2-cffi."""

    @pytest.mark.parametrize("difficulty", [1, 7])
    def test_avx512_solution_verifies(self, difficulty):
        if not _avx512_argon2_available():
            pytest.skip("AVX-512 argon2 backend not available")
        from doglib_rs import pow_solver as p

        chal = _make_challenge(difficulty)
        sol = p.solve_argon2(chal, 2)
        assert verify(chal, sol), (
            f"AVX-512 solution failed verification for D={difficulty}"
        )


class TestAutoDetect:
    def test_detect_argon2(self):
        chal = _make_challenge(8)
        data = (
            b"== proof-of-work: argon2id ==\n"
            b"    python3 <(curl -sSL https://pow.example/pow) solve "
            + chal.encode()
            + b"\n\nSolution? "
        )
        result = detect_and_solve(data)
        assert result is not None
        assert verify(chal, result)

    def test_detect_ignores_non_challenge(self):
        assert detect_and_solve(b"mentions a2id but is not a real challenge") is None
