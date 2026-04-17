import ctypes
import ctypes.util
import pytest
from doglib.rand import GlibcRand, GlibcRandCrack, srand, rand

libc_path = ctypes.util.find_library("c")
if libc_path is None:
    pytest.skip("libc not found", allow_module_level=True)
libc = ctypes.CDLL(libc_path)
libc.srand.argtypes = [ctypes.c_uint]
libc.srand.restype = None
libc.rand.argtypes = []
libc.rand.restype = ctypes.c_int

SEEDS = [0, 1, 42, 1337, 0x7fffffff, 0x80000000, 0xdeadbeef, 0xffffffff]
N = 500

@pytest.mark.parametrize("seed", SEEDS)
def test_sequence_matches_libc(seed):
    libc.srand(seed)
    r = GlibcRand(seed)
    for i in range(N):
        expected = libc.rand()
        got = r.rand()
        assert got == expected, f"seed={seed} i={i}: expected {expected}, got {got}"

def test_global_state():
    """global srand/rand should match libc"""
    libc.srand(9999)
    srand(9999)
    for i in range(100):
        assert rand() == libc.rand(), f"global mismatch at i={i}"

def test_default_seed():
    """default seed=1 should match libc after srand(1)"""
    libc.srand(1)
    r = GlibcRand()
    for i in range(100):
        assert r.rand() == libc.rand()

def test_reseed():
    """reseeding mid-sequence should reset properly"""
    r = GlibcRand(123)
    libc.srand(123)
    for _ in range(50):
        r.rand()
        libc.rand()
    r.srand(456)
    libc.srand(456)
    for i in range(100):
        assert r.rand() == libc.rand(), f"reseed mismatch at i={i}"

def test_multiple_instances():
    """independent instances shouldn't interfere"""
    r1 = GlibcRand(10)
    r2 = GlibcRand(20)
    libc.srand(10)
    seq1 = [libc.rand() for _ in range(50)]
    libc.srand(20)
    seq2 = [libc.rand() for _ in range(50)]
    for i in range(50):
        assert r1.rand() == seq1[i]
        assert r2.rand() == seq2[i]


# ---- GlibcRandCrack tests ----

class TestGlibcRandCrackSubmit:
    def test_submit_int(self):
        rc = GlibcRandCrack()
        rc.submit(1804289383)
        assert rc._constraints == [(1804289383, 0x7fffffff)]

    def test_submit_none(self):
        rc = GlibcRandCrack()
        rc.submit(None)
        assert rc._constraints == [(0, 0)]

    def test_submit_bitstring(self):
        rc = GlibcRandCrack()
        rc.submit('1?0')
        value, mask = rc._constraints[0]
        # '1?0' -> left-padded to 31 bits: '1?0' + '?' * 28
        # MSB-first: bit 30=1 (known), bit 29=? (unknown), bit 28=0 (known), rest unknown
        assert mask & (1 << 30) != 0  # bit 30 known
        assert value & (1 << 30) != 0  # bit 30 is 1
        assert mask & (1 << 29) == 0  # bit 29 unknown
        assert mask & (1 << 28) != 0  # bit 28 known
        assert value & (1 << 28) == 0  # bit 28 is 0

    def test_submit_list(self):
        rc = GlibcRandCrack()
        rc.submit([100, None, 200])
        assert len(rc._constraints) == 3
        assert rc._constraints[0] == (100, 0x7fffffff)
        assert rc._constraints[1] == (0, 0)
        assert rc._constraints[2] == (200, 0x7fffffff)

    def test_submit_invalid_int(self):
        rc = GlibcRandCrack()
        with pytest.raises(ValueError):
            rc.submit(-1)
        with pytest.raises(ValueError):
            rc.submit(0x80000000)

    def test_submit_invalid_bitstring(self):
        rc = GlibcRandCrack()
        with pytest.raises(ValueError):
            rc.submit('x0101')
        with pytest.raises(ValueError):
            rc.submit('0' * 32)

    def test_submit_invalid_type(self):
        rc = GlibcRandCrack()
        with pytest.raises(TypeError):
            rc.submit(3.14)


class TestGlibcRandCrackPredict:
    @pytest.mark.parametrize("seed", [1, 42, 1337, 0xdeadbeef])
    def test_predict_96_consecutive(self, seed):
        """submit 100 outputs, predict next 50 (pure Python path)"""
        g = GlibcRand(seed)
        outputs = [g.rand() for _ in range(100)]
        expected = [g.rand() for _ in range(50)]

        rc = GlibcRandCrack()
        rc.submit(outputs)
        p = rc.predict()
        for i, exp in enumerate(expected):
            got = p.rand()
            assert got == exp, f"seed={seed} prediction[{i}]: expected {exp}, got {got}"

    def test_predict_exact_96(self):
        """exactly 96 outputs should work for pure Python path"""
        g = GlibcRand(9999)
        outputs = [g.rand() for _ in range(96)]
        expected = [g.rand() for _ in range(20)]

        rc = GlibcRandCrack()
        rc.submit(outputs)
        p = rc.predict()
        for i, exp in enumerate(expected):
            assert p.rand() == exp, f"prediction[{i}] mismatch"

    def test_predict_many_outputs(self):
        """submit 200 outputs, predict next 200"""
        g = GlibcRand(77777)
        outputs = [g.rand() for _ in range(200)]
        expected = [g.rand() for _ in range(200)]

        rc = GlibcRandCrack()
        rc.submit(outputs)
        p = rc.predict()
        for i, exp in enumerate(expected):
            assert p.rand() == exp


try:
    from doglib_rs import rand_cracker as _rs_rand
    HAS_RUST = True
except ImportError:
    HAS_RUST = False

needs_rust = pytest.mark.skipif(not HAS_RUST, reason="doglib_rs not installed")


@needs_rust
class TestGlibcRandCrackSeed:
    def test_get_seed_basic(self):
        """recover seed from 3 full outputs"""
        seed = 42
        g = GlibcRand(seed)
        rc = GlibcRandCrack()
        rc.submit([g.rand() for _ in range(3)])
        assert rc.get_seed() == seed

    def test_get_seed_with_gaps(self):
        """recover seed with None gaps"""
        seed = 1337
        g = GlibcRand(seed)
        vals = [g.rand() for _ in range(5)]
        rc = GlibcRandCrack()
        rc.submit([vals[0], None, vals[2], None, vals[4]])
        assert rc.get_seed() == seed

    def test_get_seed_partial_bits(self):
        """recover seed from partial bit observations (low 8 bits only)"""
        seed = 9999
        g = GlibcRand(seed)
        rc = GlibcRandCrack()
        for _ in range(10):
            val = g.rand()
            # only know low 8 bits (like rand() % 256)
            bits = bin(val & 0xff)[2:].zfill(8)
            rc.submit('?' * 23 + bits)
        assert rc.get_seed() == seed

    def test_get_seed_zero(self):
        """seed=0 is treated as seed=1 by glibc"""
        g = GlibcRand(0)
        rc = GlibcRandCrack()
        rc.submit([g.rand() for _ in range(3)])
        # should find 0 or 1 (they produce the same sequence)
        found = rc.get_seed()
        assert found in (0, 1)

    def test_predict_fallback_to_seed(self):
        """predict with <31 outputs should use get_seed internally"""
        seed = 555
        g = GlibcRand(seed)
        outputs = [g.rand() for _ in range(5)]
        expected = [g.rand() for _ in range(20)]

        rc = GlibcRandCrack()
        rc.submit(outputs)
        p = rc.predict()
        for i, exp in enumerate(expected):
            assert p.rand() == exp

    def test_roundtrip(self):
        """full round-trip: seed -> generate -> submit -> get_seed -> verify"""
        seed = 31337
        g1 = GlibcRand(seed)
        rc = GlibcRandCrack()
        rc.submit([g1.rand() for _ in range(3)])
        recovered = rc.get_seed()

        g2 = GlibcRand(recovered)
        g1_check = GlibcRand(seed)
        for _ in range(200):
            assert g2.rand() == g1_check.rand()


@needs_rust
class TestGlibcRandCrackSeedKnown:
    """test get_seed() with known seed bits to reduce search space"""

    def test_known_lower_bits_int(self):
        """known=0xBEEF means lower 16 bits are 0xBEEF"""
        seed = 0xDEADBEEF
        g = GlibcRand(seed)
        rc = GlibcRandCrack()
        rc.submit([g.rand() for _ in range(3)])
        assert rc.get_seed(known=0xBEEF) == seed

    def test_known_bitstring(self):
        """known='1101' means top 4 bits are 1101, rest unknown"""
        seed = 0xDEADBEEF
        g = GlibcRand(seed)
        rc = GlibcRandCrack()
        rc.submit([g.rand() for _ in range(3)])
        # top 4 bits of 0xDEADBEEF = 0xD = 1101
        assert rc.get_seed(known=bin(0xdead)[2:]) == seed

    def test_known_full_seed(self):
        """passing the full seed as known should work instantly"""
        seed = 42
        g = GlibcRand(seed)
        rc = GlibcRandCrack()
        rc.submit([g.rand() for _ in range(3)])
        assert rc.get_seed(known=seed) == seed

    def test_known_none_same_as_default(self):
        """known=None should behave same as no argument"""
        seed = 42
        g = GlibcRand(seed)
        rc = GlibcRandCrack()
        rc.submit([g.rand() for _ in range(3)])
        assert rc.get_seed(known=None) == seed


@needs_rust
class TestGlibcRandCrackSeedAll:
    """test get_seeds() — enumerate all matching seeds"""

    def test_get_seeds_unique(self):
        """with 3 full outputs, should find exactly one seed"""
        seed = 0x421337
        g = GlibcRand(seed)
        rc = GlibcRandCrack()
        rc.submit([g.rand() for _ in range(3)])
        seeds = rc.get_seeds(known=0x1337)
        assert seeds == [0x421337]

    def test_get_seeds_multiple_with_partial(self):
        """with very few partial bits, multiple seeds may match"""
        seed = 1337
        g = GlibcRand(seed)
        val = g.rand()
        rc = GlibcRandCrack()
        # only know lowest 4 bits of one output — many seeds will match
        low4 = bin(val & 0xf)[2:].zfill(4)
        rc.submit('?' * 27 + low4)
        seeds = rc.get_seeds(known=1337)
        # the real seed must be in the list
        assert 1337 in seeds
        # with only 4 known output bits + full seed known, likely just 1
        # but the important thing is correctness
        for s in seeds:
            g2 = GlibcRand(s)
            assert g2.rand() & 0xf == val & 0xf

    def test_get_seeds_with_known(self):
        """get_seeds with known bits should narrow the search"""
        seed = 0xDEADBEEF
        g = GlibcRand(seed)
        rc = GlibcRandCrack()
        rc.submit([g.rand() for _ in range(3)])
        seeds = rc.get_seeds(known=0xBEEF)
        assert seeds == [0xDEADBEEF]

    def test_get_seeds_sorted(self):
        """results should be sorted"""
        seed = 42
        g = GlibcRand(seed)
        val = g.rand()
        rc = GlibcRandCrack()
        low8 = bin(val & 0xff)[2:].zfill(8)
        rc.submit('?' * 23 + low8)
        known_lower_16 = seed & 0xffff
        seeds = rc.get_seeds(known=known_lower_16)
        assert len(seeds) > 1 
        assert seeds == sorted(seeds)


class TestGlibcRandCrackSeedAnalytical:
    """test O(1) seed recovery via AFSR/LCG reversal (no Rust needed)"""

    @pytest.mark.parametrize("seed", [1, 42, 1337, 0xdeadbeef, 0xffffffff])
    def test_get_seed_analytical(self, seed):
        """submit 100 outputs, recover seed without Rust"""
        g = GlibcRand(seed)
        rc = GlibcRandCrack()
        rc.submit([g.rand() for _ in range(100)])
        recovered = rc._get_seed_analytical()
        # seed 0 and 1 produce same sequence
        expected = 1 if seed == 0 else seed
        assert recovered == expected

    def test_get_seed_analytical_roundtrip(self):
        """analytical recovery produces a seed that generates the same sequence"""
        seed = 31337
        g1 = GlibcRand(seed)
        outputs = [g1.rand() for _ in range(100)]
        expected = [g1.rand() for _ in range(200)]

        rc = GlibcRandCrack()
        rc.submit(outputs)
        recovered = rc._get_seed_analytical()
        assert recovered is not None

        g2 = GlibcRand(recovered)
        for _ in range(100):
            g2.rand()
        for i, exp in enumerate(expected):
            assert g2.rand() == exp, f"prediction[{i}] mismatch"

    def test_get_seed_falls_through_to_analytical(self):
        """get_seed() should use analytical path when 96+ outputs exist"""
        seed = 12345
        g = GlibcRand(seed)
        rc = GlibcRandCrack()
        rc.submit([g.rand() for _ in range(100)])
        # this should succeed even without Rust
        assert rc.get_seed() == seed

    def test_analytical_not_enough_outputs(self):
        """analytical recovery returns None with <96 outputs"""
        g = GlibcRand(42)
        rc = GlibcRandCrack()
        rc.submit([g.rand() for _ in range(50)])
        assert rc._get_seed_analytical() is None


class TestGlibcRandCrackErrors:
    def test_get_seed_no_constraints(self):
        rc = GlibcRandCrack()
        with pytest.raises((ValueError, RuntimeError)):
            rc.get_seed()

    def test_get_seed_only_gaps(self):
        rc = GlibcRandCrack()
        rc.submit([None, None, None])
        with pytest.raises((ValueError, RuntimeError)):
            rc.get_seed()
