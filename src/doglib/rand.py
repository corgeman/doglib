# pure-python reimplementation of glibc's srand()/rand()/srandom()/random()
# uses the default TYPE_3 state (degree 31, separation 3)

_U32 = 0xffffffff
_DEG = 31
_SEP = 3

def _to_i32(v):
    v &= _U32
    return v - 0x100000000 if v >= 0x80000000 else v

class GlibcRand:
    def __init__(self, seed=1):
        self.srand(seed)

    def srand(self, seed):
        seed &= _U32
        if seed == 0:
            seed = 1

        state = [0] * _DEG
        state[0] = _to_i32(seed)
        word = _to_i32(seed)
        for i in range(1, _DEG):
            word = (16807 * word) % 2147483647
            state[i] = _to_i32(word)

        self._state = state
        self._fptr = _SEP
        self._rptr = 0

        # cycle 310 times to flush initial dependencies
        for _ in range(_DEG * 10):
            self._step()

    def _step(self):
        val = (self._state[self._fptr] + self._state[self._rptr]) & _U32
        self._state[self._fptr] = _to_i32(val)
        self._fptr += 1
        if self._fptr >= _DEG:
            self._fptr = 0
            self._rptr += 1
        else:
            self._rptr += 1
            if self._rptr >= _DEG:
                self._rptr = 0
        return val

    def rand(self):
        return self._step() >> 1

    # aliases matching C naming
    random = rand
    srandom = srand

_global = GlibcRand(1)

def srand(seed: int) -> None:
    _global.srand(seed)

def rand() -> int:
    return _global.rand()

class GlibcRandCrack:
    _FULL_MASK = 0x7fffffff

    def __init__(self):
        self._constraints = []  # list of (value, mask) per rand() position

    def submit(self, observation):
        if isinstance(observation, (list, tuple)):
            for item in observation:
                self.submit(item)
            return
        if observation is None:
            self._constraints.append((0, 0))
        elif isinstance(observation, int):
            if not (0 <= observation <= self._FULL_MASK):
                raise ValueError(f"rand() output must be in [0, {self._FULL_MASK}], got {observation}")
            self._constraints.append((observation, self._FULL_MASK))
        elif isinstance(observation, str):
            self._constraints.append(self._parse_bits(observation))
        else:
            raise TypeError(f"expected int, None, str, or list, got {type(observation).__name__}")

    @staticmethod
    def _parse_bits(s):
        if len(s) > 31:
            raise ValueError(f"bit string too long (max 31 bits), got {len(s)}")
        s = s.ljust(31, '?')
        value = 0
        mask = 0
        for ch in s:
            value <<= 1
            mask <<= 1
            if ch == '1':
                value |= 1
                mask |= 1
            elif ch == '0':
                mask |= 1
            elif ch != '?':
                raise ValueError(f"invalid character in bit string: {ch!r}")
        return (value, mask)

    def _find_full_run(self):
        """find the longest consecutive run of full (mask=0x7fffffff) outputs.
        returns (start_index, length)."""
        best_start = 0
        best_len = 0
        cur_start = 0
        cur_len = 0
        for i, (_, mask) in enumerate(self._constraints):
            if mask == self._FULL_MASK:
                if cur_len == 0:
                    cur_start = i
                cur_len += 1
                if cur_len > best_len:
                    best_start = cur_start
                    best_len = cur_len
            else:
                cur_len = 0
        return best_start, best_len

    def predict(self):
        """return a GlibcRand positioned after the last submitted output.
        uses pure-python state recovery if 96+ consecutive full outputs exist
        (need ~3 full buffer cycles to uniquely resolve carry bits),
        otherwise falls back to get_seed()."""
        start, length = self._find_full_run()
        if length >= 96:
            result = self._predict_from_run(start, length)
            if result is not None:
                return result
        # not enough consecutive outputs or verification failed — need the seed
        return self._predict_from_seed()

    def _predict_from_seed(self):
        seed = self.get_seed()
        g = GlibcRand(seed)
        for _ in range(len(self._constraints)):
            g.rand()
        return g

    def _predict_from_run(self, start, length):
        outputs = [self._constraints[start + i][0] for i in range(length)]
        N = length
        _MOD31 = 1 << 31

        # each internal state is 2*output[i] + carry[i], carry ∈ {0,1}.
        # carry[i] = carry[i-31] XOR carry[i-3] (for i >= 31), so each carry
        # is a linear function of carry[0..30] over GF(2).
        # at the output level:
        #   delta = (o[i] - o[i-31] - o[i-3]) % 2^31
        #   delta == 1 means carry[i-31] = 1 AND carry[i-3] = 1
        # each such equation gives two linear constraints over GF(2).

        # build basis vectors: basis[i] represents carry[i] as a linear
        # combination of carry[0..30], stored as a 31-bit integer.
        basis = [0] * N
        for i in range(31):
            basis[i] = 1 << i
        for i in range(31, N):
            basis[i] = basis[i - 31] ^ basis[i - 3]

        # collect linear equations from delta==1 positions:
        # each gives basis[i-31] · x = 1 AND basis[i-3] · x = 1
        rows = []  # list of (coefficient_bitmask, rhs_bit)
        for i in range(31, N):
            delta = (outputs[i] - outputs[i - 31] - outputs[i - 3]) % _MOD31
            if delta == 1:
                rows.append((basis[i - 31], 1))
                rows.append((basis[i - 3], 1))

        # collect delta==0 constraints for verification
        delta0_pairs = []  # (basis_a, basis_b) where NOT both can be 1
        for i in range(31, N):
            delta = (outputs[i] - outputs[i - 31] - outputs[i - 3]) % _MOD31
            if delta == 0:
                delta0_pairs.append((basis[i - 31], basis[i - 3]))

        # GF(2) Gaussian elimination
        pivot = [0] * 31
        pivot_rhs = [0] * 31
        pivot_used = [False] * 31

        for coeff, rhs in rows:
            c, r = coeff, rhs
            for bit in range(30, -1, -1):
                if not (c & (1 << bit)):
                    continue
                if pivot_used[bit]:
                    c ^= pivot[bit]
                    r ^= pivot_rhs[bit]
                else:
                    pivot[bit] = c
                    pivot_rhs[bit] = r
                    pivot_used[bit] = True
                    break

        # identify free variables (bits without pivots)
        free_bits = [bit for bit in range(31) if not pivot_used[bit]]

        # back-substitute to find particular solution (free vars = 0)
        x0 = 0
        for bit in range(31):
            if pivot_used[bit]:
                val = bin(pivot[bit] & x0).count('1') % 2
                if val != pivot_rhs[bit]:
                    x0 |= (1 << bit)

        def _popcount_parity(v):
            v ^= v >> 16
            v ^= v >> 8
            v ^= v >> 4
            v ^= v >> 2
            v ^= v >> 1
            return v & 1

        def _check_solution(x):
            """verify x by checking the full recurrence holds."""
            c = [0] * N
            for i in range(N):
                c[i] = _popcount_parity(basis[i] & x)
            for i in range(31, N):
                a = (2 * outputs[i - 31] + c[i - 31]) & _U32
                b = (2 * outputs[i - 3] + c[i - 3]) & _U32
                expected = (a + b) & _U32
                actual = (2 * outputs[i] + c[i]) & _U32
                if expected != actual:
                    return False
            return True

        # build null space basis: for each free bit, compute its effect
        null_vecs = []
        for fbit in free_bits:
            nv = 1 << fbit
            # propagate through pivots
            for bit in range(31):
                if pivot_used[bit]:
                    if _popcount_parity(pivot[bit] & nv):
                        nv ^= (1 << bit)
            null_vecs.append(nv)

        K = len(free_bits)
        if K > 18:
            return None  # too many free variables

        # brute force free variables
        x_solution = None
        for mask in range(1 << K):
            x = x0
            for j in range(K):
                if mask & (1 << j):
                    x ^= null_vecs[j]
            if _check_solution(x):
                x_solution = x
                break

        if x_solution is None:
            return None

        # compute all carries from solution
        carries = [0] * N
        for i in range(N):
            carries[i] = _popcount_parity(basis[i] & x_solution)

        # build internal 32-bit states
        internal = [((2 * outputs[i] + carries[i]) & _U32) for i in range(N)]

        # reconstruct GlibcRand state from the last 31 internal values.
        # we don't know the absolute fptr position, but the buffer is circular
        # and we pick fptr_start=0 by convention — only relative order matters.
        fptr_now = N % _DEG
        rptr_now = (fptr_now + _DEG - _SEP) % _DEG

        state = [0] * _DEG
        for k in range(_DEG):
            buf_idx = (fptr_now - _DEG + k) % _DEG
            state[buf_idx] = _to_i32(internal[N - _DEG + k])

        g = GlibcRand.__new__(GlibcRand)
        g._state = state
        g._fptr = fptr_now
        g._rptr = rptr_now

        # advance past any remaining submitted outputs after this run
        remaining = len(self._constraints) - (start + length)
        for _ in range(remaining):
            g.rand()
        return g

    def _get_seed_analytical(self):
        """recover the seed by reversing the AFSR warmup and LCG.
        requires 96+ consecutive full outputs (same as predict's fast path).
        constraint index 0 must be the first rand() call after srand()."""
        start, length = self._find_full_run()
        if length < 96:
            return None

        g = self._predict_from_run(start, length)
        if g is None:
            return None

        # g's state uses relative buffer positions (run started at fptr=0).
        # remap to absolute positions so we can reverse back to seed init.
        # absolute fptr after 310 warmup + len(constraints) outputs:
        #   (SEP + 310 + len) % DEG = (SEP + len) % DEG  (since 310 = 10*DEG)
        n = len(self._constraints)
        rel_fptr = g._fptr
        abs_fptr = (_SEP + n) % _DEG
        offset = (abs_fptr - rel_fptr) % _DEG

        state = [0] * _DEG
        for i in range(_DEG):
            state[(i + offset) % _DEG] = g._state[i]

        # reverse 310 + n AFSR steps to recover the LCG-initialized state
        fptr = abs_fptr
        rptr = n % _DEG
        for _ in range(310 + n):
            fptr = (fptr - 1) % _DEG
            rptr = (rptr - 1) % _DEG
            state[fptr] = _to_i32(((state[fptr] & _U32) - (state[rptr] & _U32)) & _U32)

        # verify LCG relationship: state[i] = (16807 * state[i-1]) % 2147483647
        word = state[0]
        for i in range(1, _DEG):
            word = (16807 * word) % 2147483647
            if _to_i32(word) != state[i]:
                return None
        return state[0] & _U32

    @staticmethod
    def _parse_seed_hint(known):
        """parse a seed hint into (value, mask) for the 32-bit seed space.
        - None: no constraint → (0, 0)
        - int: lower bits known, e.g. 0xABC means lower 12 bits are 0xABC
        - str: 32-bit bitstring of '0'/'1'/'?', MSB-first, right-padded with '?'
        """
        if known is None:
            return (0, 0)
        if isinstance(known, int):
            if not (0 <= known <= 0xffffffff):
                raise ValueError(f"seed hint must be in [0, 0xffffffff], got {known}")
            nbits = known.bit_length() or 0
            if nbits == 0:
                return (0, 0)
            mask = (1 << nbits) - 1
            return (known & mask, mask)
        if isinstance(known, str):
            if len(known) > 32:
                raise ValueError(f"seed bit string too long (max 32 bits), got {len(known)}")
            s = known.ljust(32, '?')
            value = 0
            mask = 0
            for ch in s:
                value <<= 1
                mask <<= 1
                if ch == '1':
                    value |= 1
                    mask |= 1
                elif ch == '0':
                    mask |= 1
                elif ch != '?':
                    raise ValueError(f"invalid character in bit string: {ch!r}")
            return (value, mask)
        raise TypeError(f"expected int, str, or None for known, got {type(known).__name__}")

    def get_seed(self, known=None):
        """recover the original srand() seed.
        uses O(1) analytical recovery if 96+ consecutive full outputs exist,
        otherwise brute-forces the seed space via the Rust backend.

        known: optional hint constraining the seed value.
          - int: lower bits of the seed are known, e.g. known=0xABC means
            the seed ends in 0xABC (lower 12 bits). reduces search by 2^12.
          - str: bitstring of '0'/'1'/'?' (MSB-first), e.g. '1???0000????'
            specifies known bits at arbitrary positions.
          - None: no constraint (full 2^32 search).
        """
        seed_value, seed_mask = self._parse_seed_hint(known)

        if seed_mask == 0:
            seed = self._get_seed_analytical()
            if seed is not None:
                return seed

        try:
            from doglib_rs import rand_cracker as _rs_rand
        except ImportError:
            raise RuntimeError(
                "get_seed() requires doglib_rs (Rust backend).\n"
                "  cd src/doglib_rs && pip install -e ."
            )

        constraints = []
        for i, (value, mask) in enumerate(self._constraints):
            if mask != 0:
                constraints.append((i, value, mask))

        if not constraints:
            raise ValueError("no constraints submitted")

        result = _rs_rand.bruteforce_seed(constraints, seed_value, seed_mask)
        if result is None:
            raise RuntimeError("no seed found matching constraints")
        return result

    def get_seeds(self, known=None):
        """find ALL seeds matching the submitted constraints.
        always uses brute-force (no analytical shortcut) to ensure completeness.

        known: optional hint constraining the seed value (same format as get_seed).
        returns a sorted list of all matching seeds.
        """
        seed_value, seed_mask = self._parse_seed_hint(known)

        try:
            from doglib_rs import rand_cracker as _rs_rand
        except ImportError:
            raise RuntimeError(
                "get_seeds() requires doglib_rs (Rust backend).\n"
                "  cd src/doglib_rs && pip install -e ."
            )

        constraints = []
        for i, (value, mask) in enumerate(self._constraints):
            if mask != 0:
                constraints.append((i, value, mask))

        if not constraints:
            raise ValueError("no constraints submitted")

        results = _rs_rand.bruteforce_seed_all(constraints, seed_value, seed_mask)
        results.sort()
        return results

# helper functions to correctly format truncated rand() outputs as bit constraints

def rand_mod(value: int, n: int) -> str:
    """Format a rand() % n observation as a bit constraint string.
    For non-power-of-2 n, only bits from the 2-adic factor are pinned;
    for purely odd n this returns all unknowns."""
    a = (n & -n).bit_length() - 1
    if a == 0:
        return '?' * 31
    return '?' * (31 - a) + bin(value & ((1 << a) - 1))[2:].zfill(a)

def rand_rshift(value: int, k: int) -> str:
    """Format a rand() >> k observation as a bit constraint string."""
    return bin(value)[2:].zfill(31 - k) + '?' * k

def rand_and(value: int, mask: int) -> str:
    """Format a rand() & mask observation as a bit constraint string.
    Only bits where mask=1 are known; AND-zeroed bits reveal nothing."""
    s = ''
    for bit in range(30, -1, -1):
        if mask & (1 << bit):
            s += '1' if value & (1 << bit) else '0'
        else:
            s += '?'
    return s

def rand_divide(value: int, n: int) -> str:
    """Format a rand() // n observation as a bit constraint string."""
    min_val = value * n
    if min_val >= (1 << 31):
        raise ValueError("value implies rand() output >= 2^31")
    max_val = min(min_val + n - 1, (1 << 31) - 1)
    unknown_bits = (min_val ^ max_val).bit_length()
    if unknown_bits >= 31:
        return '?' * 31
    known = 31 - unknown_bits
    return bin(min_val >> unknown_bits)[2:].zfill(known) + '?' * unknown_bits

__all__ = [
    "GlibcRand",
    "srand", "rand",
    "GlibcRandCrack",
    "rand_mod", "rand_rshift", "rand_and", "rand_divide",
]
