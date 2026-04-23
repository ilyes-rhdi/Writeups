#!/usr/bin/env python3
"""
tinymt32.py — Standalone TinyMT32 PRNG

A Python implementation of TinyMT32 (Tiny Mersenne Twister, 32-bit variant)
with an interface modelled on the standard library's `random.Random`.

Period:  2^127 - 1
State:   127 effective bits (4 × 32-bit words, MSB of first word unused)
Authors of original C: Mutsuo Saito and Makoto Matsumoto (Mersenne Twister Lab)
Reference: https://github.com/MersenneTwister-Lab/TinyMT

Usage
-----
    from tinymt32 import TinyMT32

    rng = TinyMT32(seed=42)

    rng.random()            # float in [0.0, 1.0)
    rng.getrandbits(n)      # n-bit non-negative integer
    rng.randint(a, b)       # integer N with a <= N <= b
    rng.randrange(start, stop, step)
    rng.choice(seq)
    rng.choices(seq, k=5)
    rng.shuffle(lst)
    rng.sample(seq, k)
    rng.uniform(a, b)
    rng.gauss(mu, sigma)    # stateful, not re-entrant
    rng.seed(s)
    rng.getstate() / rng.setstate(state)
    rng.raw()               # raw uint32 output
"""

import math
import operator
from functools import reduce

__all__ = ["TinyMT32"]

# ─── TinyMT32 parameters ─────────────────────────────
_MASK32  = 0xFFFF_FFFF
_S0_MASK = 0x7FFF_FFFF
_MAT1    = 0x8F7011EE
_MAT2    = 0xFC78FF1F
_TMAT    = 0x3793FDFF


def _next_state(s0, s1, s2, s3):
    x = ((s0 & _S0_MASK) ^ s1 ^ s2) & _MASK32
    y = s3
    x = (x ^ (x << 1)) & _MASK32
    y = (y ^ (y >> 1) ^ x) & _MASK32
    ns0 = s1
    ns1 = s2
    ns2 = (x ^ (y << 10)) & _MASK32
    ns3 = y
    if y & 1:
        ns1 = (ns1 ^ _MAT1) & _MASK32
        ns2 = (ns2 ^ _MAT2) & _MASK32
    return ns0, ns1, ns2, ns3


def _temper(s0, s2, s3):
    t1 = (s0 + (s2 >> 8)) & _MASK32
    t0 = (s3 ^ t1) & _MASK32
    if t1 & 1:
        t0 = (t0 ^ _TMAT) & _MASK32
    return t0


def _seed_state(seed):
    """Initialise from a 32-bit integer seed."""
    s = [seed & _MASK32, _MAT1, _MAT2, _TMAT]
    for i in range(1, 8):
        prev = s[(i - 1) & 3]
        s[i & 3] = (s[i & 3] ^ (i + 1812433253 * (prev ^ (prev >> 30)))) & _MASK32
    if not ((s[0] & _S0_MASK) | s[1] | s[2] | s[3]):
        s = [ord('T'), ord('I'), ord('N'), ord('Y')]
    s0, s1, s2, s3 = s
    for _ in range(8):
        s0, s1, s2, s3 = _next_state(s0, s1, s2, s3)
    return s0 & _S0_MASK, s1, s2, s3


# ─── Public class ─────────────────────────────────────────────────────────────

class TinyMT32:
    """
    TinyMT32 pseudo-random number generator.

    Drop-in replacement for `random.Random` for the methods listed below.
    Seeding accepts any integer; only the low 32 bits are used (matching the
    reference C implementation).

    Methods
    -------
    raw()                   → uint32
    random()                → float in [0.0, 1.0)
    getrandbits(k)          → k-bit non-negative int
    randint(a, b)           → int in [a, b]
    randrange(start[, stop[, step]])
    uniform(a, b)           → float in [a, b]
    gauss(mu, sigma)        → float (Box-Muller; stateful)
    choice(seq)             → one element
    choices(seq, *, k=1)    → list of k elements (with replacement)
    shuffle(lst)            → None (in-place)
    sample(population, k)   → list of k unique elements
    seed(s)
    getstate()              → opaque tuple
    setstate(state)
    """

    def __init__(self, seed=None):
        self._gauss_next = None
        self.seed(seed)

    # ── seeding ───────────────────────────────────────────────────────────────

    def seed(self, s=None):
        """
        Seed the generator.

        Accepts:
          - None          → uses a random 32-bit integer from os.urandom
          - int           → low 32 bits used as the seed
          - bytes / str   → folded into a 32-bit value via XOR of 4-byte chunks
        """
        if s is None:
            import os
            s = int.from_bytes(os.urandom(4), "little")
        elif isinstance(s, (bytes, bytearray)):
            # Fold arbitrary bytes into 32 bits
            padded = s + b'\x00' * (-len(s) % 4)
            chunks = [int.from_bytes(padded[i:i+4], "little")
                      for i in range(0, len(padded), 4)]
            s = reduce(operator.xor, chunks, 0)
        elif isinstance(s, str):
            s = reduce(operator.xor,
                       (ord(c) for c in s),
                       0) & _MASK32
        else:
            s = operator.index(s)   # raises TypeError for non-integers
        self._s0, self._s1, self._s2, self._s3 = _seed_state(s & _MASK32)
        self._gauss_next = None

    # ── state ─────────────────────────────────────────────────────────────────

    def getstate(self):
        """Return internal state as an opaque tuple passable to setstate()."""
        return (self._s0, self._s1, self._s2, self._s3, self._gauss_next)

    def setstate(self, state):
        """Restore internal state from a tuple returned by getstate()."""
        if len(state) != 5:
            raise ValueError("state tuple must have 5 elements (from getstate())")
        self._s0, self._s1, self._s2, self._s3 = (v & _MASK32 for v in state[:4])
        self._s0 &= _S0_MASK
        self._gauss_next = state[4]

    # ── core generation ───────────────────────────────────────────────────────

    def _advance(self):
        """Advance state by one step and return the raw uint32 output."""
        self._s0, self._s1, self._s2, self._s3 = _next_state(
            self._s0, self._s1, self._s2, self._s3)
        return _temper(self._s0, self._s2, self._s3)

    def raw(self):
        """Return the next raw uint32 value (range [0, 2^32))."""
        return self._advance()

    # ── random.Random interface ───────────────────────────────────────────────

    def random(self):
        """Return a float in [0.0, 1.0)."""
        return self._advance() * (1.0 / 4294967296.0)   # / 2^32

    def getrandbits(self, k):
        """
        Return a non-negative integer with exactly k random bits.

        k must be a non-negative integer; k=0 returns 0.
        Matches the contract of random.Random.getrandbits().
        """
        if k < 0:
            raise ValueError("number of bits must be non-negative")
        if k == 0:
            return 0
        words = (k + 31) // 32
        acc = 0
        for _ in range(words):
            acc = (acc << 32) | self._advance()
        # Trim to exactly k bits
        return acc >> (words * 32 - k)

    def randint(self, a, b):
        """Return a random integer N such that a <= N <= b."""
        return self.randrange(a, b + 1)

    def randrange(self, start, stop=None, step=1):
        """
        Return a randomly selected element from range(start, stop, step).

        Mirrors the behaviour of random.Random.randrange().
        """
        if stop is None:
            start, stop = 0, start
        width = stop - start
        if step == 1:
            if width <= 0:
                raise ValueError("empty range for randrange()")
            return start + self._randbelow(width)
        n = math.ceil(width / step)
        if n <= 0:
            raise ValueError("empty range for randrange()")
        return start + step * self._randbelow(n)

    def _randbelow(self, n):
        """Return a random int in [0, n) with no modulo bias."""
        if n <= 0:
            raise ValueError("n must be positive")
        k = n.bit_length()
        while True:
            r = self.getrandbits(k)
            if r < n:
                return r

    def uniform(self, a, b):
        """Return a float N such that a <= N <= b (or b <= N <= a)."""
        return a + (b - a) * self.random()

    def gauss(self, mu=0.0, sigma=1.0):
        """
        Normal distribution (Box-Muller transform).

        Stateful: every other call reuses the second value from the pair.
        Not re-entrant (same as stdlib random.gauss).
        """
        z = self._gauss_next
        self._gauss_next = None
        if z is None:
            while True:
                u = 2.0 * self.random() - 1.0
                v = 2.0 * self.random() - 1.0
                s = u * u + v * v
                if 0.0 < s < 1.0:
                    break
            t = math.sqrt(-2.0 * math.log(s) / s)
            z = u * t
            self._gauss_next = v * t
        return mu + z * sigma

    def normalvariate(self, mu=0.0, sigma=1.0):
        """Alias for gauss() to match stdlib naming."""
        return self.gauss(mu, sigma)

    def choice(self, seq):
        """Return a random element from a non-empty sequence."""
        if not seq:
            raise IndexError("cannot choose from an empty sequence")
        return seq[self._randbelow(len(seq))]

    def choices(self, population, weights=None, *, cum_weights=None, k=1):
        """
        Return a list of k elements chosen with replacement.

        If weights or cum_weights are provided, selections are weighted.
        Mirrors random.choices().
        """
        n = len(population)
        if not n:
            raise IndexError("cannot choose from an empty population")
        if weights is not None and cum_weights is not None:
            raise TypeError("cannot specify both weights and cumulative weights")
        if weights is not None:
            cum_weights = list(_accumulate(weights))
        if cum_weights is not None:
            total = cum_weights[-1]
            return [population[_bisect(cum_weights, self.random() * total, 0, n) - 1]
                    for _ in range(k)]
        return [population[self._randbelow(n)] for _ in range(k)]

    def shuffle(self, lst):
        """Shuffle list in-place using Fisher-Yates."""
        for i in range(len(lst) - 1, 0, -1):
            j = self._randbelow(i + 1)
            lst[i], lst[j] = lst[j], lst[i]

    def sample(self, population, k):
        """
        Return a list of k unique elements chosen from population.

        Does not modify the original sequence.
        """
        n = len(population)
        if not 0 <= k <= n:
            raise ValueError("sample larger than population or negative k")
        result = list(population)
        for i in range(k):
            j = i + self._randbelow(n - i)
            result[i], result[j] = result[j], result[i]
        return result[:k]

    def __repr__(self):
        return (f"TinyMT32(state=({self._s0:#010x}, {self._s1:#010x}, "
                f"{self._s2:#010x}, {self._s3:#010x}))")


# ─── small helpers (avoid importing bisect / itertools just for choices) ──────

def _accumulate(weights):
    total = 0
    for w in weights:
        total += w
        yield total

def _bisect(a, x, lo, hi):
    while lo < hi:
        mid = (lo + hi) // 2
        if a[mid] < x:
            lo = mid + 1
        else:
            hi = mid
    return lo


# ─── quick self-test ──────────────────────────────────────────────────────────

if __name__ == "__main__":
    print("TinyMT32 self-test")
    print("=" * 40)

    rng = TinyMT32(seed=12345)

    print(f"\nSeed: 12345")
    print(f"First 5 raw uint32s:")
    for _ in range(5):
        print(f"  {rng.raw():#010x}")

    rng.seed(12345)
    print(f"\nFirst 5 floats [0, 1):")
    for _ in range(5):
        print(f"  {rng.random():.8f}")

    rng.seed(99)
    print(f"\ngetrandbits: 8={rng.getrandbits(8)}, 16={rng.getrandbits(16)}, 64={rng.getrandbits(64)}")
    print(f"randint(1, 6): {[rng.randint(1, 6) for _ in range(10)]}")
    print(f"choice: {rng.choice(['alpha', 'beta', 'gamma', 'delta'])}")

    lst = list(range(10))
    rng.shuffle(lst)
    print(f"shuffle(0..9): {lst}")
    print(f"sample(0..9, 4): {rng.sample(list(range(10)), 4)}")

    print(f"\ngauss(0, 1) × 5: {[round(rng.gauss(), 4) for _ in range(5)]}")

    # State save/restore
    rng.seed(777)
    state = rng.getstate()
    vals_a = [rng.raw() for _ in range(5)]
    rng.setstate(state)
    vals_b = [rng.raw() for _ in range(5)]
    print(f"\nState save/restore: {'PASS' if vals_a == vals_b else 'FAIL'}")
    print(f"  {vals_a}")

    print(f"\n{rng!r}")