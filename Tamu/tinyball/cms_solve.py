#!/usr/bin/env python3
import argparse
import os
import sys
import time
from pathlib import Path

HERE = Path(__file__).resolve().parent
CMS_ROOT = HERE / ".apt" / "cms"
if CMS_ROOT.exists():
    sys.path.insert(0, str(CMS_ROOT / "usr" / "lib" / "python3" / "dist-packages"))
    lib_dir = CMS_ROOT / "usr" / "lib" / "x86_64-linux-gnu"
    old_ld = os.environ.get("LD_LIBRARY_PATH")
    os.environ["LD_LIBRARY_PATH"] = f"{lib_dir}:{old_ld}" if old_ld else str(lib_dir)

from pycryptosat import Solver

from solve import (
    BALLS,
    EMOJI_TO_VALUE,
    EMOJIS,
    N_CENSORED,
    N_FULL,
    N_SAMPLES,
    TinyMT32,
    generate_synthetic_instance,
    make_draw,
    parse_archive,
)


WIDE = 40
WORD = 32
LOWBIT_INFO = {
    48: 4,
    60: 2,
    96: 5,
    120: 3,
}


def bits_of_int(value: int, width: int) -> list[bool]:
    return [bool((value >> i) & 1) for i in range(width)]


def bits_to_int(bits: list[int | bool], model: tuple[bool | None, ...]) -> int:
    value = 0
    for i, bit in enumerate(bits):
        if bit is True:
            value |= 1 << i
        elif bit is False:
            continue
        elif model[bit]:
            value |= 1 << i
    return value


class CMSBuilder:
    def __init__(self, *, threads: int = 7, time_limit: float | None = None):
        self.solver = Solver(threads=threads, time_limit=time_limit or 0)
        self.next_var = 1

    def new_var(self) -> int:
        var = self.next_var
        self.next_var += 1
        return var

    def new_vec(self, width: int) -> list[int]:
        return [self.new_var() for _ in range(width)]

    def set_bit(self, bit: int | bool, value: bool):
        if bit is True or bit is False:
            if bit != value:
                self.solver.add_clause([])
            return
        self.solver.add_clause([bit] if value else [-bit])

    def eq_bit(self, a: int | bool, b: int | bool):
        if isinstance(a, bool) and isinstance(b, bool):
            if a != b:
                self.solver.add_clause([])
            return
        if isinstance(a, bool):
            self.set_bit(b, a)
            return
        if isinstance(b, bool):
            self.set_bit(a, b)
            return
        self.solver.add_xor_clause([a, b], False)

    def xor_bit(self, *bits: int | bool):
        vars_only: list[int] = []
        rhs = False
        for bit in bits:
            if bit is True:
                rhs = not rhs
            elif bit is False:
                continue
            else:
                vars_only.append(bit)
        if not vars_only:
            return rhs
        if len(vars_only) == 1:
            if rhs:
                out = self.new_var()
                self.solver.add_xor_clause([out, vars_only[0]], True)
                return out
            return vars_only[0]
        out = self.new_var()
        self.solver.add_xor_clause([out, *vars_only], rhs)
        return out

    def and_bit(self, a: int | bool, b: int | bool):
        if a is False or b is False:
            return False
        if a is True:
            return b
        if b is True:
            return a
        out = self.new_var()
        self.solver.add_clause([-out, a])
        self.solver.add_clause([-out, b])
        self.solver.add_clause([out, -a, -b])
        return out

    def or_bit(self, a: int | bool, b: int | bool):
        if a is True or b is True:
            return True
        if a is False:
            return b
        if b is False:
            return a
        out = self.new_var()
        self.solver.add_clause([-a, out])
        self.solver.add_clause([-b, out])
        self.solver.add_clause([a, b, -out])
        return out

    def maj_bit(self, a: int | bool, b: int | bool, c: int | bool):
        if isinstance(a, bool) and isinstance(b, bool) and isinstance(c, bool):
            return (a + b + c) >= 2
        ab = self.and_bit(a, b)
        ac = self.and_bit(a, c)
        bc = self.and_bit(b, c)
        return self.or_bit(self.or_bit(ab, ac), bc)

    def add_vec(self, a: list[int | bool], b: list[int | bool]):
        out = []
        carry: int | bool = False
        for abit, bbit in zip(a, b):
            out.append(self.xor_bit(abit, bbit, carry))
            carry = self.maj_bit(abit, bbit, carry)
        return out, carry

    def xor_vec(self, *vecs: list[int | bool]):
        width = len(vecs[0])
        return [self.xor_bit(*(vec[i] for vec in vecs)) for i in range(width)]

    def shift_left(self, vec: list[int | bool], count: int, width: int):
        return [False] * count + list(vec[: width - count])

    def shift_right(self, vec: list[int | bool], count: int, width: int):
        return list(vec[count:]) + [False] * count

    def pad(self, vec: list[int | bool], width: int):
        return list(vec) + [False] * (width - len(vec))

    def assert_vec_equal(self, a: list[int | bool], b: list[int | bool]):
        for abit, bbit in zip(a, b):
            self.eq_bit(abit, bbit)

    def forbid_value(self, bits: list[int | bool], value: int):
        clause = []
        for i, bit in enumerate(bits):
            if bit is True or bit is False:
                if bit != bool((value >> i) & 1):
                    return
                continue
            clause.append(-bit if ((value >> i) & 1) else bit)
        self.solver.add_clause(clause)

    def constrain_small_lt(self, bits: list[int | bool], limit: int):
        for value in range(limit, 1 << len(bits)):
            self.forbid_value(bits, value)

    def constrain_low_bits(self, bits: list[int | bool], value: int, width: int):
        known = bits_of_int(value, width)
        for bit, want in zip(bits, known):
            self.set_bit(bit, want)

    def mul_const(self, vec: list[int | bool], const: int, width: int):
        terms = []
        shift = 0
        value = const
        while value:
            if value & 1:
                terms.append(self.pad(self.shift_left(vec, shift, width), width))
            shift += 1
            value >>= 1
        if not terms:
            return [False] * width
        acc = terms[0]
        for term in terms[1:]:
            acc, _ = self.add_vec(acc, term)
        return acc


def xor_with_cond_const(builder: CMSBuilder, base: list[int | bool], cond: int | bool, const: int):
    return [
        builder.xor_bit(bit, cond if ((const >> i) & 1) else False)
        for i, bit in enumerate(base)
    ]


def next_state_bits(builder: CMSBuilder, state):
    s0, s1, s2, s3 = state

    x0 = []
    for i in range(31):
        x0.append(builder.xor_bit(s0[i], s1[i], s2[i]))
    x0.append(builder.xor_bit(s1[31], s2[31]))

    x = [x0[0]]
    for i in range(1, WORD):
        x.append(builder.xor_bit(x0[i], x0[i - 1]))

    y = []
    for i in range(31):
        y.append(builder.xor_bit(s3[i], s3[i + 1], x[i]))
    y.append(builder.xor_bit(s3[31], x[31]))

    y0 = y[0]
    ns0 = s1
    ns1 = xor_with_cond_const(builder, s2, y0, 0x8F7011EE)
    y_shift = builder.shift_left(y, 10, WORD)
    ns2 = builder.xor_vec(x, y_shift)
    ns2 = xor_with_cond_const(builder, ns2, y0, 0xFC78FF1F)
    ns3 = y
    return ns0, ns1, ns2, ns3


def temper_bits(builder: CMSBuilder, state):
    s0, _, s2, s3 = state
    s2_shift = builder.shift_right(s2, 8, WORD)
    t1, _ = builder.add_vec(s0, s2_shift)
    out = xor_with_cond_const(builder, builder.xor_vec(s3, t1), t1[0], 0x3793FDFF)
    return out


def add_full_observation(builder: CMSBuilder, out_bits, mod: int, value: int):
    if mod in LOWBIT_INFO:
        builder.constrain_low_bits(out_bits, value, LOWBIT_INFO[mod])

    qbits = ((1 << 32) // mod).bit_length()
    q = builder.new_vec(qbits)
    prod = builder.mul_const(q, mod, WIDE)
    rem = bits_of_int(value, WIDE)
    total, _ = builder.add_vec(prod, rem)
    builder.assert_vec_equal(total, builder.pad(out_bits, WIDE))


def add_censored_observation(builder: CMSBuilder, out_bits, mod: int, emoji_value: int):
    if mod in LOWBIT_INFO:
        low = LOWBIT_INFO[mod]
        builder.constrain_low_bits(out_bits, emoji_value, min(low, 3))

    qbits = ((1 << 32) // mod).bit_length()
    q = builder.new_vec(qbits)
    prod = builder.mul_const(q, mod, WIDE)

    rbits = max(3, (mod - 1).bit_length())
    rem = builder.new_vec(rbits)
    builder.constrain_low_bits(rem, emoji_value, 3)
    builder.constrain_small_lt(rem, mod)

    total, _ = builder.add_vec(prod, builder.pad(rem, WIDE))
    builder.assert_vec_equal(total, builder.pad(out_bits, WIDE))


def build_solver(censored_draws, full_draws, *, threads: int = 7, time_limit: float = 300.0):
    builder = CMSBuilder(threads=threads, time_limit=time_limit)

    state = tuple(builder.new_vec(WORD) for _ in range(4))
    builder.set_bit(state[0][31], False)
    initial_state = state

    for draw in censored_draws:
        state = next_state_bits(builder, state)
        out = temper_bits(builder, state)
        for mod, emoji_value in zip(BALLS, draw):
            add_censored_observation(builder, out, mod, emoji_value)
            state = next_state_bits(builder, state)
            out = temper_bits(builder, state)
        # loop overdraws one state too far, rewind logical cursor by carrying the last step forward
        state = (
            state[0],
            state[1],
            state[2],
            state[3],
        )

    return builder, initial_state


def build_archive_solver(censored_draws, full_draws, *, threads: int = 7, time_limit: float = 300.0):
    builder = CMSBuilder(threads=threads, time_limit=time_limit)
    state = tuple(builder.new_vec(WORD) for _ in range(4))
    builder.set_bit(state[0][31], False)
    initial_state = state
    step_infos = []

    observations = []
    for draw in censored_draws:
        observations.extend(("censored", mod, value) for mod, value in zip(BALLS, draw))
    for draw in full_draws:
        observations.extend(("full", mod, value) for mod, value in zip(BALLS, draw))

    for step_index, (kind, mod, value) in enumerate(observations, start=1):
        state = next_state_bits(builder, state)
        out = temper_bits(builder, state)
        step_infos.append(
            {
                "step": step_index,
                "kind": kind,
                "mod": mod,
                "value": value,
                "out_lsb": out[0],
            }
        )
        if kind == "full":
            add_full_observation(builder, out, mod, value)
        else:
            add_censored_observation(builder, out, mod, value)

    return builder, initial_state, step_infos


def recover_initial_state(censored_draws, full_draws, *, threads: int = 7, time_limit: float = 300.0):
    builder, initial_state, _ = build_archive_solver(
        censored_draws, full_draws, threads=threads, time_limit=time_limit
    )
    started = time.time()
    sat, model = builder.solver.solve()
    elapsed = time.time() - started
    if sat is None:
        raise RuntimeError(f"SAT solve timed out after {elapsed:.2f}s")
    if sat is False:
        raise RuntimeError(f"SAT solve returned UNSAT after {elapsed:.2f}s")

    state = tuple(bits_to_int(word, model) for word in initial_state)
    return state, elapsed


def solve_with_full_odd_assumptions(
    censored_draws,
    full_draws,
    assume_bits: str,
    *,
    threads: int = 7,
    time_limit: float = 300.0,
):
    builder, initial_state, infos = build_archive_solver(
        censored_draws, full_draws, threads=threads, time_limit=time_limit
    )
    candidate_vars = [info["out_lsb"] for info in infos if info["kind"] == "full" and info["mod"] in (25, 75)]
    candidate_vars = list(reversed(candidate_vars))
    if len(assume_bits) > len(candidate_vars):
        raise ValueError(f"at most {len(candidate_vars)} assumption bits are available")

    assumptions = []
    for bit_char, var in zip(assume_bits, candidate_vars):
        if bit_char not in "01":
            raise ValueError("assumption bits must be 0/1 only")
        assumptions.append(var if bit_char == "1" else -var)

    started = time.time()
    sat, model = builder.solver.solve(assumptions=assumptions, time_limit=time_limit)
    elapsed = time.time() - started
    if sat is not True:
        return sat, elapsed, None

    state = tuple(bits_to_int(word, model) for word in initial_state)
    return sat, elapsed, state


def self_test(rounds: int, time_limit: float, threads: int):
    for index in range(rounds):
        archive, today, answer = generate_synthetic_instance()
        censored = [[value % 8 for value in draw] for draw in archive[:N_CENSORED]]
        full = archive[N_CENSORED:]
        state, elapsed = recover_initial_state(
            censored, full, threads=threads, time_limit=time_limit
        )
        rng = TinyMT32(0)
        rng.setstate(state + (None,))
        predicted = [make_draw(rng) for _ in range(N_SAMPLES + 2)]
        print(f"round {index + 1}: solved in {elapsed:.2f}s")
        print("archive ok:", predicted[:N_SAMPLES] == archive)
        print("today ok:", predicted[N_SAMPLES] == today)
        print("answer ok:", predicted[N_SAMPLES + 1] == answer)


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--self-test", type=int, default=0)
    parser.add_argument("--stdin", action="store_true")
    parser.add_argument("--time-limit", type=float, default=300.0)
    parser.add_argument("--threads", type=int, default=7)
    parser.add_argument("--assume-full-odd", default="")
    args = parser.parse_args()

    if args.self_test:
        self_test(args.self_test, args.time_limit, args.threads)
        return

    if args.stdin:
        text = sys.stdin.read()
        censored, full = parse_archive(text)
        if args.assume_full_odd:
            sat, elapsed, state = solve_with_full_odd_assumptions(
                censored,
                full,
                args.assume_full_odd,
                threads=args.threads,
                time_limit=args.time_limit,
            )
            print(f"solve_time={elapsed:.2f}s")
            print(f"status={sat}")
            if sat is True:
                rng = TinyMT32(0)
                rng.setstate(state + (None,))
                draws = [make_draw(rng) for _ in range(N_SAMPLES + 2)]
                print("answer:", " ".join(map(str, draws[N_SAMPLES + 1])))
            return
        state, elapsed = recover_initial_state(
            censored, full, threads=args.threads, time_limit=args.time_limit
        )
        rng = TinyMT32(0)
        rng.setstate(state + (None,))
        draws = [make_draw(rng) for _ in range(N_SAMPLES + 2)]
        print(f"solve_time={elapsed:.2f}s")
        print("answer:", " ".join(map(str, draws[N_SAMPLES + 1])))
        return

    parser.error("pick --self-test or --stdin")


if __name__ == "__main__":
    main()
