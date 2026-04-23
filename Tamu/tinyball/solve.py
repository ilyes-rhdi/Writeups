#!/usr/bin/env python3
import argparse
import base64
import random
import re
import socket
import ssl
import sys
import time

from tinymt32 import TinyMT32, _MAT1, _MAT2


BALLS = [25, 48, 60, 75, 96, 120]
N_SAMPLES = 27
N_FULL = 10
N_CENSORED = N_SAMPLES - N_FULL
EMOJIS = "🟥🟧🟨🟩🟦🟪🟫⬜"
EMOJI_TO_VALUE = {emoji: value for value, emoji in enumerate(EMOJIS)}

STATE_BITS = 127
POW_N = 1279
POW_P = (1 << POW_N) - 1
POW_RE = re.compile(rb"(s\.[A-Za-z0-9+/=_-]+\.[A-Za-z0-9+/=_-]+)")


def make_draw(rng: TinyMT32) -> list[int]:
    return [rng.raw() % m for m in BALLS]


def generate_synthetic_instance():
    rng = TinyMT32(0xF10C70)
    seeded = tuple(random.getrandbits(32) for _ in range(4)) + (None,)
    rng.setstate(seeded)
    archive = [make_draw(rng) for _ in range(N_SAMPLES)]
    today = make_draw(rng)
    answer = make_draw(rng)
    return archive, today, answer


def parse_archive(text: str):
    censored = []
    full = []
    for line in text.splitlines():
        emojis = [ch for ch in line if ch in EMOJI_TO_VALUE]
        if len(emojis) == len(BALLS):
            censored.append([EMOJI_TO_VALUE[ch] for ch in emojis])
            continue
        numbers = [int(x) for x in re.findall(r"\d+", line)]
        if len(numbers) == len(BALLS):
            full.append(numbers)
    if len(censored) != N_CENSORED or len(full) != N_FULL:
        raise ValueError(
            f"parsed {len(censored)} censored draws and {len(full)} full draws, "
            f"expected {N_CENSORED} and {N_FULL}"
        )
    return censored, full


def flatten_observations(censored_draws: list[list[int]], full_draws: list[list[int]]):
    observations = []
    for draw in censored_draws:
        observations.extend(("censored", mod, value) for mod, value in zip(BALLS, draw))
    for draw in full_draws:
        observations.extend(("full", mod, value) for mod, value in zip(BALLS, draw))
    return observations


def initial_state_basis():
    state = []
    index = 0
    for word in range(4):
        width = 31 if word == 0 else 32
        bits = []
        for _ in range(width):
            bits.append(1 << index)
            index += 1
        if word == 0:
            bits.append(0)
        state.append(bits)
    return state


def next_state_masks(state):
    s0, s1, s2, s3 = state

    x0 = [0] * 32
    for i in range(31):
        x0[i] = s0[i] ^ s1[i] ^ s2[i]
    x0[31] = s1[31] ^ s2[31]

    x = [0] * 32
    x[0] = x0[0]
    for i in range(1, 32):
        x[i] = x0[i] ^ x0[i - 1]

    y = [0] * 32
    for i in range(31):
        y[i] = s3[i] ^ s3[i + 1] ^ x[i]
    y[31] = s3[31] ^ x[31]

    y0 = y[0]
    ns0 = s1[:]
    ns1 = [s2[i] ^ (y0 if ((_MAT1 >> i) & 1) else 0) for i in range(32)]
    ns2 = [
        x[i] ^ (y[i - 10] if i >= 10 else 0) ^ (y0 if ((_MAT2 >> i) & 1) else 0)
        for i in range(32)
    ]
    ns3 = y[:]
    return [ns0, ns1, ns2, ns3]


def build_parity_rows(censored_draws: list[list[int]], full_draws: list[list[int]]):
    rows = []
    state = initial_state_basis()
    for kind, mod, value in flatten_observations(censored_draws, full_draws):
        state = next_state_masks(state)
        if mod % 2 == 0:
            # For TinyMT32, the output LSB is exactly the new state's s3[0] bit.
            rows.append((state[3][0], value & 1))
    return rows


def affine_solutions_from_rows(rows, nvars: int = STATE_BITS):
    work = [[mask, rhs & 1] for mask, rhs in rows if mask]
    pivot_cols = []
    pivot_row = 0

    for col in range(nvars - 1, -1, -1):
        found = None
        for row in range(pivot_row, len(work)):
            if (work[row][0] >> col) & 1:
                found = row
                break
        if found is None:
            continue
        work[pivot_row], work[found] = work[found], work[pivot_row]
        mask, rhs = work[pivot_row]
        for row in range(len(work)):
            if row != pivot_row and ((work[row][0] >> col) & 1):
                work[row][0] ^= mask
                work[row][1] ^= rhs
        pivot_cols.append(col)
        pivot_row += 1
        if pivot_row == len(work):
            break

    for mask, rhs in work:
        if mask == 0 and rhs:
            raise RuntimeError("parity system is inconsistent")

    reduced = work[:pivot_row]
    free_cols = [col for col in range(nvars) if col not in pivot_cols]

    particular = 0
    for row, pivot in enumerate(pivot_cols):
        if reduced[row][1]:
            particular |= 1 << pivot

    basis = []
    for free in free_cols:
        vec = 1 << free
        for row, pivot in enumerate(pivot_cols):
            if (reduced[row][0] >> free) & 1:
                vec |= 1 << pivot
        basis.append(vec)

    return particular, basis


def vector_to_state(vec: int):
    s0 = vec & ((1 << 31) - 1)
    s1 = (vec >> 31) & 0xFFFF_FFFF
    s2 = (vec >> 63) & 0xFFFF_FFFF
    s3 = (vec >> 95) & 0xFFFF_FFFF
    return s0, s1, s2, s3


def state_matches_observations(state, observations) -> bool:
    rng = TinyMT32(0)
    rng.setstate(state + (None,))
    for kind, mod, value in observations:
        remainder = rng.raw() % mod
        if kind == "full":
            if remainder != value:
                return False
        elif (remainder & 7) != value:
            return False
    return True


def predict_future(state):
    rng = TinyMT32(0)
    rng.setstate(state + (None,))
    archive = [make_draw(rng) for _ in range(N_SAMPLES)]
    today = make_draw(rng)
    answer = make_draw(rng)
    return archive, today, answer


def recover_initial_state_from_archive(censored_draws, full_draws):
    started = time.time()
    rows = build_parity_rows(censored_draws, full_draws)
    particular, basis = affine_solutions_from_rows(rows)
    observations = flatten_observations(censored_draws, full_draws)

    vec = particular
    prev_gray = 0
    checked = 0
    for index in range(1 << len(basis)):
        gray = index ^ (index >> 1)
        if index:
            delta = gray ^ prev_gray
            vec ^= basis[delta.bit_length() - 1]
            prev_gray = gray
        state = vector_to_state(vec)
        checked += 1
        if state_matches_observations(state, observations):
            return state, time.time() - started, len(basis), checked

    raise RuntimeError("no state matched the full archive")


def _b64decode_int(text: str) -> int:
    padded = text + "=" * (-len(text) % 4)
    return int.from_bytes(base64.b64decode(padded), "big")


def _pow_reduce(value: int) -> int:
    value = (value & POW_P) + (value >> POW_N)
    value = (value & POW_P) + (value >> POW_N)
    if value >= POW_P:
        value -= POW_P
    return value


def solve_pow(challenge: str) -> str:
    version, d_b64, x_b64 = challenge.split(".")
    difficulty = _b64decode_int(d_b64)
    value = _b64decode_int(x_b64)
    for _ in range(difficulty):
        for _ in range(POW_N - 2):
            value = _pow_reduce(value * value)
        value ^= 1
    encoded = base64.b64encode(value.to_bytes((value.bit_length() + 7) // 8 or 1, "big")).decode()
    return f"{version}.{encoded}"


def recv_until(sock: ssl.SSLSocket, marker: bytes, timeout: float = 30.0) -> bytes:
    sock.settimeout(timeout)
    data = b""
    while marker not in data:
        chunk = sock.recv(4096)
        if not chunk:
            break
        data += chunk
    return data


def recv_rest(sock: ssl.SSLSocket, timeout: float = 2.0) -> bytes:
    sock.settimeout(timeout)
    chunks = []
    while True:
        try:
            chunk = sock.recv(4096)
        except TimeoutError:
            break
        if not chunk:
            break
        chunks.append(chunk)
    return b"".join(chunks)


def solve_remote(host: str, port: int, sni: str | None = None):
    with socket.create_connection((host, port), timeout=15) as raw_sock:
        context = ssl.create_default_context()
        context.check_hostname = False
        context.verify_mode = ssl.CERT_NONE
        with context.wrap_socket(raw_sock, server_hostname=sni or host) as sock:
            prelude = recv_until(sock, b"solution: ")
            match = POW_RE.search(prelude)
            if not match:
                raise RuntimeError("could not find proof-of-work challenge")
            pow_challenge = match.group(1).decode()
            pow_solution = solve_pow(pow_challenge)
            sock.sendall(pow_solution.encode() + b"\n")

            challenge_text = recv_until(sock, b"> ").decode("utf-8", errors="replace")
            censored, full = parse_archive(challenge_text)
            state, elapsed, free_bits, checked = recover_initial_state_from_archive(censored, full)
            _, _, answer = predict_future(state)
            sock.sendall((" ".join(map(str, answer)) + "\n").encode())
            result_text = recv_rest(sock).decode("utf-8", errors="replace")

    return {
        "challenge": challenge_text,
        "solve_time": elapsed,
        "free_bits": free_bits,
        "checked": checked,
        "answer": answer,
        "result": result_text,
    }


def self_test(rounds: int):
    for index in range(rounds):
        archive, today, answer = generate_synthetic_instance()
        censored = [[value % 8 for value in draw] for draw in archive[:N_CENSORED]]
        full_draws = archive[N_CENSORED:]
        state, elapsed, free_bits, checked = recover_initial_state_from_archive(
            censored, full_draws
        )
        predicted_archive, predicted_today, predicted_answer = predict_future(state)
        if predicted_archive != archive:
            raise RuntimeError(f"archive mismatch on round {index}")
        if predicted_today != today:
            raise RuntimeError(f"today mismatch on round {index}")
        if predicted_answer != answer:
            raise RuntimeError(f"answer mismatch on round {index}")
        print(
            f"round {index + 1}: solved in {elapsed:.2f}s, "
            f"free_bits={free_bits}, checked={checked}, answer={' '.join(map(str, answer))}"
        )


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--self-test", type=int, default=0)
    parser.add_argument("--stdin", action="store_true", help="parse challenge text from stdin")
    parser.add_argument("--remote", action="store_true", help="solve the remote service end-to-end")
    parser.add_argument("--host", default="streams.tamuctf.com")
    parser.add_argument("--port", type=int, default=443)
    parser.add_argument("--sni", default="tinyball")
    args = parser.parse_args()

    if args.self_test:
        self_test(args.self_test)
        return

    if args.stdin:
        text = sys.stdin.read()
        censored, full_draws = parse_archive(text)
        state, elapsed, free_bits, checked = recover_initial_state_from_archive(
            censored, full_draws
        )
        _, _, answer = predict_future(state)
        print(f"solve_time={elapsed:.2f}s")
        print(f"free_bits={free_bits}")
        print(f"checked={checked}")
        print("answer:", " ".join(map(str, answer)))
        return

    if args.remote:
        result = solve_remote(args.host, args.port, sni=args.sni)
        print(f"solve_time={result['solve_time']:.2f}s")
        print(f"free_bits={result['free_bits']}")
        print(f"checked={result['checked']}")
        print("answer:", " ".join(map(str, result["answer"])))
        print(result["result"], end="" if result["result"].endswith("\n") else "\n")
        return

    parser.error("pick --self-test, --stdin, or --remote")


if __name__ == "__main__":
    main()
