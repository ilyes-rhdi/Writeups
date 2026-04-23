#!/usr/bin/env python3
import os
try:
    from tinymt32 import TinyMT32
except ImportError:
    exit("Error: tinymt32.py not found. Place it in the same directory.")


BALLS = [25, 48, 60, 75, 96, 120]
EMOJIS = '🟥🟧🟨🟩🟦🟪🟫⬜'
N_SAMPLES = 27
N_FULL = 10
N_CENSORED = N_SAMPLES - N_FULL

FLAG = open("flag.txt").read().strip()


def make_draw(rng: TinyMT32) -> list[int]:
    return [rng.raw() % m for m in BALLS]


def fmt_full(nums: list[int]) -> str:
    return "  ".join(f"{n:3d}" for n in nums)


def fmt_censored(nums: list[int]) -> str:
    return "   ".join(EMOJIS[n % 8] for n in nums)


def main():
    rng = TinyMT32(0xf10c70)
    new_state = tuple(int.from_bytes(os.urandom(4), 'little') for _ in range(4)) + (rng.getstate()[4], )
    rng.setstate(new_state)

    archive = [make_draw(rng) for _ in range(N_SAMPLES)]
    today = make_draw(rng) 
    answer = make_draw(rng)

    W = 31
    print(f'╔{"═"*W}╗')
    print(f'║{"🎰  TINYBALL DELUXE  🎰":^{W-2}}║')
    print(f'║{"Now's your chance to be a":^{W}}║')
    print(f'║{"𝔹𝕀𝔾 𝕊ℍ𝕆𝕋":^{W}}║')
    print(f'╚{"═"*W}╝')
    print()

    print(f'  ┌── Archived Draws {"─"*(W-19)}┐')
    for i, draw in enumerate(archive):
        if i < N_CENSORED:
            line = f'  │ {fmt_censored(draw)}  │'
        else:
            line = f'  │ {fmt_full(draw)} │'
        print(line)
    print(f'  └{"─"*(W-1)}┘')
    print()

    print(f'  ┌── Today\'s Draw {"─"*(W-17)}┐')
    print( '  │ Sorry... come back tomorrow  │')
    print(f'  └{"─"*(W-1)}┘')
    print()

    print("Enter your prediction for tomorrow's draw:")
    try:
        _input = input("> ").split()
        predicted = list(map(int, _input))
    except (ValueError, EOFError):
        print("Invalid input.")
        return

    if predicted == answer:
        print("  ✓  Correct! You predicted the future!")
        print(f"  🏆  {FLAG}")
    else:
        print("  ✗  Wrong. Try your luck again tomorrow!")


if __name__ == "__main__":
    main()
