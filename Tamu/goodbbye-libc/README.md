# goodbye-libc Write-Up

This folder now contains the solved exploit for the `goodbye-libc` challenge.

Remote flag:

```text
gigem{flamepyromancer_didnt_change_the_default_flag}
```

Local test flag:

```text
TESTFLAG{local_success}
```

## Files

- `goodbye-libc.c`: main challenge source
- `bye-libc.c`: tiny custom libc-like shared object
- `goodbye-libc`: challenge binary
- `libbye-libc.so`: shared object used by the binary
- `ta.py`: working remote solver

## Protections

`goodbye-libc` has:

- Full RELRO
- NX
- PIE
- No canary

So a normal GOT overwrite is out, and a direct static ret2win does not exist.

## Root Cause

The core bug is in `input_index()` in [`goodbye-libc.c`](/home/ilyes/Downloads/Tamu/goodbbye-libc/goodbye-libc.c).

It parses decimal input into a signed `int`:

```c
int choice = 0;
choice = 10*choice + (input[i]-'0');
```

and then accepts:

```c
if (choice <= 3 && choice >= -2) {
    return choice-1;
}
```

Because `choice` is a 32-bit signed integer, large decimal values wrap.

Two useful wrapped inputs are:

- `4294967295` -> `choice == -1` -> returned index `-2`
- `4294967294` -> `choice == -2` -> returned index `-3`

That turns the `nums[3]` array into an out-of-bounds read/write primitive on `_start`'s stack frame.

## Useful Stack Slots

In `_start`, `nums` lives on the stack. With the wrapped indices:

- index `-2` reads/writes `rbp-0x48`
- index `-3` reads/writes `rbp-0x50`

These are outside the intended `nums[3]` array.

The important leaks are:

- `PRINT_NUM` with raw input `4294967295`
  - leaks a PIE pointer
  - specifically something at fixed offset `0x1cbd` from the binary base
- `PRINT_NUM` with raw input `4294967294`
  - leaks a stack pointer from `_start`

## Extra Leak

The exploit also uses a same-connection library leak.

By overwriting the saved return address of `write_num()` with a mid-function address inside `_start` (`0x1710` from PIE base), execution resumes in the middle of the add-path where `rcx` still contains a pointer derived from the last syscall wrapper.

That produces output like:

```text
Result of <stack-ish> + <libbye-libc pointer>: ...
```

From that second value, subtracting `0x1065` gives the base of `libbye-libc.so`.

## Exploit Strategy

The final exploit in [`ta.py`](/home/ilyes/Downloads/Tamu/goodbbye-libc/ta.py) does this:

1. Leak PIE base with raw index `4294967295`.
2. Leak a stack pointer with raw index `4294967294`.
3. Leak `libbye-libc.so` base with the `rcx` trick.
4. Use legitimate writes to `nums[0..2]` to preload a tiny stack-pivot chain:
   - `nums[0] = pop rbp ; ret`
   - `nums[1] = stage1_addr`
   - `nums[2] = leave ; ret`
5. Overwrite `write_num()`'s saved RIP using raw index `4294967295` so it returns into `read@plt`.
6. Send stage 1:
   - call `read(0, stage2_addr, 0x200)`
   - pivot into stage 2 with `leave ; ret`
7. Send stage 2:
   - call `read(0, execbuf, 59)`
   - set up registers for `execve("/bin/sh", argv, NULL)`
   - jump to the bare `syscall` gadget inside `libbye-libc.so`
8. Send the final 59-byte buffer:
   - starts with `/bin/sh`
   - also contains `argv = {"/bin/sh", NULL}`
   - because `read()` returns `59`, `rax == 59`, which is already the syscall number for `execve`
9. Send `cat flag.txt; exit`.

## Why The Final Stage Works

The custom library is tiny but very helpful:

- `0x103f`: `pop rdi ; pop rsi ; pop rdx ; ret`
- `0x1039`: `syscall`

There is no normal `pop rax ; ret` in the library, so the exploit avoids needing one by making the last `read()` return exactly `59`.

That leaves:

- `rax = 59`
- `rdi = "/bin/sh"`
- `rsi = argv`
- `rdx = 0`

and the raw `syscall` executes `execve`.

## Running The Solver

Run:

```bash
python3 ta.py
```

It connects to:

```text
streams.tamuctf.com:443
```

with TLS SNI:

```text
goodbye-libc
```

## Notes

- The challenge does not appear to require proof-of-work on this endpoint.
- The solver relies on the service keeping one process alive across menu actions, which the remote challenge does.
- The `core.*` files in this directory were generated during local crash debugging and have been removed.
