# gauntlet3 - Full Writeup

## TL;DR

The binary has a two-stage bug chain:

1. `printf(user_input)` format-string leak
2. `strcpy(stack_buf, user_input)` stack overflow

I used stage 1 to leak libc, then stage 2 to overwrite RIP with a libc one-gadget.  
Because one-gadget constraints vary by runtime state, I try multiple gadget offsets with retries until a shell is stable.

Remote flag:

`922f936b9911812111eb648e30917b7c`

---

## 1. Setup and binary info

Files provided:

- `gauntlet_patched_patched`
- `libc-2.27.so`
- `ld-2.27.so`

Security profile (`checksec`):

- Partial RELRO
- No stack canary
- NX enabled
- No PIE

Implication:

- Return address overwrite is possible.
- We need code-reuse (NX is on).

---

## 2. Reversing main logic

From disassembly of `main`:

1. `buf = malloc(0x3e8)`
2. `fgets(buf, 0x3e8, stdin)`
3. `printf(buf)`  <- format string vuln
4. `fgets(buf, 0x3e8, stdin)`
5. `strcpy(local_stack_buf, buf)` <- overflow
6. `ret` (controlled RIP)

So exploitation plan is straightforward:

- First input: leak libc pointer.
- Second input: overflow return address and jump to useful libc code.

---

## 3. Finding a good libc leak index

I enumerated format arguments:

```python
'.'.join([f'%{i}$p' for i in range(1,50)])
```

You usually see many `0x7f...` values, but not all are equally useful.  
I selected index **23** because it passed three checks:

1. Stable pattern across runs (same low bytes trend).
2. Produced a sensible page-aligned libc base after subtraction.
3. Using that base made exploitation work in practice.

Chosen leak:

- `%23$p` -> leaked pointer
- libc base calc used in exploit:

`libc_base = leak - 0x21c87`

Where `0x21c87` corresponds to the leaked return-site offset in libc (`__libc_start_main`-related frame).

---

## 4. Overflow offset

Using cyclic pattern + corefile:

- RIP overwrite offset = **120 bytes**

So payload layout is:

`b"A"*120 + <new RIP>`

---

## 5. Why not classic ret2libc chain?

At first glance, `pop rdi; ret; "/bin/sh"; system` should work.  
In this binary, overflow goes through `strcpy`, and `strcpy` stops at first null byte.

That makes long packed-pointer chains fragile/truncated depending on where `\x00` appears during copy.  
To avoid this, I use a short payload that only needs to land a one-gadget jump.

---

## 6. One-gadget constraints: how I handled them

I extracted candidates from provided libc:

- `0x4f302`
- `0x4f2a5`
- `0x10a2fc`
- `0x4f29e`
- `0x4f297`

Important point: one-gadget constraints are **state-dependent** (registers/stack/argv/envp), and runtime state changes between runs, especially remote.

So I do not assume one gadget always works.  
I verify dynamically:

1. Jump to gadget.
2. Send `echo PWNED`.
3. If `PWNED` appears, gadget constraints were satisfied for that run.
4. If EOF/crash, try next gadget / retry connection.

This is why script tries multiple gadgets and retries loops.

---

## 7. Exploit script logic (`solve.py`)

Current script:

- Local/remote connect helper.
- Leak via `%23$p`.
- Compute libc base with `0x21c87`.
- Build overflow payload:
  - `A * 120 + p64(libc_base + gadget_off)`
- Send payload.
- Probe shell with `echo PWNED`.
- If success:
  - interactive mode, or
  - run `CMD='...'` automatically.
- Otherwise retry.

This makes exploitation robust instead of one-shot fragile.

---

## 8. Run commands

Local interactive:

```bash
python3 solve.py LOCAL
```

Local one command:

```bash
python3 solve.py LOCAL CMD='id'
```

Remote interactive:

```bash
python3 solve.py
```

Remote one command:

```bash
python3 solve.py CMD='cat flag.txt'
```

---

## 9. Final result

Remote shell obtained and flag read:

`922f936b9911812111eb648e30917b7c`

---

## 10. Key takeaway

In this challenge, constraints are not fully under attacker control with the chosen short payload style; they depend heavily on runtime state.  
That is exactly why multi-gadget fallback + retries is the correct practical strategy.
