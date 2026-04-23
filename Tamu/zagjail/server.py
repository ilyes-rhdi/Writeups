#!/usr/bin/env python3
import os
import re
import tempfile
import subprocess

ZAG_BINARY      = os.environ.get("ZAG_BINARY", "/app/zag")
MAX_SRC_SIZE    = 32 * 1024  # 32 KB
COMPILE_TIMEOUT = 10         # seconds

BANNER = """\
=== Zag Jail ===
Submit your Zag source code. End with <EOF>.
Rules:
  - extern is not allowed
  - pointer arithmetic (p + N, p - N) is not allowed, that would be too easy :)
  - out-of-bounds subscript accesses are not allowed
===
"""

TYPE_SIZES = {
    'i8': 1,  'u8': 1,
    'i16': 2, 'u16': 2,
    'i32': 4, 'u32': 4,
    'i64': 8, 'u64': 8,
    'f32': 4, 'f64': 8,
}


def die(msg: str) -> None:
    print(msg)
    raise SystemExit(1)


class PtrState:
    __slots__ = ('origin', 'length', 'elem_size', 'index', 'tainted')

    def __init__(self, origin: str, length: int, elem_size: int, index: int = 0):
        self.origin    = origin
        self.length    = length
        self.elem_size = elem_size
        self.index     = index
        self.tainted   = False

    def clone(self) -> 'PtrState':
        s = PtrState(self.origin, self.length, self.elem_size, self.index)
        s.tainted = self.tainted
        return s


# Master tokeniser: alternatives tried left-to-right, most specific first.
_TOKEN = re.compile(
    r'(?P<STR>"(?:[^"\\]|\\.)*")'
    r"|(?P<CHR>'(?:[^'\\]|\\.)*')"
    r"|(?P<CTRL>\b(?:while|if)\b)"
    r"|(?P<ELSE>\belse\b)"
    r"|(?P<OPEN>\{)"
    r"|(?P<CLOSE>\})"
    r"|(?P<VPI>\bvar\s+\w+\s*:\s*\*\w+\s*=\s*&\w+\s*\[\d+\])"
    r"|(?P<VPB>\bvar\s+\w+\s*:\s*\*\w+\s*=\s*&\w+(?!\s*\[))"
    r"|(?P<VPC>\bvar\s+\w+\s*:\s*\*\w+\s*=\s*\w+)"
    r"|(?P<RAI>\b\w+\s*=\s*&\w+\s*\[\d+\])"
    r"|(?P<RAB>\b\w+\s*=\s*&\w+(?!\s*\[))"
    r"|(?P<PTRASSIGN>\b\w+\s*=\s*\w+\b(?!\s*[+\-]))"
    r"|(?P<POSTINC>\b\w+\+\+)"
    r"|(?P<PREINC>\+\+\w+\b)"
    r"|(?P<POSTDEC>\b\w+--)"
    r"|(?P<PREDEC>--\w+\b)"
    r"|(?P<SUB>\b\w+\s*\[\d+\])"
    r"|(?P<VSUB>\b\w+\s*\[[^\]]*\])"
    r"|(?P<DEREF>\*\w+\b)"
    r"|(?P<ARITH>\b\w+\s*[+\-](?![+\-=]))"
)

_re = {
    'VPI':        re.compile(r'var\s+(\w+)\s*:\s*\*(\w+)\s*=\s*&(\w+)\s*\[(\d+)\]'),
    'VPB':        re.compile(r'var\s+(\w+)\s*:\s*\*(\w+)\s*=\s*&(\w+)'),
    'VPC':        re.compile(r'var\s+(\w+)\s*:\s*\*(\w+)\s*=\s*(\w+)'),
    'RAI':        re.compile(r'(\w+)\s*=\s*&(\w+)\s*\[(\d+)\]'),
    'RAB':        re.compile(r'(\w+)\s*=\s*&(\w+)'),
    'PTRASSIGN':  re.compile(r'(\w+)\s*=\s*(\w+)'),
    'INCDEC':     re.compile(r'(\w+)'),
    'SUB':        re.compile(r'(\w+)\s*\[(\d+)\]'),
    'VSUB':       re.compile(r'(\w+)\s*\[([^\]]*)\]'),
    'DEREF':      re.compile(r'\*(\w+)'),
    'ARITH':      re.compile(r'(\w+)'),
}


def check_pointer_safety(src: str) -> None:
    src = re.sub(r'//[^\n]*', '', src)

    arrays: dict[str, tuple[int, int]] = {}
    for m in re.finditer(r'\bvar\s+(\w+)\s*:\s*\[(\d+)\](\w+)', src):
        arrays[m.group(1)] = (int(m.group(2)), TYPE_SIZES.get(m.group(3), 8))

    scalars: dict[str, int] = {}
    for m in re.finditer(r'\bvar\s+(\w+)\s*:\s*([a-z]\w*)(?!\s*[\[*])', src):
        name, t = m.group(1), m.group(2)
        if name not in arrays and t in TYPE_SIZES:
            scalars[name] = TYPE_SIZES[t]

    def resolve(name: str) -> tuple[int, int] | None:
        if name in arrays:  return arrays[name]
        if name in scalars: return (1, scalars[name])
        return None

    ptrs: dict[str, PtrState] = {}
    ctx: list[bool] = []
    last_ctrl = False

    def in_cond() -> bool:
        return any(ctx)

    def bounds_check(name: str, offset: int, what: str) -> None:
        if name not in ptrs:
            return
        s = ptrs[name]
        if s.tainted:
            die(f"Rejected: '{name}' was mutated inside a loop or conditional; "
                f"subscript access is not allowed on tainted pointers.")
        access = s.index + offset
        if access < 0 or access >= s.length:
            die(f"Rejected: {what} accesses tracked index "
                f"{s.index}{'+' if offset >= 0 else ''}{offset} = {access}, "
                f"out of bounds for '{s.origin}' (length {s.length}).")

    for m in _TOKEN.finditer(src):
        k   = m.lastgroup
        txt = m.group(0)

        if k in ('STR', 'CHR'):
            last_ctrl = False
        elif k == 'CTRL':
            last_ctrl = True
        elif k == 'ELSE':
            last_ctrl = True
        elif k == 'OPEN':
            ctx.append(last_ctrl)
            last_ctrl = False
        elif k == 'CLOSE':
            if ctx: ctx.pop()
            last_ctrl = False
        else:
            last_ctrl = False

            if k == 'VPI':
                name, t, arr, idx = _re['VPI'].search(txt).groups()
                info = resolve(arr)
                if info:
                    length, _ = info
                    init_idx = int(idx)
                    if init_idx < 0 or init_idx >= length:
                        die(f"Rejected: initial pointer index {init_idx} is out of bounds "
                            f"for '{arr}' (length {length}).")
                    ptrs[name] = PtrState(arr, length, TYPE_SIZES.get(t, 8), init_idx)
                else:
                    die(f"Rejected: '{arr}' is not a known array or scalar.")

            elif k == 'VPB':
                name, t, arr = _re['VPB'].search(txt).groups()
                info = resolve(arr)
                if info:
                    ptrs[name] = PtrState(arr, info[0], TYPE_SIZES.get(t, 8))
                else:
                    die(f"Rejected: '{arr}' is not a known array or scalar.")

            elif k == 'VPC':
                name, t, src_ptr = _re['VPC'].search(txt).groups()
                if src_ptr in ptrs:
                    src = ptrs[src_ptr]
                    new_elem = TYPE_SIZES.get(t, 8)
                    total_bytes = src.length * src.elem_size
                    byte_offset = src.index * src.elem_size
                    new_length = total_bytes // new_elem
                    new_index  = byte_offset // new_elem
                    ptrs[name] = PtrState(src.origin, new_length, new_elem, new_index)
                    ptrs[name].tainted = src.tainted
                else:
                    die(f"Rejected: '{src_ptr}' is not a tracked pointer.")

            elif k == 'RAI':
                ptr, arr, idx = _re['RAI'].search(txt).groups()
                if ptr in ptrs:
                    info = resolve(arr)
                    if info:
                        ptrs[ptr].origin  = arr
                        ptrs[ptr].length  = info[0]
                        ptrs[ptr].index   = int(idx)
                        ptrs[ptr].tainted = False

            elif k == 'RAB':
                ptr, arr = _re['RAB'].search(txt).groups()
                if ptr in ptrs:
                    info = resolve(arr)
                    if info:
                        ptrs[ptr].origin  = arr
                        ptrs[ptr].length  = info[0]
                        ptrs[ptr].index   = 0
                        ptrs[ptr].tainted = False

            elif k == 'PTRASSIGN':
                ptr, rhs = _re['PTRASSIGN'].search(txt).groups()
                if ptr in ptrs:
                    if in_cond():
                        ptrs[ptr].tainted = True
                    elif rhs in ptrs:
                        ptrs[ptr] = ptrs[rhs].clone()
                    else:
                        ptrs[ptr].tainted = True

            elif k in ('POSTINC', 'PREINC'):
                name = _re['INCDEC'].search(txt).group(1)
                if name in ptrs:
                    if in_cond(): ptrs[name].tainted = True
                    else:         ptrs[name].index += 1

            elif k in ('POSTDEC', 'PREDEC'):
                name = _re['INCDEC'].search(txt).group(1)
                if name in ptrs:
                    if in_cond(): ptrs[name].tainted = True
                    else:         ptrs[name].index -= 1

            elif k == 'SUB':
                name, idx = _re['SUB'].search(txt).groups()
                idx = int(idx)
                if name in arrays:
                    length, _ = arrays[name]
                    if idx < 0 or idx >= length:
                        die(f"Rejected: '{name}[{idx}]' is out of bounds "
                            f"for '{name}' (length {length}).")
                elif name in ptrs:
                    bounds_check(name, idx, f"'{name}[{idx}]'")
                else:
                    die(f"Rejected: subscript on untracked variable '{name}'.")

            elif k == 'VSUB':
                name, expr = _re['VSUB'].search(txt).groups()
                if name in arrays:
                    die(f"Rejected: non-literal subscript '{name}[{expr.strip()}]' "
                        f"on array '{name}'.")
                elif name in ptrs:
                    die(f"Rejected: non-literal subscript '{name}[{expr.strip()}]' "
                        f"on tracked pointer '{name}'.")
                else:
                    die(f"Rejected: subscript on untracked variable '{name}'.")

            elif k == 'DEREF':
                name = _re['DEREF'].search(txt).group(1)
                if name in TYPE_SIZES:
                    pass  # type annotation (*u32 etc.), not a dereference
                elif name in ptrs:
                    bounds_check(name, 0, f"'*{name}'")
                else:
                    die(f"Rejected: dereference of untracked pointer '{name}'.")

            elif k == 'ARITH':
                name = _re['ARITH'].search(txt).group(1)
                if name in ptrs:
                    die(f"Rejected: explicit pointer arithmetic on '{name}';")


def validate(src: str) -> None:
    if re.search(r'\bextern\b', src):
        die("Rejected: 'extern' is not allowed.")
    check_pointer_safety(src)


def main() -> None:
    print(BANNER, end="")

    lines = []
    total = 0
    try:
        while True:
            line = input()
            if line == '<EOF>':
                break
            line += '\n'
            total += len(line.encode())
            if total > MAX_SRC_SIZE:
                die("Error: source too large (max 32 KB).")
            lines.append(line)
    except EOFError:
        pass

    src_text = "".join(lines)
    validate(src_text)

    with tempfile.TemporaryDirectory(prefix="zagjail_") as tmpdir:
        src_path = os.path.join(tmpdir, "program.zag")
        bin_path = os.path.join(tmpdir, "program")

        with open(src_path, "w") as f:
            f.write(src_text)

        print("Compiling...")
        try:
            result = subprocess.run(
                [ZAG_BINARY, src_path, "-o", bin_path],
                capture_output=True,
                text=True,
                timeout=COMPILE_TIMEOUT,
            )
        except subprocess.TimeoutExpired:
            die("Error: compilation timed out.")
        except FileNotFoundError:
            die("Error: compiler not found.")

        if result.returncode != 0:
            print("Compilation failed:")
            print(result.stderr[:2048])
            raise SystemExit(1)

        # check if the binary was actually created
        if not os.path.isfile(bin_path):
            die("Error: compiled binary not found, did you break the compiler :p")

        print("Running...")
        os.execv(bin_path, [bin_path])


if __name__ == "__main__":
    main()
