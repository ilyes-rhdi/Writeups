from pwn import *
import subprocess
import requests
import os

io = remote("streams.tamuctf.com", 443, ssl=True, sni="tinyball")

# handle pow
if not os.path.exists('pow_solver.sh'):
    pow_file = requests.get('https://pwn.red/pow').text
    open('pow_solver.sh', 'w').write(pow_file)
    os.chmod('pow_solver.sh', 0o755)
io.recvline()
pow_chal = io.recvline().decode().strip()
# log.info(f"Solving PoW: {pow_chal}")
pow_chal = pow_chal.split()[-1]
result = subprocess.run(['sh', 'pow_solver.sh', pow_chal], capture_output=True, text=True)
if result.returncode != 0:
    log.error(f"PoW solver failed: {result.stderr}")
    exit(1)
pow_sol = result.stdout.strip()
# log.info(f"PoW solution: {pow_sol}")
io.sendlineafter(b'solution: ', pow_sol.encode())

io.interactive(prompt="")
