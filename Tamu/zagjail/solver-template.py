from pwn import *

io = remote("streams.tamuctf.com", 443, ssl=True, sni="zagjail")
io.interactive(prompt="")
