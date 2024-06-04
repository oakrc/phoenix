#!/usr/bin/env python3
from pwn import *

# context.log_level = "debug"
context.arch = "amd64"

r = remote("127.0.0.1", 64002)
r.recvline()
r.recvline()
sum = 0
for i in range(8):
    sum += int(r.unpack())
r.pack(sum & (2**64 - 1))
print(r.recvline().decode("ascii"))
