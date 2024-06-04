#!/usr/bin/env python3
from pwn import *

r = remote("127.0.0.1", 64001)
r.recvline()
n = u32(r.recv(4))
r.sendline(str(n).encode("ascii"))
print(r.recvline().decode("ascii"))
