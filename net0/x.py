#!/usr/bin/env python3
from pwn import *

r = remote("127.0.0.1", 64000)
r.recvuntil(b"'")
num = r.recvuntil(b"'", drop=True).decode("ascii")
num = int(num)
r.clean()
r.sendline(p32(num))
print(r.recvline().decode("ascii"))
