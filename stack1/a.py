#!/usr/bin/env python3
from pwn import *

io = process(["/opt/phoenix/amd64/stack-one", cyclic(100)])
print(io.recvline().decode("ascii"))
print(io.recvline().decode("ascii"))
