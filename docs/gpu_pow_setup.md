# gpu pow

this library contains some efficient SHA256/SHA1 code in CUDA to help solve hash-based proof of work systems  
in my tests it's very close to hashcat speeds (`hashcat -b -m [1420/120]`)  
it also works on wsl2!

## prereqs
to install this you'll need:
- a nvidia gpu. sorry but it's the only thing supported on wsl and even on non-wsl it's not easy
- nvidia drivers. if you're on WSL all you need are the windows drivers installed ([source](https://docs.nvidia.com/cuda/wsl-user-guide/index.html#nvidia-compute-software-support-on-wsl-2))
- nvidia's cuda toolkit. download [here](https://developer.nvidia.com/cuda-downloads)
- rust and maturin (`pip install maturin` or `apt install python3-maturin`)

## building
you can build and install the library with:
```sh
cd src/doglib_rs
maturin build --release --features cuda # it will spit out 'built wheel to <BLAH>'
pip install /path/to/built/wheel/file.whl
```

### warning: small wsl2 bug
if you get a warning about `nvcc` being unable to find your drivers,  
```sh
export LD_LIBRARY_PATH="/usr/lib/wsl/lib:$LD_LIBRARY_PATH"
```
should hopefully fix your problems.

## testing
everything should be set up! if you want to test your speeds, you can run
```sh
cargo run --release --features cuda --example gpu_bench
```
which should report your expected hashrate. if you wanna test sha256 set `GPU_BENCH_ALGO=sha256`.

## using
now you should hopefully be able to use this through `doglib_rs`:
```python
>>> from doglib_rs import pow_solver
>>> # find X such that the first 32 bits of sha1(b'wooting'+X) are 0
>>> pow_solver.hash_bruteforce(b"wooting", "sha1", 32, "leading", "numeric")
b'570502797'
>>>
>>> from hashlib import sha1
>>> sha1(b'wooting'+b'570502797').hexdigest()
>>> '00000000495200a10f8d2baca4148da60bcdcb22'
```
and if you're using this for a well-known POW, say [socaz](https://hub.docker.com/r/cybersecnatlab/socaz), `do_pow` might be all you need:
```bash
corgo@dog-computer:~$ nc localhost 1089
    Do Hashcash for 30 bits with resource "udtAjLfhDpIu"
    Result: ^C
corgo@dog-computer:~$ echo ERMMMMMM
    ERMMMMMM
corgo@dog-computer:~/pwn/.config/doglib/research/testpow$ cat ./testpow.py
    from dog import *
    p = do_pow(remote("localhost",1089))
    p.interactive()
corgo@dog-computer:~/pwn/.config/doglib/research/testpow$ python3 ./testpow.py DEBUG
    [+] Opening connection to localhost on port 1089: Done
    [DEBUG] Received 0x98 bytes:
        b'Do Hashcash for 30 bits with resource "9wLIFMcmGci4"\n'
        b'Result: '
    [DEBUG] Sent 0x2f bytes:
        b'1:30:260331:9wLIFMcmGci4::k-K0GHpmBSo:378f7f70\n'
    [*] Switching to interactive mode
    [DEBUG] Received 0x12 bytes:
        b'Write your code > '
```

## notes
since we are trying to go as fast as possible some very long prefixes (len(prefix)%64 >= 50) will not work with this kernel and you will be forced back to the CPU. you will be warned if this happens. if this is a problem you can try decreasing `MAX_SUFFIX_LEN` inside of `constants.rs`  
if you know some common POWs that `do_pow` doesn't cover, make an issue/pr. some i am aware of
- [0ctf](https://ctftime.org/writeup/29116): doable in hashcat, so probably won't add (at least for GPU)