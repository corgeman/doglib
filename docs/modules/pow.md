# pow

`pow` contains highly efficient solvers for every common ctf proof-of-work system:

*  an incredibly fast solver likely implemended in rust or cuda
*  a slow but pure-python solver to be used as a fallback


we currently support the following proof-of-works:

*  [`kctf`](github.com/google/kctf/blob/v1/docker-images/challenge/pow.py)
*  [`redpwn`](https://github.com/redpwn/jail/blob/main/internal/server/proxy.go#L83)
*  [`sossette`](https://github.com/FCSC-FR/sossette/blob/main/src/pow.rs)
*  [`cybersecnatlab/challenge-jail`](https://hub.docker.com/r/cybersecnatlab/challenge-jail)
*  `hxpctf`


if this library is missing a common proof-of-work i'm unaware of, feel free to make an issue or pr!

# API

## `#!python detect_and_solve(data: bytes | str) -> bytes | None`
given a dump of data `bytes`, scan for a known POW challenge, solve it, and return the correct response

## `#!python do_pow(p: tube) -> tube`
wrap this around a pwntools `tube` object to automatically solve the proof of work. it returns the `tube` object passed, so you can write something like this:
```python
from dog import *
p = do_pow(remote("whatever.pwn.local",11037))
# ... continue exploiting ...
```
if there is no POW, the connection will hang.