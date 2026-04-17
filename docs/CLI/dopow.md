# dog dopow
`dog dopow` is like `netcat` with proof-of-work solving powers.  
it takes a hostname and port, which it will connect to and attempt to auto-solve its proof of work, then drop you into interactive mode:
```bash
corgo@dog-computer:/tmp$ nc localhost 5000
    proof of work: curl -sSfL https://pwn.red/pow | sh -s s.AAAB9A==.aB8l8ynAt+Q2IN8RV1L+EQ==
    solution: ^C
corgo@dog-computer:~/tmp$ dog dopow localhost 5000
    Welcome! Please enter your name: ^C
corgo@dog-computer:/tmp$
```
this is useful if you're too lazy to write a solve script and would just rather talk to the server yourself

## help

```bash
corgo@dog-computer:/tmp$ dog dopow --help
usage: dog dopow [-h] [-v] HOST PORT

Connects to HOST on PORT, waits for and solves any recognised proof-of-work challenge, then hands control to you interactively.

positional arguments:
  HOST           Remote hostname or IP
  PORT           Remote port

options:
  -h, --help     show this help message and exit
  -v, --verbose  Show connection and PoW progress info
```