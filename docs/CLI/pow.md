# dog pow
some tools for solving proof-of-work systems:

* **`solve`** - given a pow challenge string, detect its format and print its solution
* **`nc`** - like netcat, but will solve the pow before dropping into interactive mode.
* **`check`** - show which solver backends are available 

## nc
```bash
corgo@dog-computer:/tmp$ nc localhost 5000
    proof of work: curl -sSfL https://pwn.red/pow | sh -s s.AAAB9A==.aB8l8ynAt+Q2IN8RV1L+EQ==
    solution: ^C
corgo@dog-computer:/tmp$ dog pow nc localhost 5000
    Welcome! Please enter your name: ^C
```

```
usage: dog pow nc [-h] [-v] HOST PORT

positional arguments:
  HOST           Remote hostname or IP
  PORT           Remote port

options:
  -h, --help     show this help message and exit
  -v, --verbose  Show connection and PoW progress info
```

## solve
```bash
corgo@dog-computer:~$ dog pow solve 's.AAAB9A==.+siar2PJaFdWHvOAeiFMGg=='
s.PW6ref35OeJ2/E8P6hbOD9NcImSjm6....

```

```
usage: dog pow solve [-h] CHALLENGE

positional arguments:
  CHALLENGE   Challenge string (or '-' to read from stdin)

options:
  -h, --help  show this help message and exit
```

## check
```bash
corgo@dog-computer:/tmp$ dog pow check
doglib_rs:     installed (0.1.0)
cuda feature:  compiled in
cuda init:     ok

status: GPU acceleration available
```
