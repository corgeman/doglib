# dog fetch
`dog fetch` can be used to quickly find and optionally apply debug symbols for a given libc/ld:

```bash
corgo@dog-computer:/tmp/test$ ls
libc.so.6
corgo@dog-computer:/tmp/test$ dog fetch ./libc.so.6 --dbg
/tmp/test/ld-2.39.so
[+] Debug symbols applied to libc '/tmp/test/libc.so.6'.
[+] Debug symbols applied to ld '/tmp/test/ld-2.39.so'.
corgo@dog-computer:/tmp/test$ ls
ld-2.39.so  libc.so.6
corgo@dog-computer:/tmp/test$ file ./libc.so.6 | grep -o 'with debug_info.*'
with debug_info, not stripped
```

this is quite similar to what [pwninit](https://github.com/io12/pwninit) does, but it can additionally:

*  find debian-based libcs (i'm sure you've ran into this at least once)
*  find archived libcs (ones that have been superseded by minor security patches/updates)
*  find libc given only ld


## help

```bash
corgo@dog-computer:/tmp/test$ dog fetch --help
usage: dog fetch [-h] [--ld LD] [--dbg] [-f] [-o PATH] FILE

Auto-detects whether FILE is a libc or ld linker by scanning for the embedded glibc 
version string, then downloads the missing counterpart from Ubuntu/Debian package mirrors. 
With --dbg, also fetches and applies debug symbols from the libc6-dbg package.

positional arguments:
  FILE            Path to a glibc artifact (libc or ld linker)

options:
  -h, --help      show this help message and exit
  --ld LD         Explicitly provide the ld linker (when FILE is a libc)
  --dbg           Also download and apply debug symbols from libc6-dbg
  -f, --force     Re-apply debug symbols even if .debug_info already present
  -o, --out PATH  Where to write the fetched counterpart (default: next to FILE)
```