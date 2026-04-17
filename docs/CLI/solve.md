# dog solve
`dog solve` is a very simple drop-in replacement for [pwninit](https://github.com/io12/pwninit)'s solve template generator. it works practically the exact same, format and all, but it won't automatically try to detect libc/ld.

## help

```bash
corgo@dog-computer:/tmp$ dog solve --help
usage: dog solve [-h] --bin PATH [--libc PATH] [--ld PATH] --template PATH [--out PATH] [--no-overwrite]

Fills in TEMPLATE with ELF bindings for the given binary, libc, and ld, then writes the result to OUTPUT (default: solve.py). Does nothing if the output file already
exists and --no-overwrite is passed.

options:
  -h, --help       show this help message and exit
  --bin PATH       Path to the binary (becomes the 'exe' ELF binding)
  --libc PATH      Path to the libc (becomes the 'libc' ELF binding)
  --ld PATH        Path to the ld linker (becomes the 'ld' ELF binding)
  --template PATH  Path to the template file
  --out PATH       Output path (default: solve.py)
  --no-overwrite   Do nothing if the output file already exists
```