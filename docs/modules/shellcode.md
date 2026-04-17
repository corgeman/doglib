# shellcode

this contains some niche but useful shellcode

# API

## `#!python minshell: ShellcodeSet`
a very tiny shell as position-independent shellcode. useful for seccomp jails where you can't `execve/execveat`.
```python
>>> shellcode.minshell
ShellcodeSet('minshell', arches = 
    ['aarch64', 'amd64', 'arm', 
    'armeb', 'i386', 'mips', 
    'mipsel', 'powerpc', 'ppcel'])
>>> len(shellcode.minshell.amd64)
1275
>>>
```
the list of supported commands are:

*  `cat`: read files
*  `ls`: list files
*  `cd`: change directory
*  `exit`: quit
*  anything else is treated as a command to execute
    *  type `tg` to use execveat() over execve()

## `#!python runcmd(cmd: str, ctx: str | None = None) -> bytes`
shorthand for `#!python linux.execve("/bin/sh", ["/bin/sh", "-c", cmd], 0)`; run `cmd` in a shell

## `#!python listdir(path: str, size: int = 0x1000, ctx: str | None = None) -> bytes`
list all files in the directory `path` by dumping the raw `dirent` structs to stdout, which `pwnlib.util.dirents` can parse into clean filenames. `size` is how much stack space you'd like to allocate, the higher the more files can be read

## `#!python bash_shellcode(asm: bytes, compress: bool = False) -> str`
wrapper around [this](https://github.com/nobodyisnobody/docs/tree/main/linux.tricks/Bash.shellcode.injection.oneliner) to run arbitrary shellcode in bash only using `base64`, `dd`, and `cut`. set `compress` to true if you'd like your shellcode to be gzip-compressed.
