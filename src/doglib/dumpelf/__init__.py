"""
doglib.dumpelf -- Remote ELF dumper.

Given an arbitrary-read primitive and a known pointer into a remote
process, dump the loaded ELF segments and reconstruct a valid ELF
file with section headers and a patched GOT.  Optionally identify
the remote libc via build ID or version string.

Usage::

    from doglib.dumpelf import DumpELF

    d = DumpELF(leak_func, known_ptr)
    d.dump('output.elf')         # dump + reconstruct
    libc = d.libc                # identify + download remote libc
    d.dump_lib('libc', 'libc.so.6')  # dump a specific library
"""
from doglib.dumpelf._dumper import DumpELF

__all__ = ["DumpELF"]
