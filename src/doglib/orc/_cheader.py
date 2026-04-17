"""
ORCHeader and ORCInline: compile C headers to DWARF ELFs for type resolution.
"""
import os
import hashlib
import struct
import subprocess
from pwnlib.log import getLogger
from pwnlib.context import context

from ._orc import ORC

log = getLogger(__name__)


class ORCHeader(ORC):
    """
    Takes a C header file, automatically compiles it into a temporary ELF
    with DWARF symbols via GCC, and wraps it in an ORC interface.

    Accepts optional include_dirs for headers that #include other files.
    Pass bits=32 to compile for 32-bit targets. If not provided, uses
    context.bits when the user has explicitly set context.arch or
    context.bits, otherwise falls back to the host architecture.
    """
    def __init__(self, header_path: str | os.PathLike, include_dirs=None, bits=None):
        header_path = os.path.abspath(header_path)
        if not os.path.exists(header_path):
            raise FileNotFoundError(f"Header file not found: {header_path}")

        with open(header_path, 'rb') as f:
            header_data = f.read()

        host_bits = struct.calcsize('P') * 8
        if bits is None:
            if 'bits' in vars(context):
                bits = context.bits
            else:
                bits = host_bits

        hash_input = header_data + str(bits).encode()
        if include_dirs:
            for d in sorted(os.path.abspath(d) for d in include_dirs):
                hash_input += b'|' + d.encode()
                for root, _, files in os.walk(d):
                    for fname in sorted(files):
                        fpath = os.path.join(root, fname)
                        try:
                            hash_input += os.path.relpath(fpath, d).encode()
                            with open(fpath, 'rb') as inc:
                                hash_input += inc.read()
                        except OSError:
                            pass
        header_hash = hashlib.sha256(hash_input).hexdigest()[:16]

        orc_cache_dir = os.path.join(context.cache_dir, 'orc_cache')
        os.makedirs(orc_cache_dir, exist_ok=True)

        elf_path = os.path.join(orc_cache_dir, f"orcheader_{header_hash}.elf")

        if not os.path.exists(elf_path):
            log.info(f"Compiling {os.path.basename(header_path)} to DWARF ELF...")
            try:
                cmd = ['gcc', '-x', 'c', '-c', '-g', '-fno-eliminate-unused-debug-types']
                if bits != host_bits:
                    cmd.append(f'-m{bits}')
                if include_dirs:
                    for d in include_dirs:
                        cmd.extend(['-I', os.path.abspath(d)])
                cmd.extend([header_path, '-o', elf_path])
                subprocess.run(cmd, check=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
            except FileNotFoundError:
                log.exception("Failed to compile header: 'gcc' is not installed or not in PATH.")
            except subprocess.CalledProcessError as e:
                log.exception(f"GCC failed to compile the header:\n{e.stderr.decode() if e.stderr else ''}")

        super().__init__(elf_path, bits=bits)


class ORCInline(ORCHeader):
    """
    Like ORCHeader but accepts C source code directly as a string instead of a
    file path. Types are compiled to DWARF on the fly and cached by content
    hash, so repeated calls with identical source never recompile.

    Example:
        types = ORCInline('''
            typedef struct chunk {
                size_t prev_size;
                size_t size;
                struct chunk *fd, *bk;
            } chunk;
        ''')
        c = types.craft('chunk')
        c.size = 0x21

    # 32-bit layout
    types32 = ORCInline('typedef struct foo { int x; } foo;', bits=32)
    """
    def __init__(self, source, bits=None):
        import tempfile
        src_bytes = source.encode() if isinstance(source, str) else bytes(source)
        with tempfile.NamedTemporaryFile(suffix='.h', prefix='cinline_') as f:
            f.write(src_bytes)
            f.flush()
            super().__init__(f.name, bits=bits)
