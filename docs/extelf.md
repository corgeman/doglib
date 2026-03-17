# ExtendedELF & CHeader

DWARF-powered C struct toolkit for pwntools. Craft, parse, and inspect C structures using debug info or raw `.h` files.

---

## Showcase

```python
from doglib.extelf import ExtendedELF, CHeader, C64


libc = ExtendedELF('./libc.so.6') # load types from a binary with debug symbols..
hdrs = CHeader('my_structs.h') # or compile a .h on the fly!
C64 # don't have anything? this has some useful types ready

# using any of these, you can...
# - craft the raw bytes of arbitrary structs
b = libc.craft("tcache_perthread_struct")
b.counts[10] = 1; b.entries[10] = 0x123456789
bytes(b) # correct layout!

# - get important info on structs
hdrs.sizeof('malloc_chunk')           # 0x30
hdrs.offsetof('malloc_chunk', 'fd')   # 0x10 

# - parse leaked bytes into a struct
chunk = libc.parse('malloc_chunk', io.recvn(0x30))
print(chunk.fd)

# - view symbols as structs
arena = libc.sym_obj['main_arena'].bins[3].fd

# - cast addresses as structs
ptr = libc.cast('malloc_chunk', 0x55555555b000)
ptr.fd # 0x55555555b010

# - work with enums
hdrs.enum('State').RUNNING # correct enum value

# - work with complex arrays / types
j = C64.craft("float[3][3]")
j.fill(3.14) # now all indices are 3.14
j[1][1] += 9
j[2] = [3.0,4.0,5.0]
bytes(j) # correct bytes!

# .... and probably even more i'm forgetting

```

---

## Setup

```python
from doglib.extelf import ExtendedELF, CHeader
```

**From a binary with debug symbols:**

```python
libc = ExtendedELF('./libc.so.6')
libc.address = 0x7ffff7a00000  # PIE base slides are respected automatically
```

**From a C header file (compiled to DWARF on the fly):**

```python
structs = CHeader("my_structs.h")

# With include paths for headers that #include other files
structs = CHeader("my_structs.h", include_dirs=["./include"])

# Force 32-bit struct layouts
structs = CHeader("my_structs.h", bits=32)
```

CHeader respects `context.bits` when the user has explicitly set `context.arch` or `context.bits`. Otherwise it defaults to the host architecture. An explicit `bits=` argument always takes priority.

---

## Crafting Structs

Create a zeroed struct and assign fields by name. Supports nested structs, arrays (including multi-dimensional), unions, pointers, floats, enums, and negative/signed values.

```python
chunk = libc.craft('malloc_chunk')
chunk.mchunk_prev_size = 0x420
chunk.fd = 0x123456789
chunk.bk_nextsize = 0x11037
payload = bytes(chunk)  # raw bytes ready to send
```

### Arrays of structs

Craft/parse/cast arrays of any type using either the `count` parameter or C-style array syntax in the type string:

```python
# Flat array via count=
arr = structs.craft('Basic', count=64)
arr[0].field = 42
bytes(arr)  # all 64 elements

# Equivalent type string syntax
arr = structs.craft('Basic[64]')

# Multi-dimensional arrays
mat = structs.craft('Basic[4][8]')
mat[1][2].a = ord('X')
bytes(mat)

# Primitive type arrays
ints = structs.craft('int[100]')
ints[0].value = 0xdeadbeef
ints[42].value = -1

# Parse arrays back
parsed = structs.parse('Basic[4][8]', leaked_data)
parsed[1][2].a.value
```

### Nested structs and arrays

```python
boss = structs.craft('BossFight')
boss.b[1].a = ord('Z')
boss.b[1].b = 999
boss.u.data.raw = b"AAAAAAAW"
```

### Multi-dimensional arrays

```python
final = structs.craft('FinalBoss')
final.matrix[1][2] = 9999
```

### Sub-struct assignment

Assign a crafted struct directly into another struct's field:

```python
header = structs.craft('Basic')
header.a = ord('A')
header.b = 1234

wrapper = structs.craft('Wrapper')
wrapper.header = header  # copies bytes in
wrapper.payload = 0xBEEF
```

### Slice assignment

Assign multiple array elements at once:

```python
arr = structs.craft('ArrayFun')
arr.arr[0:3] = [10, 20, 30]

um = structs.craft('UnionMadness')
um.data.raw[0:4] = b"\xAA\xBB\xCC\xDD"
```

### Integer assignment on arrays

Array elements of primitive types can be assigned integers (or floats) directly:

```python
arr = structs.craft('int[4]')
arr[0] = 111
arr[3] = -42

final = structs.craft('FinalBoss')
final.matrix[1][2] = 9999
```

### OOB writes and the `pad` parameter

Out-of-bounds writes on crafted structs/arrays are allowed but emit a
warning, since they extend the backing buffer. This is intentional for
CTF exploitation scenarios where you need controlled overflow:

```python
arr = structs.craft('int[3][3]')
arr[5][5] = 42  # warns: OOB write extends backing by N bytes
bytes(arr)      # includes the extended region
```

To suppress the warning, pre-allocate extra space with `pad=`:

```python
arr = structs.craft('int[5][6]', pad=64)
arr[4][6] = 0xdeadbeef  # within pad, no warning
```

### Negative indexing

Negative array indices are allowed when they stay within the backing
buffer (i.e. they land on an earlier field of the same struct). If the
negative offset would go before the start of the buffer, `IndexError`
is raised:

```python
final = structs.craft('FinalBoss')
final.matrix[0][-1]  # valid: lands on negative_val field
final.matrix[0][-3]  # IndexError: before the backing buffer
```

### Iterating arrays

All array types support `for ... in` iteration:

```python
arr = structs.craft('int[4]')
for i, elem in enumerate(arr):
    arr[i] = i * 10
values = [elem.value for elem in arr]  # [0, 10, 20, 30]

# Works on DWARFArray (cast) too
for addr in structs.cast('Basic[3]', 0x1000):
    log.info(hex(int(addr)))
```

Unbounded pointer arrays (`cast('int *', ...)`) raise `TypeError` on
iteration, since they have no fixed length.

### Reading values back

The `.value` property reads back the current value of a primitive field:

```python
chunk = libc.craft('malloc_chunk')
chunk.size = 0x421
chunk.size.value  # -> 0x421

final = structs.craft('FinalBoss')
final.max_hp = 3.14
final.max_hp.value  # -> 3.140000104904175 (float precision)
final.negative_val = -1337
final.negative_val.value  # -> -1337 (signed)
```

For struct/array fields, `.value` returns raw bytes.

---

## Parsing Structs (Reverse of Craft)

Parse leaked memory back into a readable struct:

```python
leaked = io.recv(libc.sizeof('malloc_chunk'))
chunk = libc.parse('malloc_chunk', leaked)
log.info(f"fd = {hex(chunk.fd.value)}")
log.info(f"bk = {hex(chunk.bk.value)}")
log.info(f"size = {hex(chunk.size.value)}")
```

Data is truncated or zero-padded to match the struct size.

---

## Enum Constants

Access named enum values from DWARF debug info:

```python
state = structs.enum('State')
state.IDLE       # -> 0
state.RUNNING    # -> 1
state.CRASHED    # -> -1

# Use directly in crafting
final = structs.craft('FinalBoss')
final.current_state = state.CRASHED

# Check membership
'IDLE' in state  # -> True

# Iterate all constants
for name, value in state:
    print(f"{name} = {value}")
```

---

## sizeof / offsetof / containerof

```python
structs.sizeof('malloc_chunk')                  # -> 48
structs.offsetof('FinalBoss', 'matrix')         # -> 8
structs.offsetof('FinalBoss', 'matrix[1][2]')   # -> 28
structs.offsetof('BossFight', 'u.data.raw')     # -> 32

# Works with primitive types and array syntax
structs.sizeof('int')                           # -> 4
structs.sizeof('unsigned long')                 # -> 8
structs.sizeof('int[100]')                      # -> 400
structs.sizeof('Basic[3][2]')                   # -> 72
```

Common C type aliases (`short`, `long`, `long long`, `unsigned short`, `unsigned long`, `unsigned long long`) are mapped to their DWARF names automatically.

`containerof` calculates the base address of a struct given a pointer to one of its members (equivalent to the Linux kernel `container_of` macro):

```python
# You have a pointer to the 'tasks' list_head inside a task_struct
base = libc.containerof('task_struct', 'tasks', list_entry_addr)
```

---

## Struct Layout Inspection

Print the memory layout of any struct:

```python
structs.describe('FinalBoss')
```

Output:

```
struct FinalBoss (48 bytes):
  offset   size   type                         name
  ------   ----   ----                         ----
  0x0      4      enum State                   current_state
  0x4      2      short int                    negative_val
  0x8      24     int[2][3]                    matrix
  0x20     4      float                        max_hp
  0x28     8      double                       current_hp
```

Anonymous struct/union members are automatically inlined:

```python
structs.describe('AnonMember')
```

```
struct AnonMember (12 bytes):
  offset   size   type                         name
  ------   ----   ----                         ----
  0x0      4      int                          type
  0x4      4      int                          as_int
  0x4      4      float                        as_float
  0x8      2      short int                    x
  0xa      2      short int                    y
```

---

## Typedef Resolution

See what a typedef resolves to:

```python
structs.resolve_type('size_t')  # -> 'long unsigned int'
structs.resolve_type('State')   # -> 'enum State'
```

---

## Address Math on Symbols

For binaries with debug symbols, resolve C-style field paths to exact memory addresses. PIE base address slides are respected automatically.

```python
libc = ExtendedELF('./libc.so.6')
libc.address = 0x7ffff7a00000

# Attribute-style access
addr = libc.sym_obj['main_arena']          # DWARFAddress for main_arena
fd_addr = libc.sym_obj['main_arena'].bins[3].fd  # address of bins[3].fd

# Cast arbitrary addresses
chunk = libc.cast('malloc_chunk', 0x55555555b000)
size_addr = chunk.size  # address of the size field

# Cast as arrays using type string or count=
entries = libc.cast('malloc_chunk[64]', heap_start)
entries[3].fd  # address of 4th chunk's fd field

# Multi-dimensional
grid = libc.cast('int[4][8]', buffer_addr)
grid[1][2]  # address of element at row 1, col 2

# Primitive type arrays
libc.cast('unsigned long[16]', stack_leak)
```

### Pointer cast syntax

Cast an address as a pointer type for unbounded indexing (no `count` needed):

```python
ptr = libc.cast('int *', heap_base)
ptr[520292]   # heap_base + 520292 * sizeof(int), wraps around VA space
ptr[-10]      # negative offsets work too

sizeof('int *')  # -> 8 on 64-bit
```

Pointer members in structs also support indexing:

```python
chunk = libc.cast('ArrayFun', addr)
chunk.ptr[10]  # addr_of_ptr_field + 10 * sizeof(char)
```

Multi-level pointers (`int **`) are not supported. Use `unsigned long *` to treat memory as an array of pointer-sized values.

### VA space wrapping

All address arithmetic wraps around the ELF's bit width (32 or 64 bit). This is critical for exploitation where large or negative offsets must behave like real CPU addressing:

```python
ptr = libc.cast('int *', 0xffffffffffffff00)
ptr[100]  # wraps around 64-bit VA space

arr = libc.cast('long long *', 0x1000)
arr[(1 << 64) // 8]  # wraps back to 0x1000
```

`DWARFAddress` is an `int` subclass, so it works anywhere an address is expected:

```python
io.send(p64(fd_addr))
```

### DWARFAddress arithmetic

Adding or subtracting an integer from a `DWARFAddress` returns a new
`DWARFAddress` that preserves the original type, with VA wrapping:

```python
chunk = libc.cast('malloc_chunk', 0x55555555b000)
next_chunk = chunk + 0x20    # DWARFAddress, same type
next_chunk.fd                # field access works

prev = chunk - 0x10          # DWARFAddress, same type
diff = next_chunk - chunk    # plain int (0x20)

0x100 + chunk                # radd also preserves type
```

`containerof` and `resolve_field` also apply VA wrapping automatically.

`DWARFAddress` also has a descriptive repr:

```python
>>> libc.sym_obj['main_arena']
<DWARFAddress 0x7ffff7dd1b20 type=struct malloc_state>
```

### Check if a symbol has debug info

```python
'main_arena' in libc.sym_obj  # -> True
```

### String-based field resolution

```python
addr = libc.resolve_field('main_arena', 'bins[3].fd')
```

---

## Supported Types

| Type | craft | parse | cast | sizeof | offsetof | describe |
|------|-------|-------|------|--------|----------|----------|
| struct | yes | yes | yes | yes | yes | yes |
| union | yes | yes | yes | yes | yes | yes |
| enum | yes | yes | yes | yes | - | - |
| primitives (int, char, ...) | yes | yes | yes | yes | - | - |
| array (1D) | yes | yes | yes | yes | yes | yes |
| array (multi-dim) | yes | yes | yes | yes | yes | yes |
| array type string (`Foo[3][4]`) | yes | yes | yes | yes | - | - |
| pointer | yes (as int) | yes | yes (unbounded indexing) | yes | yes | yes |
| float/double | yes | yes | - | yes | yes | yes |
| anonymous struct/union | yes | yes | yes | yes | yes | yes (inlined) |
| typedef | yes | yes | yes | yes | yes | yes |
| bit-field | warning | warning | warning | - | - | - |

---

## Caching

DWARF parsing results and compiled CHeader ELFs are cached to disk under `~/.cache/.pwntools-cache-*/extelf_cache/`. Caches are keyed by build ID (or content hash for binaries without one) and header content hash. Delete the cache directory to force a rebuild.

---

## Fast DWARF Parsing (optional)

For large binaries like glibc, the initial DWARF parse can take several seconds with pyelftools. An optional Rust extension (`doglib-dwarf-parser`) uses [gimli](https://github.com/gimli-rs/gimli) for significantly faster cold-cache parsing. Once cached, both paths are equally fast.

Requires a Rust toolchain and [maturin](https://www.maturin.rs/) (`pip install maturin`).

**Installing into a virtualenv** (e.g. for development):

```bash
cd src/dwarf_parser_rs && maturin develop --release
```

**Installing into the global Python environment** — `maturin develop` requires a venv, so build a wheel first and install that:

```bash
cd src/dwarf_parser_rs
maturin build --release
pip install --break-system-packages target/wheels/doglib_dwarf_parser-*.whl
```

Omit `--break-system-packages` if your global pip doesn't require it (e.g. inside a conda environment or an older system).

The extension is automatically detected at import time. If not installed, extelf falls back to pyelftools transparently — no code changes needed.

---

## Limitations

- **Pointers cannot be dereferenced** -- `sym_obj['arena'].bins[3].fd` gives you the *address* of `fd`, not its value. You must read memory manually in your exploit to follow pointers.
- **Bit-fields** are detected and produce a warning but are not fully supported for read/write operations.
- **Flexible array members** (`char data[]`) have zero size and cannot be crafted directly.
