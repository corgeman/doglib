# obtaining debuginfo

# Obtaining debug information
The magic behind this library is debug information. If an ELF has debug information, we can parse it and immediately get access to all the information necessary to implement the juicy stuff above. However, it's very likely you don't have any yet, and need some to work with. This section offers some solutions to common situations.
## Unstripping libc
If all you care about is getting GLIBC debug information, `doglib` has your back with the `dog fetch` CLI tool:
```
corgo@dog-computer:/tmp/test$ ls
libc.so.6
corgo@dog-computer:/tmp/test$ dog fetch ./libc.so.6 --dbg
/tmp/test/ld-2.39.so
[+] Debug symbols applied to libc '/tmp/test/libc.so.6'.
[+] Debug symbols applied to ld '/tmp/test/ld-2.39.so'.
corgo@dog-computer:/tmp/test$ ls
ld-2.39.so  libc.so.6
corgo@dog-computer:/tmp/test$


```
Both `libc.so.6` and the newly-created `ld-2.39.so` will contain full debug information that you can use as you please.
## Unstripping other libraries
If you need to strip a common library that's not libc/ld, you should try seeing if you can find debug symbols on some [debuginfod servers](https://wiki.archlinux.org/title/Debuginfod). here's a script to do that:
```bash
#!/bin/bash
set -e

FORCE=false
FILE=""

while [[ "$#" -gt 0 ]]; do
    case $1 in
        --force|-f) FORCE=true; shift ;;
        -*) echo "[-] Unknown parameter: $1"; exit 1 ;;
        *) FILE="$1"; shift ;;
    esac
done

if [ -z "$FILE" ]; then
    echo "Usage: $0 [--force] <library_file>"
    exit 1
fi

if [ ! -f "$FILE" ]; then
    echo "[-] Error: File '$FILE' not found."
    exit 1
fi

if ! file "$FILE" | grep -q "ELF"; then
    echo "[-] Error: '$FILE' does not appear to be a valid ELF file."
    exit 1
fi

if [ "$FORCE" = false ] && readelf -S "$FILE" 2>/dev/null | grep -q '\.debug_info'; then
    echo "[+] '$FILE' already has debug symbols. Skipping. (use --force to override)"
    exit 0
fi

BUILD_ID=$(readelf -n "$FILE" 2>/dev/null | grep "Build ID:" | awk '{print $3}')

if [ -z "$BUILD_ID" ]; then
    echo "[-] Error: Could not find a Build ID for '$FILE'."
    exit 1
fi

echo "[+] Found Build ID: $BUILD_ID"

PLUMB_SERVERS="https://debuginfod.pwndbg.re/ https://debuginfod.ubuntu.com/ https://debuginfod.debian.net/ https://debuginfod.elfutils.org/"
export DEBUGINFOD_URLS="$PLUMB_SERVERS ${DEBUGINFOD_URLS:-}"

# Only clear negative cache entries (0-byte debuginfo files), not valid cached results
CACHE_DIR="$HOME/.cache/debuginfod_client/$BUILD_ID"
if [ -d "$CACHE_DIR" ]; then
    CACHED_DEBUGINFO="$CACHE_DIR/debuginfo"
    if [ -f "$CACHED_DEBUGINFO" ] && [ ! -s "$CACHED_DEBUGINFO" ]; then
        echo "[*] Clearing negative debuginfod cache for $BUILD_ID..."
        rm -f "$CACHED_DEBUGINFO"
    fi
fi

echo "[*] Fetching debuginfo..."
DEBUG_FILE=$(debuginfod-find debuginfo "$BUILD_ID" 2>/dev/null) || true

if [ -z "$DEBUG_FILE" ] || [ ! -f "$DEBUG_FILE" ]; then
    echo "[-] No debuginfo found for $BUILD_ID on any configured server."
    exit 1
fi

echo "[+] Debuginfo found/downloaded to: $DEBUG_FILE"
echo "[*] Applying debug info using eu-unstrip..."

TMPOUT=$(mktemp "${FILE}.unstrip.XXXXXX")
if eu-unstrip -o "$TMPOUT" "$FILE" "$DEBUG_FILE"; then
    mv "$TMPOUT" "$FILE"
    echo "[+] Successfully applied debug symbols to '$FILE'."
        chmod +x "$FILE"
    exit 0
else
    rm -f "$TMPOUT"
    echo "[-] Error: eu-unstrip failed."
    exit 1
fi
```

## C64/C32/C
If the types you're looking for are commonly used in CTFs, this module may have them inside `C64`/`C32`/`C`.
```python
>>> from dog import C64
>>> C64.describe("malloc_state")
struct malloc_state (2200 bytes):
  offset   size   type                         name
  ------   ----   ----                         ----
  0x0      4      int                          mutex
  0x4      4      int                          flags
  0x8      4      int                          have_fastchunks
  0x10     80     void*[10]                    fastbinsY
  0x60     8      void*                        top
  0x68     8      void*                        last_remainder
  0x70     2032   void*[254]                   bins
  0x860    16     unsigned int[4]              binmap
  0x870    8      struct malloc_state*         next
  0x878    8      struct malloc_state*         next_free
  0x880    8      size_t                       attached_threads
  0x888    8      size_t                       system_mem
  0x890    8      size_t                       max_system_mem
```
If you'd like to add a useful type, feel free to make a [PR](https://github.com/corgeman/doglib/blob/main/src/doglib/data/orc/ctypes_builtin.h)!  
Note that your type cannot have gone under significant change-- for instance, you should not PR the `tcache_perthread_struct` because [it was significantly changed in version 2.42](https://github.com/pwndbg/pwndbg/issues/3454).


## Debuginfo via header files
If none of these apply, you'll have to create the necessary struct definitions yourself.  
Write an `.h` file containing all your definitions like so:
```c
struct Basic {
    char a;
    int b;
    short c;
};
```
then
```python
from dog import *
hed = ORCHeader("./your_h_file.h")
```
or if it's small, via direct inline:
```python
from dog import *
hed = ORCInline("""
struct Basic {
    char a;
    int b;
    short c;
};
""")
```