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
## Unstripping other libraries !!!WORKONME!!!<><HIHIHIIH>
If you need to strip a common library that's not libc/ld, you should try looking it up against some common debuginfod servers.
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