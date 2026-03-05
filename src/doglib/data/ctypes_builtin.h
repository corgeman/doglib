#include <stdint.h>
#include <stdbool.h>
#include <stddef.h>
#include <sys/types.h>
#include <uchar.h>
#include <wchar.h>
#include <complex.h>
#include <stdarg.h>
#include <stdio.h>
#include <time.h>
#include <sys/time.h>
#include <ucontext.h>
#include <setjmp.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <link.h>
#include <elf.h>
/* Ensure every standard scalar type is referenced so DWARF emits them. */
typedef char               _ct_char;
typedef signed char        _ct_schar;
typedef unsigned char      _ct_uchar;
typedef short              _ct_short;
typedef unsigned short     _ct_ushort;
typedef int                _ct_int;
typedef unsigned int       _ct_uint;
typedef long               _ct_long;
typedef unsigned long      _ct_ulong;
typedef long long          _ct_llong;
typedef unsigned long long _ct_ullong;
typedef float              _ct_float;
typedef double             _ct_double;
typedef long double        _ct_ldouble;
typedef size_t             _ct_size_t;
typedef ssize_t            _ct_ssize_t;
typedef ptrdiff_t          _ct_ptrdiff_t;
typedef intptr_t           _ct_intptr_t;
typedef uintptr_t          _ct_uintptr_t;
typedef int8_t             _ct_i8;
typedef int16_t            _ct_i16;
typedef int32_t            _ct_i32;
typedef int64_t            _ct_i64;
typedef uint8_t            _ct_u8;
typedef uint16_t           _ct_u16;
typedef uint32_t           _ct_u32;
typedef uint64_t           _ct_u64;
typedef bool               _ct_bool;

/* slightly less standard stuff but useful for CTF */
typedef intmax_t           _ct_intmax_t;
typedef uintmax_t          _ct_uintmax_t;
typedef wchar_t            _ct_wchar_t;
typedef char16_t           _ct_char16_t;
typedef char32_t           _ct_char32_t;
typedef va_list            _ct_va_list;
typedef FILE               _ct_FILE;
typedef fpos_t             _ct_fpos_t;

typedef pid_t              _ct_pid_t;
typedef uid_t              _ct_uid_t;
typedef gid_t              _ct_gid_t;
typedef off_t              _ct_off_t;
typedef mode_t             _ct_mode_t;
typedef time_t             _ct_time_t;
typedef clock_t            _ct_clock_t;
typedef struct timespec    _ct_timespec;
typedef struct timeval     _ct_timeval;

typedef ucontext_t         _ct_ucontext_t;
typedef jmp_buf            _ct_jmp_buf;
typedef sigjmp_buf         _ct_sigjmp_buf;
typedef socklen_t          _ct_socklen_t;
typedef struct sockaddr    _ct_sockaddr;
typedef struct sockaddr_in _ct_sockaddr_in;
typedef struct link_map    _ct_link_map;
typedef Elf64_Ehdr         _ct_Elf64_Ehdr;
typedef Elf64_Phdr         _ct_Elf64_Phdr;