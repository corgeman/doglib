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

// custom stuff
// !! only add if it is consistent across all libc versions !!
typedef struct _IO_jump_t {
    size_t __dummy;
    size_t __dummy2;
    void (*__finish)(FILE *, int);
    int (*__overflow)(FILE *, int);
    int (*__underflow)(FILE *);
    int (*__uflow)(FILE *);
    int (*__pbackfail)(FILE *, int);
    size_t (*__xsputn)(FILE *, const void *, size_t);
    size_t (*__xsgetn)(FILE *, void *, size_t);
    __off64_t (*__seekoff)(FILE *, __off64_t, int, int);
    __off64_t (*__seekpos)(FILE *, __off64_t, int);
    FILE * (*__setbuf)(FILE *, char *, ssize_t);
    int (*__sync)(FILE *);
    int (*__doallocate)(FILE *);
    ssize_t (*__read)(FILE *, void *, ssize_t);
    ssize_t (*__write)(FILE *, const void *, ssize_t);
    __off64_t (*__seek)(FILE *, __off64_t, int);
    int (*__close)(FILE *);
    int (*__stat)(FILE *, void *);
    int (*__showmanyc)(FILE *);
    void (*__imbue)(FILE *, void *);
} _ct_IO_jump_t;

typedef struct _IO_FILE_plus {
    FILE file;
    const struct _IO_jump_t *vtable;
} _ct_IO_FILE_plus;

typedef struct malloc_chunk {
    size_t      mchunk_prev_size; 
    size_t      mchunk_size;  
    void* fd;   
    void* bk;
    void* fd_nextsize;
    void* bk_nextsize;
} _ct_malloc_chunk;
 
enum
{
  ef_free,	/* `ef_free' MUST be zero!  */
  ef_us,
  ef_on,
  ef_at,
  ef_cxa
};

struct exit_function
  {
    /* `flavour' should be of type of the `enum' above but since we need
       this element in an atomic operation we have to use `long int'.  */
    long int flavor;
    union
      {
	void (*at) (void);
	struct
	  {
	    void (*fn) (int status, void *arg);
	    void *arg;
	  } on;
	struct
	  {
	    void (*fn) (void *arg, int status);
	    void *arg;
	    void *dso_handle;
	  } cxa;
      } func;
  };
struct exit_function_list
  {
    struct exit_function_list *next;
    size_t idx;
    struct exit_function fns[32];
  };