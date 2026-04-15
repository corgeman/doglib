/*
 * type_zoo.c — synthetic C source designed to emit a broad variety of DWARF
 * constructs for parser-parity testing.
 *
 * Compile with:
 *   gcc type_zoo.c -o type_zoo.challenge.elf -g -no-pie \
 *       -fno-eliminate-unused-debug-types -std=c11
 */
#include <stdint.h>
#include <stddef.h>
#include <stdbool.h>
#include <stdatomic.h>

/* ── Base-type coverage ──────────────────────────────────────────── */
typedef int8_t   i8;
typedef int16_t  i16;
typedef int32_t  i32;
typedef int64_t  i64;
typedef uint8_t  u8;
typedef uint16_t u16;
typedef uint32_t u32;
typedef uint64_t u64;
typedef __int128            i128;
typedef unsigned __int128   u128;
typedef _Bool               MyBool;

/* ── Typedef chains ──────────────────────────────────────────────── */
typedef int   ChainA;
typedef ChainA ChainB;
typedef ChainB ChainC;

/* ── Simple struct ───────────────────────────────────────────────── */
struct Simple { int x; int y; };

/* ── Bitfields (mixed width, unnamed padding) ────────────────────── */
struct Bitfield {
    unsigned int a : 3;
    unsigned int b : 5;
    unsigned int c : 8;
    unsigned int   : 4;   /* unnamed padding */
    unsigned int d : 12;
};

/* ── Union inside struct ─────────────────────────────────────────── */
struct WithUnion {
    int tag;
    union {
        int     as_int;
        float   as_float;
        struct { uint8_t b0, b1, b2, b3; } as_bytes;
    } val;
};

/* ── Anonymous struct member (C11) ───────────────────────────────── */
struct AnonOuter {
    int outer_field;
    struct {
        int inner_a;
        int inner_b;
    };
};

/* ── Flexible array member ───────────────────────────────────────── */
struct FlexArray {
    size_t len;
    int    data[];
};

/* ── Function-pointer typedefs (incl. varargs) ───────────────────── */
typedef int  (*Callback)(int, void *);
typedef void (*Handler)(const char *, ...);
typedef int  (*(*NestedFnPtr)(void))(char);

/* ── Multi-level pointer ─────────────────────────────────────────── */
typedef int ***TriplePtr;

/* ── Const / volatile / restrict qualifiers ──────────────────────── */
typedef const int          CInt;
typedef volatile long      VLong;
typedef const volatile char CVChar;
typedef int * restrict     RPtr;

/* ── Nested structs (3 levels) ───────────────────────────────────── */
struct Level1 { int a; };
struct Level2 { struct Level1 l1; int b; };
struct Level3 { struct Level2 l2; int c; };

/* ── Multi-dimensional array typedefs ────────────────────────────── */
typedef int     Matrix3x3[3][3];
typedef char    Grid4[4][4][4];
typedef int     *PtrArray[8];

/* ── Enums (with negative + explicit values) ─────────────────────── */
enum Signal {
    SIG_ERR  = -1,
    SIG_NONE =  0,
    SIG_HUP  =  1,
    SIG_TERM = 15,
    SIG_KILL =  9
};

typedef enum { MODE_R, MODE_W, MODE_X } FileMode;

/* ── Forward declaration (exercises DW_AT_declaration filtering) ─── */
struct ForwardDecl;   /* declaration only — no definition */

/* ── Self-referential (linked list node) ─────────────────────────── */
struct Node { int val; struct Node *next; };

/* ── Top-level union ─────────────────────────────────────────────── */
union Variant { int32_t i; uint64_t u; double d; uint8_t raw[8]; };

/* ── Atomic types ────────────────────────────────────────────────── */
typedef _Atomic int       AtomicInt;
typedef _Atomic long long AtomicLL;

/* ── Struct exercising every built-in base type ──────────────────── */
struct AllBaseTypes {
    _Bool           b;
    char            c;
    signed char     sc;
    unsigned char   uc;
    short           s;
    unsigned short  us;
    int             i;
    unsigned int    ui;
    long            l;
    unsigned long   ul;
    long long       ll;
    unsigned long long ull;
    float           f;
    double          dd;
    long double     ld;
    __int128        i128field;
};

/* ── Opaque pointer (common C pattern) ───────────────────────────── */
typedef struct OpaqueHandle *Handle;

/* ── Globals — populate _dwarf_vars ──────────────────────────────── */
struct Simple          g_simple;
struct Bitfield        g_bitfield;
struct WithUnion       g_with_union;
struct AnonOuter       g_anon_outer;
struct Level3          g_nested;
struct Node            g_node;
union Variant          g_variant;
struct AllBaseTypes    g_all_types;
Matrix3x3              g_matrix;
Grid4                  g_grid;
enum Signal            g_signal;
FileMode               g_mode;
Callback               g_cb;
Handler                g_handler;
MyBool                 g_bool;
AtomicInt              g_atomic_int;
AtomicLL               g_atomic_ll;
i128                   g_i128;
u128                   g_u128;
ChainC                 g_chain;
TriplePtr              g_triple;
PtrArray               g_ptrarr;

int main(void) { return 0; }
