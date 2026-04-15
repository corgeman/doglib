/*
 * type_zoo.cpp — C++ DWARF construct coverage for parser-parity tests.
 *
 * Compile with:
 *   g++ type_zoo.cpp -o type_zoo_cpp.challenge.elf -g -no-pie \
 *       -fno-eliminate-unused-debug-types
 */
#include <cstdint>
#include <cstddef>

/* ── Templates ───────────────────────────────────────────────────── */
template<typename T>
struct Box {
    T      value;
    size_t size;
};

template<typename K, typename V>
struct Pair {
    K key;
    V val;
};

/* ── Namespaces ──────────────────────────────────────────────────── */
namespace outer {
    struct Point { int x, y; };
    namespace inner {
        struct Vector { float x, y, z; };
    }
}

/* ── Virtual inheritance / diamond ──────────────────────────────── */
struct VBase {
    virtual ~VBase() = default;
    virtual int get() = 0;
    int base_field;
};

struct VDerived : virtual VBase {
    int derived_field;
    int get() override { return derived_field; }
};

struct Diamond1 : virtual VBase {
    int d1;
    int get() override { return d1; }
};

struct Diamond2 : virtual VBase {
    int d2;
    int get() override { return d2; }
};

struct DiamondBottom : Diamond1, Diamond2 {
    int get() override { return d1 + d2; }
};

/* ── enum class ──────────────────────────────────────────────────── */
enum class Color : uint8_t { RED = 0, GREEN = 1, BLUE = 2 };
enum class Direction { NORTH, SOUTH, EAST, WEST };

/* ── using aliases ───────────────────────────────────────────────── */
using IntBox   = Box<int>;
using FloatBox = Box<float>;
using CoordPair = Pair<int, int>;

/* ── Nested class ────────────────────────────────────────────────── */
struct Outer {
    struct Inner { int x; int y; };
    Inner inner;
    int   val;
};

/* ── Class with rich member set ──────────────────────────────────── */
class Thing {
public:
    int    id;
    float  weight;
    char   name[32];
    Color  color;
    Thing *next;
    virtual ~Thing() = default;
    virtual void update() {}
};

/* ── Multiple-level template nesting ─────────────────────────────── */
struct Wrapper {
    Box<Box<int>> nested_box;
    Pair<Color, Direction> enum_pair;
};

/* ── Globals — populate _dwarf_vars ──────────────────────────────── */
Box<int>              g_int_box;
Box<double>           g_double_box;
Pair<int, float>      g_pair;
outer::Point          g_point;
outer::inner::Vector  g_vector;
VDerived              g_derived;
DiamondBottom         g_diamond;
Color                 g_color;
Direction             g_dir;
IntBox                g_intbox;
FloatBox              g_floatbox;
CoordPair             g_coordpair;
Outer                 g_outer;
Thing                 g_thing;
Wrapper               g_wrapper;

int main() { return 0; }
