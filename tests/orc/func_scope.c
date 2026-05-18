/* Two functions each declare their own `struct point` with different layouts,
 * and a file-scope `struct point` is yet another layout. The orc.scope() API
 * should resolve `point` to the per-function definition, while plain
 * `orc.cast('point', ...)` should hit the file-scope one. */

struct point { int x; int y; };

/* Force the file-scope struct point into DWARF: GCC otherwise eliminates
 * unused types even with -g. */
struct point file_scope_point = { 1, 2 };

void f1(void) {
    struct point { char r; } p = { 'A' };
    (void)p;
}

void f2(void) {
    struct point { double d; } p = { 1.0 };
    (void)p;
}

int main(void) { f1(); f2(); return file_scope_point.x; }
