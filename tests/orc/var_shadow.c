/* Reproduces the libc.so.6 `initial` shadowing bug:
 *   file-scope global `initial` has type `struct globalty`
 *   function-local `initial` has type `struct localty`
 * The parser must index only the global. */

struct globalty { int a; long b; };
struct localty  { char x; char y; };

static struct globalty initial = { 1, 2 };

void use_local(void) {
    volatile struct localty initial = { 3, 4 };
    (void)initial;
}

int main(void) {
    use_local();
    return (int)initial.b;
}
