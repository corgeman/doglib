/* Simple test target for DumpELF tests.
 *
 * Compiled as both PIE and non-PIE to test both paths.
 * The test harness reads this binary's memory via /proc/pid/mem
 * to simulate an arbitrary-read primitive.
 */
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>

int global_var = 0x41414141;

void target_func(void) {
    printf("target_func called\n");
}

int main(int argc, char **argv) {
    if (argc > 1 && strcmp(argv[1], "--confirm") == 0) {
        printf("CONFIRMED WORKS\n");
        return 0;
    }

    /* Print our PID so the test harness can find us, then wait */
    printf("PID:%d\n", getpid());
    fflush(stdout);

    /* Wait for the test harness to signal us */
    char buf[16];
    if (fgets(buf, sizeof(buf), stdin) == NULL)
        return 1;

    return 0;
}
