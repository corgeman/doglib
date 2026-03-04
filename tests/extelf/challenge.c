#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include "complex_structs.h"

// IMPORTANT COMPILE COMMAND:
// gcc challenge.c -o challenge -g -no-pie

// Global symbol mapped into the ELF for Level 6
struct GlobalTest target_sym;

void setup() {
    setvbuf(stdin, NULL, _IONBF, 0);
    setvbuf(stdout, NULL, _IONBF, 0);
}

int main() {
    setup();
    printf("--- Struct Crafter Stress Test ---\n");

    // Level 1
    struct Basic b;
    memset(&b, 0, sizeof(b));
    printf("Level 1: Send %lu bytes for Basic\n", sizeof(b));
    read(0, &b, sizeof(b));
    if (b.a == 'X' && b.b == 0x1337 && b.c == 0x42) {
        printf("[+] Level 1 passed!\n");
    } else {
        printf("[-] Level 1 failed.\n");
        exit(1);
    }

    // Level 2
    struct ArrayFun a;
    memset(&a, 0, sizeof(a));
    printf("Level 2: Send %lu bytes for ArrayFun\n", sizeof(a));
    read(0, &a, sizeof(a));
    if (a.arr[0] == 10 && a.arr[4] == 50 && a.ptr == (char*)0xdeadbeef) {
        printf("[+] Level 2 passed!\n");
    } else {
        printf("[-] Level 2 failed.\n");
        exit(1);
    }

    // Level 3
    struct UnionMadness u;
    memset(&u, 0, sizeof(u));
    printf("Level 3: Send %lu bytes for UnionMadness\n", sizeof(u));
    read(0, &u, sizeof(u));
    if (u.type == 1 && u.data.coords.x == 0x11223344 && u.data.coords.y == 0x55667788) {
        printf("[+] Level 3 passed!\n");
    } else {
        printf("[-] Level 3 failed.\n");
        exit(1);
    }

    // Level 4
    struct BossFight boss;
    memset(&boss, 0, sizeof(boss));
    printf("Level 4: Send %lu bytes for BossFight\n", sizeof(boss));
    read(0, &boss, sizeof(boss));
    if (boss.b[1].a == 'Z' && boss.b[1].b == 999 && boss.u.data.raw[7] == 'W') {
        printf("[+] Level 4 passed!\n");
    } else {
        printf("[-] Level 4 failed.\n");
        exit(1);
    }

    // Level 5
    struct EdgeCases edge;
    memset(&edge, 0, sizeof(edge));
    printf("Level 5: Send %lu bytes for EdgeCases\n", sizeof(edge));
    read(0, &edge, sizeof(edge));
    if (edge.small_int == 0xbeef && strcmp(edge.small_buf, "AAAA") == 0 && edge.big_int == -1) {
        printf("[+] Level 5 passed!\n");
    } else {
        printf("[-] Level 5 failed. small_int=%x, small_buf=%s, big_int=%lld\n", edge.small_int, edge.small_buf, edge.big_int);
        exit(1);
    }

    // Level 6
    unsigned long predicted_addr = 0;
    printf("Level 6: Send the exact address of target_sym.arr[2].ptr (8 bytes)\n");
    read(0, &predicted_addr, 8);
    if (predicted_addr == (unsigned long)&target_sym.arr[2].ptr) {
        printf("[+] Level 6 passed!\n");
    } else {
        printf("[-] Level 6 failed. Expected %p, got %p\n", &target_sym.arr[2].ptr, (void*)predicted_addr);
        exit(1);
    }

    // Level 7
    struct FinalBoss final;
    memset(&final, 0, sizeof(final));
    printf("Level 7: Send %lu bytes for FinalBoss\n", sizeof(final));
    read(0, &final, sizeof(final));
    if (final.current_state == CRASHED && final.negative_val == -1337 &&
        final.matrix[1][2] == 9999 && final.max_hp == 1000.5f && final.current_hp == 1337.75) {
        printf("[+] Level 7 passed!\n");
    } else {
        printf("[-] Level 7 failed. state=%d, neg=%d, mat[1][2]=%d, max_hp=%f, cur_hp=%lf\n",
               final.current_state, final.negative_val, final.matrix[1][2], final.max_hp, final.current_hp);
        exit(1);
    }

    // Level 8: Multi-dimensional arrays with proper indexing
    struct MultiDimTest md;
    memset(&md, 0, sizeof(md));
    printf("Level 8: Send %lu bytes for MultiDimTest\n", sizeof(md));
    read(0, &md, sizeof(md));
    if (md.grid[1][2] == 42 && md.grid[2][3] == 99 &&
        md.cube[1][0][2] == 'Q' && md.cube[0][2][3] == 'Z') {
        printf("[+] Level 8 passed!\n");
    } else {
        printf("[-] Level 8 failed. grid[1][2]=%d, grid[2][3]=%d, cube[1][0][2]=%c, cube[0][2][3]=%c\n",
               md.grid[1][2], md.grid[2][3], md.cube[1][0][2], md.cube[0][2][3]);
        exit(1);
    }

    // Level 9: Anonymous struct/union members
    struct AnonMember am;
    memset(&am, 0, sizeof(am));
    printf("Level 9: Send %lu bytes for AnonMember\n", sizeof(am));
    read(0, &am, sizeof(am));
    if (am.type == 5 && am.as_int == 0xCAFE && am.x == 100 && am.y == 200) {
        printf("[+] Level 9 passed!\n");
    } else {
        printf("[-] Level 9 failed. type=%d, as_int=0x%x, x=%d, y=%d\n", am.type, am.as_int, am.x, am.y);
        exit(1);
    }

    // Level 10: Sub-struct assignment
    struct Wrapper w;
    memset(&w, 0, sizeof(w));
    printf("Level 10: Send %lu bytes for Wrapper\n", sizeof(w));
    read(0, &w, sizeof(w));
    if (w.header.a == 'A' && w.header.b == 1234 && w.header.c == 42 && w.payload == 0xBEEF) {
        printf("[+] Level 10 passed! All tests passed!\n");
    } else {
        printf("[-] Level 10 failed. a=%c, b=%d, c=%d, payload=0x%x\n",
               w.header.a, w.header.b, w.header.c, w.payload);
        exit(1);
    }

    return 0;
}
