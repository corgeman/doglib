#ifndef COMPLEX_STRUCTS_H
#define COMPLEX_STRUCTS_H

// Level 1: Tests basic types and struct padding
struct Basic {
    char a;
    int b;
    short c;
};

// Level 2: Tests arrays and pointers
struct ArrayFun {
    int arr[5];
    char *ptr;
};

// Level 3: Tests anonymous unions and structs sharing memory
struct UnionMadness {
    long type;
    union {
        struct {
            int x;
            int y;
        } coords;
        char raw[8];
    } data;
};

// Level 4: Tests deeply nested arrays of structs and union combinations
struct BossFight {
    struct Basic b[2];
    struct UnionMadness u;
};

// Level 5: Truncation and Data Types
struct EdgeCases {
    unsigned short small_int;
    char small_buf[5];
    long long big_int;
};

// Level 6: Global Address Resolution & Padding
struct GlobalTest {
    char pad[13]; // This forces weird 3-byte struct padding!
    struct ArrayFun arr[3];
};

// Level 7: Enums, Negative Signed Types, Multi-Dimensional Arrays & Floats
enum State {
    IDLE = 0,
    RUNNING = 1,
    CRASHED = -1
};

struct FinalBoss {
    enum State current_state;
    short negative_val;
    int matrix[2][3];
    float max_hp;
    double current_hp;
};

// Level 8: Multi-dimensional array proper indexing (3D)
struct MultiDimTest {
    int grid[3][4];
    char cube[2][3][4];
};

// Level 9: Anonymous struct/union members (C11)
struct AnonMember {
    int type;
    union {
        int as_int;
        float as_float;
    };
    struct {
        short x;
        short y;
    };
};

// Level 10: Sub-struct assignment & value readback
struct Wrapper {
    struct Basic header;
    int payload;
};

#endif
