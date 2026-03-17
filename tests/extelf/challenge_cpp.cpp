#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <unistd.h>

// IMPORTANT COMPILE COMMAND:
// g++ challenge_cpp.cpp -o challenge_cpp -g -no-pie -fno-stack-protector

// ── Types ─────────────────────────────────────────────────────────────────────

class Coords {
public:
    int x;
    int y;
    int z;
};

class Weapon {
public:
    int damage;
    int durability;
};

class Entity {
public:
    int id;
    Coords pos;
    char name[16];
};

class Player : public Entity {
public:
    int health;
    Weapon weapon;
};

class Monster {
public:
    int hp;
    virtual void attack() {
        printf("[-] Normal attack.\n");
        _exit(1);
    }
};

void win() {
    printf("[+] Level 4 passed! Vtable hijack successful!\n");
}

// Writable buffer the solver can use as a fake vtable.
unsigned long fake_vtable[4] = {0};

// Global for address resolution test
Player global_player;

// ── Challenge ─────────────────────────────────────────────────────────────────

void setup() {
    setvbuf(stdin, NULL, _IONBF, 0);
    setvbuf(stdout, NULL, _IONBF, 0);
}

int main() {
    setup();
    printf("--- C++ Struct Crafter Challenge ---\n");

    // Level 1: Simple class
    Coords c;
    memset(&c, 0, sizeof(c));
    printf("Level 1: Send %lu bytes for Coords\n", sizeof(c));
    read(0, &c, sizeof(c));
    if (c.x == 10 && c.y == 20 && c.z == 30) {
        printf("[+] Level 1 passed!\n");
    } else {
        printf("[-] Level 1 failed. x=%d y=%d z=%d\n", c.x, c.y, c.z);
        exit(1);
    }

    // Level 2: Nested class
    Entity e;
    memset(&e, 0, sizeof(e));
    printf("Level 2: Send %lu bytes for Entity\n", sizeof(e));
    read(0, &e, sizeof(e));
    if (e.id == 42 && e.pos.x == 100 && e.pos.y == 200 && e.pos.z == 300
        && strcmp(e.name, "hero") == 0) {
        printf("[+] Level 2 passed!\n");
    } else {
        printf("[-] Level 2 failed. id=%d pos=(%d,%d,%d) name=%s\n",
               e.id, e.pos.x, e.pos.y, e.pos.z, e.name);
        exit(1);
    }

    // Level 3: Inheritance
    Player p;
    memset(&p, 0, sizeof(p));
    printf("Level 3: Send %lu bytes for Player\n", sizeof(p));
    read(0, &p, sizeof(p));
    if (p.id == 1 && p.pos.x == 50 && p.health == 100
        && p.weapon.damage == 25 && p.weapon.durability == 75) {
        printf("[+] Level 3 passed!\n");
    } else {
        printf("[-] Level 3 failed. id=%d pos.x=%d health=%d dmg=%d dur=%d\n",
               p.id, p.pos.x, p.health, p.weapon.damage, p.weapon.durability);
        exit(1);
    }

    // Level 4: Vtable hijack
    // Heap-allocated so GCC cannot devirtualize the call.
    Monster* m = new Monster();
    m->hp = 0;
    printf("Level 4: Send 8 bytes for fake_vtable[0], then %lu bytes for Monster\n",
           sizeof(Monster));
    read(0, &fake_vtable[0], 8);
    read(0, m, sizeof(Monster));
    m->attack();

    return 0;
}
