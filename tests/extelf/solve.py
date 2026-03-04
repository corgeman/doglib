#!/usr/bin/env python3
from pwn import *

from doglib.extelf import CHeader, ExtendedELF

# Load our types
headers = CHeader("complex_structs.h")

# Ensure you compile the challenge first: gcc challenge.c -o challenge -g -no-pie
# We load it with ExtendedELF so we can parse its global variables!
chal_elf = ExtendedELF("./challenge")
context.binary = chal_elf
io = process("./challenge")
info(context.bits)
# --- LEVEL 1: Padding & Basics ---
log.info("Solving Level 1...")
basic = headers.craft('Basic')
basic.a = ord('X')
basic.b = 0x1337
basic.c = 0x42
io.sendafter(b"Basic\n", bytes(basic))

# --- LEVEL 2: Arrays & Pointers ---
log.info("Solving Level 2...")
arr_fun = headers.craft('ArrayFun')
arr_fun.arr[0] = 10
arr_fun.arr[4] = 50
arr_fun.ptr = 0xdeadbeef
io.sendafter(b"ArrayFun\n", bytes(arr_fun))

# --- LEVEL 3: Unions & Anonymous Structs ---
log.info("Solving Level 3...")
union_madness = headers.craft('UnionMadness')
union_madness.type = 1
union_madness.data.coords.x = 0x11223344
union_madness.data.coords.y = 0x55667788
io.sendafter(b"UnionMadness\n", bytes(union_madness))

# --- LEVEL 4: Deep Nesting & Array Bytes ---
log.info("Solving Level 4...")
boss = headers.craft('BossFight')
boss.b[1].a = ord('Z')
boss.b[1].b = 999
boss.u.data.raw = b"AAAAAAAW"
io.sendafter(b"BossFight\n", bytes(boss))

# --- LEVEL 5: Truncation & Overflows ---
log.info("Solving Level 5...")
edge = headers.craft('EdgeCases')
edge.small_int = 0xdeadbeef
edge.small_buf = b"AAAA\x00TRASH_DATA_THAT_GETS_DROPPED"
edge.big_int = -1
io.sendafter(b"EdgeCases\n", bytes(edge))

# --- LEVEL 6: DWARF Array Strides & Offset Math ---
log.info("Solving Level 6...")
target_addr = int(chal_elf.sym_obj['target_sym'].arr[2].ptr)

log.info(f"Dynamically calculated array sub-field address: {hex(target_addr)}")
io.sendafter(b"(8 bytes)\n", p64(target_addr))

# --- LEVEL 7: Enums, Signed Values, Multi-Dimensional Arrays, & Floats ---
log.info("Solving Level 7...")
final = headers.craft('FinalBoss')
final.current_state = -1  # CRASHED
final.negative_val = -1337

# Multi-dimensional arrays now support proper [row][col] indexing!
final.matrix[1][2] = 9999

final.max_hp = 1000.5
final.current_hp = 1337.75
io.sendafter(b"FinalBoss\n", bytes(final))

# --- LEVEL 8: Multi-Dimensional Array Proper Indexing (2D + 3D) ---
log.info("Solving Level 8...")
md = headers.craft('MultiDimTest')
md.grid[1][2] = 42
md.grid[2][3] = 99
md.cube[1][0][2] = ord('Q')
md.cube[0][2][3] = ord('Z')
io.sendafter(b"MultiDimTest\n", bytes(md))

# --- LEVEL 9: Anonymous Struct/Union Members ---
log.info("Solving Level 9...")
am = headers.craft('AnonMember')
am.type = 5
am.as_int = 0xCAFE   # Accessed directly through anonymous union
am.x = 100           # Accessed directly through anonymous struct
am.y = 200
io.sendafter(b"AnonMember\n", bytes(am))

# --- LEVEL 10: Sub-Struct Assignment & Value Readback ---
log.info("Solving Level 10...")
hdr = headers.craft('Basic')
hdr.a = ord('A')
hdr.b = 1234
hdr.c = 42

wrapper = headers.craft('Wrapper')
wrapper.header = hdr    # Sub-struct assignment: DWARFCrafter -> DWARFCrafter!
wrapper.payload = 0xBEEF

# Test .value readback on the fields we just set
assert wrapper.payload.value == 0xBEEF, "Integer value readback failed!"
assert wrapper.header.a.value == ord('A'), "Char value readback failed!"
assert wrapper.header.b.value == 1234, "Int value readback failed!"
log.info(f"Value readback tests passed (payload={hex(wrapper.payload.value)}, a={wrapper.header.a.value}, b={wrapper.header.b.value})")

io.sendafter(b"Wrapper\n", bytes(wrapper))

io.interactive()
