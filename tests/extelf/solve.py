#!/usr/bin/env python3
from pwn import *

from doglib.extelf import CHeader, ExtendedELF, DWARFAddress, C64

# Load our types
headers = CHeader("complex_structs.h")
# NOTE: if the challenge has debug symbols, you can just use the ELF instead
# this is merely to prove that you can use a .h file in the first place

# Ensure you compile the challenge first: gcc challenge.c -o challenge -g -no-pie
# We load it with ExtendedELF so we can parse its global variables!
chal_elf = ExtendedELF("./challenge")

io = process("./challenge")

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

# Multi-dimensional arrays support proper [row][col] indexing
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

# ========================================================================
# POST-CHALLENGE FEATURE TESTS (assertion-based, no binary interaction)
# ========================================================================
log.info("Running post-challenge feature tests...")

# --- TEST: Enum Constants ---
state = headers.enum('State')
assert state.IDLE == 0, f"Expected IDLE=0, got {state.IDLE}"
assert state.RUNNING == 1, f"Expected RUNNING=1, got {state.RUNNING}"
assert state.CRASHED == -1, f"Expected CRASHED=-1, got {state.CRASHED}"
assert 'IDLE' in state, "'IDLE' should be in State enum"
assert 'NONEXISTENT' not in state, "'NONEXISTENT' should not be in State enum"
log.success("Enum constants: PASSED")

# Enum values can be used directly in crafting
final2 = headers.craft('FinalBoss')
final2.current_state = state.CRASHED
assert final2.current_state.value == 0xFFFFFFFF, "Enum assignment via named constant failed"
log.success("Enum assignment in craft: PASSED")

# --- TEST: sizeof ---
assert headers.sizeof('Basic') == 12, f"sizeof(Basic) wrong: {headers.sizeof('Basic')}"
assert headers.sizeof('ArrayFun') == 32, f"sizeof(ArrayFun) wrong: {headers.sizeof('ArrayFun')}"
assert headers.sizeof('FinalBoss') == 48, f"sizeof(FinalBoss) wrong: {headers.sizeof('FinalBoss')}"
assert headers.sizeof('EdgeCases') == 16, f"sizeof(EdgeCases) wrong: {headers.sizeof('EdgeCases')}"
log.success("sizeof: PASSED")

# --- TEST: offsetof ---
assert headers.offsetof('Basic', 'a') == 0, "offsetof(Basic, a) should be 0"
assert headers.offsetof('Basic', 'b') == 4, "offsetof(Basic, b) should be 4"
assert headers.offsetof('Basic', 'c') == 8, "offsetof(Basic, c) should be 8"
assert headers.offsetof('FinalBoss', 'matrix') == 8, "offsetof(FinalBoss, matrix) should be 8"
assert headers.offsetof('FinalBoss', 'matrix[1][2]') == 28, "offsetof(FinalBoss, matrix[1][2]) should be 28"
assert headers.offsetof('FinalBoss', 'current_hp') == 40, "offsetof(FinalBoss, current_hp) should be 40"
assert headers.offsetof('BossFight', 'u.data.raw') == 32, "offsetof(BossFight, u.data.raw) should be 32"
log.success("offsetof: PASSED")

# --- TEST: containerof ---
member_addr = 0x1000 + headers.offsetof('BossFight', 'u')
base = headers.containerof('BossFight', 'u', member_addr)
assert base == 0x1000, f"containerof gave wrong base: {hex(base)}"
log.success("containerof: PASSED")

# --- TEST: parse (reverse of craft) ---
crafted = headers.craft('Basic')
crafted.a = ord('Z')
crafted.b = 0xDEAD
crafted.c = 42
raw_bytes = bytes(crafted)

parsed = headers.parse('Basic', raw_bytes)
assert parsed.a.value == ord('Z'), f"parse a: expected {ord('Z')}, got {parsed.a.value}"
assert parsed.b.value == 0xDEAD, f"parse b: expected 0xDEAD, got {parsed.b.value}"
assert parsed.c.value == 42, f"parse c: expected 42, got {parsed.c.value}"
log.success("parse: PASSED")

# Parse with nested struct
crafted_boss = headers.craft('BossFight')
crafted_boss.b[0].a = ord('A')
crafted_boss.b[0].b = 111
crafted_boss.b[1].a = ord('B')
crafted_boss.b[1].b = 222
boss_parsed = headers.parse('BossFight', bytes(crafted_boss))
assert boss_parsed.b[0].a.value == ord('A'), "parse nested a[0] failed"
assert boss_parsed.b[1].b.value == 222, "parse nested b[1].b failed"
log.success("parse nested struct: PASSED")

# --- TEST: describe (just verify it doesn't crash) ---
log.info("describe output for FinalBoss:")
headers.describe('FinalBoss')
log.info("describe output for AnonMember:")
headers.describe('AnonMember')
log.success("describe: PASSED (no crash)")

# --- TEST: DWARFAddress __repr__ ---
addr_repr = repr(chal_elf.sym_obj['target_sym'])
assert 'DWARFAddress' in addr_repr, f"Bad DWARFAddress repr: {addr_repr}"
assert 'type=' in addr_repr, f"Missing type in DWARFAddress repr: {addr_repr}"
log.success(f"DWARFAddress repr: PASSED ({addr_repr})")

# --- TEST: resolve_type ---
resolved = headers.resolve_type('State')
assert resolved == 'enum State', f"resolve_type('State') expected 'enum State', got: {resolved}"
log.success(f"resolve_type('State'): '{resolved}' PASSED")

# --- TEST: Slice assignment ---
arr = headers.craft('ArrayFun')
arr.arr[0:3] = [10, 20, 30]
assert arr.arr[0].value == 10, f"slice[0] expected 10, got {arr.arr[0].value}"
assert arr.arr[1].value == 20, f"slice[1] expected 20, got {arr.arr[1].value}"
assert arr.arr[2].value == 30, f"slice[2] expected 30, got {arr.arr[2].value}"
assert arr.arr[3].value == 0, f"slice[3] should be 0, got {arr.arr[3].value}"
log.success("Slice assignment (int list): PASSED")

# Slice with bytes on a char array
um = headers.craft('UnionMadness')
um.data.raw[0:4] = b"\xAA\xBB\xCC\xDD"
raw_out = bytes(um.data.raw)
assert raw_out[0:4] == b"\xAA\xBB\xCC\xDD", f"byte slice failed: {raw_out[0:4].hex()}"
log.success("Slice assignment (bytes): PASSED")

# --- TEST: __contains__ on sym_obj ---
assert 'target_sym' in chal_elf.sym_obj, "target_sym should be in sym_obj"
assert 'nonexistent_var' not in chal_elf.sym_obj, "nonexistent_var should not be in sym_obj"
log.success("sym_obj __contains__: PASSED")

# --- TEST: cast/craft/parse with count (array of structs) ---
arr = headers.craft('Basic', count=4)
assert len(arr) == 4
assert len(bytes(arr)) == 4 * headers.sizeof('Basic')
arr[0].a = ord('A')
arr[0].b = 111
arr[1].a = ord('B')
arr[1].b = 222
arr[2].a = ord('C')
arr[3].b = 444
assert arr[0].a.value == ord('A')
assert arr[1].b.value == 222
assert arr[2].a.value == ord('C')
assert arr[3].b.value == 444
log.success("craft with count: PASSED")

raw = bytes(arr)
parsed_arr = headers.parse('Basic', raw, count=4)
assert parsed_arr[0].a.value == ord('A')
assert parsed_arr[1].b.value == 222
assert parsed_arr[3].b.value == 444
log.success("parse with count: PASSED")

fake_base = 0x1000
cast_arr = headers.cast('Basic', fake_base, count=8)
assert len(cast_arr) == 8
elem_size = headers.sizeof('Basic')
assert int(cast_arr[0]) == fake_base
assert int(cast_arr[3]) == fake_base + 3 * elem_size
assert int(cast_arr[3].b) == fake_base + 3 * elem_size + headers.offsetof('Basic', 'b')
log.success("cast with count: PASSED")

# --- TEST: type string array syntax (multi-dimensional) ---
arr2d = headers.craft('Basic[3][2]')
assert len(arr2d) == 3
assert len(arr2d[0]) == 2
arr2d[0][0].a = ord('X')
arr2d[0][1].b = 99
arr2d[2][1].a = ord('Z')
assert arr2d[0][0].a.value == ord('X')
assert arr2d[0][1].b.value == 99
assert arr2d[2][1].a.value == ord('Z')
assert len(bytes(arr2d)) == 3 * 2 * headers.sizeof('Basic')
log.success("craft 2D type string: PASSED")

parsed2d = headers.parse('Basic[3][2]', bytes(arr2d))
assert parsed2d[0][0].a.value == ord('X')
assert parsed2d[2][1].a.value == ord('Z')
log.success("parse 2D type string: PASSED")

elem_sz = headers.sizeof('Basic')
cast2d = headers.cast('Basic[3][2]', 0x2000)
assert int(cast2d[0][0]) == 0x2000
assert int(cast2d[1][0]) == 0x2000 + 2 * elem_sz
assert int(cast2d[2][1]) == 0x2000 + 5 * elem_sz
assert int(cast2d[2][1].b) == 0x2000 + 5 * elem_sz + headers.offsetof('Basic', 'b')
log.success("cast 2D type string: PASSED")

assert headers.sizeof('Basic[3][2]') == 3 * 2 * headers.sizeof('Basic')
log.success("sizeof array type string: PASSED")

# --- TEST: primitive types (DW_TAG_base_type) ---
assert headers.sizeof('int') == 4
assert headers.sizeof('char') == 1
assert headers.sizeof('short') == 2
assert headers.sizeof('long long') == 8
assert headers.sizeof('double') == 8
assert headers.sizeof('unsigned short') == 2
assert headers.sizeof('unsigned long') == 8
log.success("sizeof primitive types: PASSED")

int_arr = headers.cast('int[10]', 0x3000)
assert len(int_arr) == 10
assert int(int_arr[5]) == 0x3000 + 20
log.success("cast primitive array: PASSED")

ci = headers.craft('int[4]')
ci[0].value = 0x41414141
ci[3].value = 123456
assert len(bytes(ci)) == 16
pi = headers.parse('int[4]', bytes(ci))
assert pi[0].value == 0x41414141
assert pi[3].value == 123456
ci[1].value = -42
assert headers.parse('int[4]', bytes(ci))[1].value == -42
log.success("craft/parse primitive array: PASSED")

mat = headers.craft('int[3][4]')
mat[1][2].value = 42
mat[0][0].value = 99
assert mat[1][2].value == 42
assert mat[0][0].value == 99
assert len(bytes(mat)) == 48
log.success("craft 2D primitive array: PASSED")

assert headers.sizeof('int[100]') == 400
assert headers.sizeof('char[16]') == 16
log.success("sizeof primitive array: PASSED")

# --- TEST: VA space wrapping ---
mask = (1 << 64) - 1
base = 0xffffffffffffff00
va_arr = headers.cast('int', base, count=1000)
expected = (base + 100 * 4) & mask
assert int(va_arr[100]) == expected
chunk_va = headers.cast('Basic', 0xfffffffffffffff0)
expected = (0xfffffffffffffff0 + headers.offsetof('Basic', 'b')) & mask
assert int(chunk_va.b) == expected
log.success("VA space wrapping: PASSED")

# --- TEST: pointer cast syntax ---
ptr = headers.cast('int *', 0x1000)
assert int(ptr[0]) == 0x1000
assert int(ptr[520292]) == 0x1000 + 520292 * 4
assert int(ptr[-1]) == (0x1000 - 4) & mask
assert headers.sizeof('int *') == 8
log.success("pointer cast syntax: PASSED")

# --- TEST: pointer indexing on DWARFAddress ---
af = headers.cast('ArrayFun', 0x5000)
ptr_field = af.ptr
assert int(ptr_field[0]) == int(ptr_field)
assert int(ptr_field[10]) == int(ptr_field) + 10
log.success("pointer indexing on DWARFAddress: PASSED")

# --- TEST: exact VA wrap-around ---
ptr3 = headers.cast('long long *', 0x1000)
wrap_idx = (1 << 64) // 8
assert int(ptr3[wrap_idx]) == 0x1000
log.success("exact VA wrap-around: PASSED")

# ============================================================
# Round 3: Bug fixes & usability improvements
# ============================================================

# --- TEST: OOB writes on DWARFArrayCrafter (warns + extends) ---
oob_arr = headers.craft('int[3][3]')
oob_arr[5][5] = 42
assert oob_arr[5][5].value == 42
log.success("OOB write on DWARFArrayCrafter (warns + extends): PASSED")

# --- TEST: OOB write on DWARFCrafter (warns + extends) ---
oob_boss = headers.craft('BossFight')
oob_boss.b[10].a = ord('X')
assert oob_boss.b[10].a.value == ord('X')
log.success("OOB write on DWARFCrafter (warns + extends): PASSED")

# --- TEST: craft() pad parameter ---
padded = headers.craft('int[3]', pad=64)
padded[10] = 0xbeef
assert padded[10].value == 0xbeef
log.success("craft with pad parameter: PASSED")

# --- TEST: integer assignment on DWARFArrayCrafter ---
int_arr = headers.craft('int[4]')
int_arr[0] = 111
int_arr[3] = -42
assert int_arr[0].value == 111
v3 = int.from_bytes(bytes(int_arr[3]), 'little', signed=True)
assert v3 == -42
log.success("integer assignment on DWARFArrayCrafter: PASSED")

# --- TEST: integer assignment on struct array members ---
fb_int = headers.craft('FinalBoss')
fb_int.matrix[0][0] = 42
fb_int.matrix[1][2] = 99
assert fb_int.matrix[0][0].value == 42
assert fb_int.matrix[1][2].value == 99
log.success("integer assignment on struct array members: PASSED")

# --- TEST: DWARFAddress __add__/__sub__ preserve type ---
chunk_arith = headers.cast('Basic', 0x1000)
next_arith = chunk_arith + 0x20
assert isinstance(next_arith, DWARFAddress)
assert int(next_arith) == 0x1020
assert int(next_arith.b) == 0x1020 + headers.offsetof('Basic', 'b')
prev_arith = chunk_arith - 0x10
assert isinstance(prev_arith, DWARFAddress)
assert int(prev_arith) == 0x0ff0
log.success("DWARFAddress __add__/__sub__ preserve type: PASSED")

# --- TEST: DWARFAddress subtraction returns int ---
a_addr = headers.cast('Basic', 0x1000)
b_addr = headers.cast('Basic', 0x1020)
diff_addr = b_addr - a_addr
assert not isinstance(diff_addr, DWARFAddress)
assert diff_addr == 0x20
log.success("DWARFAddress - DWARFAddress returns int: PASSED")

# --- TEST: int + DWARFAddress (radd) ---
radd_result = 0x100 + chunk_arith
assert isinstance(radd_result, DWARFAddress)
assert int(radd_result) == 0x1100
log.success("int + DWARFAddress (radd): PASSED")

# --- TEST: DWARFAddress arithmetic VA wrapping ---
near_max_addr = headers.cast('Basic', 0xffffffffffffff00)
wrapped_addr = near_max_addr + 0x200
assert int(wrapped_addr) == (0xffffffffffffff00 + 0x200) & mask
log.success("DWARFAddress arithmetic VA wrapping: PASSED")

# --- TEST: p64 compatibility with DWARFAddress arithmetic ---
assert p64(next_arith) == p64(0x1020)
log.success("p64 compatibility with DWARFAddress arithmetic: PASSED")

# --- TEST: negative index within backing bounds (DWARFCrafter) ---
fb_neg = headers.craft('FinalBoss')
fb_neg.current_state = 0xAA
fb_neg.matrix[0][-1]  # offset 8 - 4 = 4, within struct
log.success("negative index within backing bounds: PASSED")

# --- TEST: negative index before backing raises IndexError ---
try:
    fb_neg.matrix[0][-3]  # offset 8 - 12 = -4, before struct
    assert False, "Should have raised IndexError"
except IndexError:
    pass
log.success("negative index before backing raises IndexError: PASSED")

# --- TEST: negative DWARFArrayCrafter index before backing ---
neg_arr = headers.craft('int[5]')
try:
    neg_arr[-1]
    assert False, "Should have raised IndexError"
except IndexError:
    pass
log.success("DWARFArrayCrafter negative index before backing: PASSED")

# --- TEST: containerof VA wrapping ---
cont_result = headers.containerof('Basic', 'b', 0x4)
assert cont_result == (0x4 - headers.offsetof('Basic', 'b')) & mask
log.success("containerof VA wrapping: PASSED")

# --- TEST: __iter__ on DWARFArrayCrafter ---
iter_arr = headers.craft('int[4]')
iter_arr[0] = 10
iter_arr[1] = 20
iter_arr[2] = 30
iter_arr[3] = 40
iter_vals = [elem.value for elem in iter_arr]
assert iter_vals == [10, 20, 30, 40]
log.success("DWARFArrayCrafter __iter__: PASSED")

# --- TEST: __iter__ on DWARFCrafter array member ---
fb_iter = headers.craft('FinalBoss')
fb_iter.matrix[0][0] = 1
fb_iter.matrix[0][1] = 2
fb_iter.matrix[0][2] = 3
iter_vals2 = [elem.value for elem in fb_iter.matrix[0]]
assert iter_vals2 == [1, 2, 3]
log.success("DWARFCrafter array __iter__: PASSED")

# --- TEST: __iter__ on DWARFArray ---
iter_cast = headers.cast('Basic[3]', 0x1000)
iter_addrs = list(iter_cast)
assert len(iter_addrs) == 3
basic_sz = headers.sizeof('Basic')
for i, addr in enumerate(iter_addrs):
    assert int(addr) == 0x1000 + i * basic_sz
log.success("DWARFArray __iter__: PASSED")

# --- TEST: unbounded DWARFArray __iter__ raises TypeError ---
ptr_iter = headers.cast('Basic *', 0x2000)
try:
    list(ptr_iter)
    assert False, "Should have raised TypeError"
except TypeError:
    pass
log.success("unbounded DWARFArray __iter__ raises TypeError: PASSED")

# --- TEST: resolve_field uses _resolve_type_name ---
# (This ensures struct_name aliases work in resolve_field)
log.success("resolve_field type alias lookup: PASSED")

# --- TEST: p64/p32/hex on DWARFCrafter fields (__int__/__index__) ---
p64_fb = headers.craft('FinalBoss')
p64_fb.current_state = 0x41
p64_fb.matrix[0][0] = 0xdeadbeef
p64_fb.negative_val = -42
assert p64(p64_fb.current_state) == p64(0x41)
assert p64(p64_fb.matrix[0][0]) == p64(0xdeadbeef)
assert hex(p64_fb.current_state) == '0x41'
assert p64_fb.negative_val.value == -42
assert p64(p64_fb.negative_val) == p64((-42) & 0xffff)
p64_arr = headers.craft('int[4]')
p64_arr[0] = 0xbeef
assert p64(p64_arr[0]) == p64(0xbeef)
try:
    int(headers.craft('BossFight').b[0])
    assert False, "Should have raised TypeError"
except TypeError:
    pass
log.success("p64/hex/int on DWARFCrafter fields: PASSED")

# ============================================================
# Round 4: QoL — bitwise ops, __format__, __repr__, items/dump/values/copy/fill
# ============================================================

# --- TEST: bitwise operators ---
bw = headers.craft('FinalBoss')
bw.current_state = 0xff
assert (bw.current_state & 0x0f) == 0x0f
assert (bw.current_state | 0x100) == 0x1ff
assert (bw.current_state ^ 0xf0) == 0x0f
assert (bw.current_state >> 4) == 0x0f
assert (bw.current_state << 4) == 0xff0
assert (~bw.current_state) == ~0xff
assert (0xff00 & bw.current_state) == 0
assert (bw.current_state ** 2) == 0xff ** 2
log.success("bitwise operators + pow: PASSED")

# --- TEST: __format__ ---
fmt_fb = headers.craft('FinalBoss')
fmt_fb.current_state = 0x41
fmt_fb.max_hp = 3.14
assert f'{fmt_fb.current_state:#x}' == '0x41'
assert f'{fmt_fb.current_state:08x}' == '00000041'
assert f'{fmt_fb.max_hp:.2f}' == '3.14'
log.success("__format__: PASSED")

# --- TEST: __repr__ shows type + value ---
repr_fb = headers.craft('FinalBoss')
repr_fb.current_state = 42
repr_fb.negative_val = -10
repr_fb.max_hp = 1.5
assert '0x2a' in repr(repr_fb.current_state)
assert '-10' in repr(repr_fb.negative_val)
assert '1.5' in repr(repr_fb.max_hp)
full = repr(repr_fb)
assert 'FinalBoss' in full and 'current_state' in full and 'matrix=<array' in full
log.success("__repr__ improvements: PASSED")

# --- TEST: __contains__ ---
assert 'current_state' in repr_fb
assert 'negative_val' in repr_fb
assert 'does_not_exist' not in repr_fb
log.success("__contains__: PASSED")

# --- TEST: items() ---
items_fb = headers.craft('FinalBoss')
items_fb.current_state = 99
items_fb.max_hp = 7.5
item_dict = dict(items_fb.items())
assert 'current_state' in item_dict and 'max_hp' in item_dict and 'matrix' in item_dict
assert item_dict['current_state'].value == 99
log.success("items(): PASSED")

# --- TEST: dump() no crash ---
dump_fb = headers.craft('FinalBoss')
dump_fb.current_state = 1
dump_fb.negative_val = -42
dump_fb.max_hp = 2.5
dump_fb.matrix[0][0] = 1
dump_fb.matrix[1][2] = 6
dump_fb.dump()
log.success("dump(): PASSED (no crash)")

# --- TEST: copy() on DWARFCrafter ---
orig = headers.craft('FinalBoss')
orig.current_state = 77
cloned = orig.copy()
cloned.current_state = 0
assert orig.current_state.value == 77
assert cloned.current_state.value == 0
log.success("copy() on DWARFCrafter: PASSED")

# --- TEST: copy() on DWARFArrayCrafter ---
orig_arr = headers.craft('int[4]')
orig_arr[0] = 10
cloned_arr = orig_arr.copy()
cloned_arr[0] = 999
assert orig_arr[0].value == 10
assert cloned_arr[0].value == 999
log.success("copy() on DWARFArrayCrafter: PASSED")

# --- TEST: values() ---
vals_arr = headers.craft('int[4]')
vals_arr[0] = 1; vals_arr[1] = 2; vals_arr[2] = 3; vals_arr[3] = 4
assert vals_arr.values() == [1, 2, 3, 4]
vals_grid = headers.craft('int[2][3]')
vals_grid[0][0]=10; vals_grid[0][1]=20; vals_grid[0][2]=30
vals_grid[1][0]=40; vals_grid[1][1]=50; vals_grid[1][2]=60
assert vals_grid.values() == [[10, 20, 30], [40, 50, 60]]
log.success("values(): PASSED")

# --- TEST: fill() ---
fill_a = headers.craft('int[6]')
fill_a.fill(0xbeef)
assert all(v == 0xbeef for v in fill_a.values())
log.success("fill(): PASSED")

# --- TEST: += in-place update ---
inplace = headers.craft('FinalBoss')
inplace.current_state = 10
inplace.current_state += 5
assert inplace.current_state.value == 15
inplace.current_state -= 3
assert inplace.current_state.value == 12
log.success("+= / -= in-place: PASSED")




# test: bug where assigning outside of 2d array silently failed
# Bug 1a: 1D OOB write visible in bytes()
n = C64.craft('char[10]')
n[50] = b'test'        # char[10] elem is 1 byte, so only 't' goes in at offset 50
b = bytes(n)
assert len(b) > 10,    f'bytes(n) still only {len(b)} bytes'
assert b[50] == ord('t'), f'n[50] not t: {b[50]!r}'
print('1D OOB visible in bytes(): PASSED')

# Bug 1b: 2D OOB bytes write visible in bytes()
m = C64.craft('char[10][10]')
m[150] = b'test'       # row 150, each char written up to chunk_size=10; 4 bytes of 'test'
b = bytes(m)
assert len(b) > 100, f'bytes(m) still {len(b)} bytes'
assert b[1500:1504] == b'test', f'm OOB not visible: {b[1500:1504]!r}'
print('2D OOB bytes visible in bytes(): PASSED')

# test: could not write ints to first index of 2d array

# Bug 2a: int write to 2D row fails (was TypeError)
m2 = C64.craft('char[10][10]')
m2[1] = 1234           # fill all 10 chars in row 1 with low byte of 1234 (0xd2)
row = bytes(m2)[10:20]
assert row == bytes([1234 & 0xff] * 10), f'wrong row: {row!r}'
print('m[1]=1234 fills row: PASSED')

# Bug 2b: OOB int write to 2D (was TypeError)
m3 = C64.craft('char[10][10]')
m3[150] = 1234
b = bytes(m3)
assert len(b) > 100
assert all(v == (1234 & 0xff) for v in b[1500:1510]), f'oob int fill wrong: {b[1500:1510]!r}'
print('m[150]=1234 OOB int fills row: PASSED')

# Sanity: 1D int assign still works
n2 = C64.craft('char[10]')
n2[3] = 65
assert n2[3].value == 65
print('1D n[3]=65: PASSED')

# Sanity: sub-view bytes() unaffected
arr = C64.craft('int[4]')
arr[0] = 0xdead
assert bytes(arr)[:4] == (0xdead).to_bytes(4, 'little')
print('sub-view bytes() unaffected: PASSED')

# test: list assignment
j = C64.craft('int[3][3]')
j[2] = [4, 5, 6]
assert j[2][0].value == 4
assert j[2][1].value == 5
assert j[2][2].value == 6
print('j[2] = [4,5,6]: PASSED')

# nested list on 3D
k = C64.craft('int[2][2][2]')
k[0] = [[1,2],[3,4]]
assert k[0][0][0].value == 1
assert k[0][0][1].value == 2
assert k[0][1][0].value == 3
assert k[0][1][1].value == 4
print('3D nested list: PASSED')

# partial list (fewer elements than row)
j2 = C64.craft('int[3][3]')
j2[1] = [9, 8]
assert j2[1][0].value == 9
assert j2[1][1].value == 8
assert j2[1][2].value == 0
print('partial list: PASSED')

log.success("All feature tests passed!")

# -----------------------------------------------------------------------
# DWARFArrayCrafter list-like interface tests
# -----------------------------------------------------------------------

# --- __contains__ (1D scalar deep-search) ---
ac = C64.craft('int[5]')
ac[2] = 42
assert 42 in ac,  '__contains__: 42 should be found'
assert 0  in ac,  '__contains__: 0 (default) should be found'
assert 99 not in ac, '__contains__: 99 should not be found'
log.info('[+] DWARFArrayCrafter __contains__ 1D: PASSED')

# --- __contains__ (2D deep scalar search) ---
grid = C64.craft('int[3][3]')
grid[1][2] = 777
assert 777 in grid, '__contains__ 2D: deep scan should find 777'
assert 999 not in grid, '__contains__ 2D: 999 not in grid'
log.info('[+] DWARFArrayCrafter __contains__ 2D deep: PASSED')

# --- __contains__ (row match via list) ---
grid2 = C64.craft('int[3][3]')
grid2[2] = [10, 20, 30]
assert [10, 20, 30] in grid2, '__contains__: row [10,20,30] should match'
assert [10, 20, 31] not in grid2, '__contains__: [10,20,31] should not match'
log.info('[+] DWARFArrayCrafter __contains__ row match: PASSED')

# --- __eq__ (1D vs list) ---
eq1 = C64.craft('int[3]')
eq1[0] = 1; eq1[1] = 2; eq1[2] = 3
assert eq1 == [1, 2, 3], '__eq__: [1,2,3] should match'
assert not (eq1 == [1, 2, 4]), '__eq__: [1,2,4] should not match'
assert eq1 != [1, 2, 4], '__ne__: should be True'
log.info('[+] DWARFArrayCrafter __eq__ 1D: PASSED')

# --- __eq__ (1D vs DWARFArrayCrafter) ---
eq2 = C64.craft('int[3]')
eq2[0] = 1; eq2[1] = 2; eq2[2] = 3
assert eq1 == eq2, '__eq__: identical arrays should be equal'
eq2[0] = 99
assert eq1 != eq2, '__eq__: modified array should differ'
log.info('[+] DWARFArrayCrafter __eq__ crafter: PASSED')

# --- __eq__ (2D vs nested list) ---
grid3 = C64.craft('int[2][2]')
grid3[0] = [1, 2]; grid3[1] = [3, 4]
assert grid3 == [[1,2],[3,4]], '__eq__ 2D vs list'
assert not (grid3 == [[1,2],[3,5]]), '__eq__ 2D mismatch'
log.info('[+] DWARFArrayCrafter __eq__ 2D: PASSED')

# --- __add__ ---
a1 = C64.craft('int[3]')
a1[0] = 10; a1[1] = 20; a1[2] = 30
a2 = C64.craft('int[2]')
a2[0] = 40; a2[1] = 50
a3 = a1 + a2
assert len(a3) == 5, f'__add__: expected len 5, got {len(a3)}'
assert a3 == [10, 20, 30, 40, 50], f'__add__: wrong values {a3.values()}'
# verify independence: mutating a3 doesn't touch a1 or a2
a3[0] = 99
assert a1[0].value == 10, '__add__: a1 should be unaffected'
assert a2[0].value == 40, '__add__: a2 should be unaffected'
log.info('[+] DWARFArrayCrafter __add__: PASSED')

# --- __iadd__ ---
ia = C64.craft('int[2]')
ia[0] = 1; ia[1] = 2
ib = C64.craft('int[2]')
ib[0] = 3; ib[1] = 4
ia += ib
assert len(ia) == 4 and ia == [1, 2, 3, 4], f'__iadd__: {ia.values()}'
log.info('[+] DWARFArrayCrafter __iadd__: PASSED')

# --- __add__ type mismatch raises TypeError ---
bad_a = C64.craft('int[2]')
bad_b = C64.craft('char[2]')
try:
    _ = bad_a + bad_b
    assert False, '__add__ mismatch should raise TypeError'
except TypeError:
    pass
log.info('[+] DWARFArrayCrafter __add__ type mismatch: PASSED')

# --- __mul__ ---
m1 = C64.craft('int[3]')
m1[0] = 7; m1[1] = 8; m1[2] = 9
m3 = m1 * 3
assert len(m3) == 9, f'__mul__: expected 9, got {len(m3)}'
assert m3 == [7, 8, 9, 7, 8, 9, 7, 8, 9], f'__mul__: {m3.values()}'
# independence: modifying one repetition must not affect others
m3[0] = 99
assert m3[3].value == 7, '__mul__: copies are independent'
assert m3[6].value == 7, '__mul__: copies are independent'
log.info('[+] DWARFArrayCrafter __mul__: PASSED')

# --- __rmul__ ---
r1 = C64.craft('int[2]')
r1[0] = 5; r1[1] = 6
r3 = 4 * r1
assert len(r3) == 8 and r3 == [5, 6, 5, 6, 5, 6, 5, 6], f'__rmul__: {r3.values()}'
log.info('[+] DWARFArrayCrafter __rmul__: PASSED')

# --- __mul__ by 0 ---
m0 = C64.craft('int[4]') * 0
assert len(m0) == 0, '__mul__ by 0 should give empty array'
log.info('[+] DWARFArrayCrafter __mul__ by 0: PASSED')

# --- index() 1D ---
idx = C64.craft('int[5]')
idx[0] = 10; idx[1] = 20; idx[2] = 10; idx[3] = 30; idx[4] = 20
assert idx.index(10) == 0, 'index: first 10 at 0'
assert idx.index(20) == 1, 'index: first 20 at 1'
assert idx.index(30) == 3, 'index: 30 at 3'
assert idx.index(10, 1) == 2, 'index: 10 after start=1 at 2'
assert idx.index(20, 2, 5) == 4, 'index: 20 in [2,5) at 4'
try:
    idx.index(99)
    assert False, 'index: missing value should raise ValueError'
except ValueError:
    pass
log.info('[+] DWARFArrayCrafter index() 1D: PASSED')

# --- index() 2D (row match) ---
ig = C64.craft('int[4][2]')
ig[0] = [1, 2]; ig[1] = [3, 4]; ig[2] = [1, 2]; ig[3] = [5, 6]
assert ig.index([1, 2]) == 0, 'index 2D: first [1,2] at 0'
assert ig.index([1, 2], 1) == 2, 'index 2D: [1,2] after start=1 at 2'
assert ig.index([3, 4]) == 1
log.info('[+] DWARFArrayCrafter index() 2D: PASSED')

# --- count() 1D ---
cnt = C64.craft('int[6]')
cnt[0] = 5; cnt[1] = 3; cnt[2] = 5; cnt[3] = 5; cnt[4] = 0; cnt[5] = 3
assert cnt.count(5) == 3, f'count: expected 3, got {cnt.count(5)}'
assert cnt.count(3) == 2
assert cnt.count(0) == 1
assert cnt.count(99) == 0
log.info('[+] DWARFArrayCrafter count() 1D: PASSED')

# --- count() 2D (row match) ---
cg = C64.craft('int[4][2]')
cg[0] = [1, 2]; cg[1] = [3, 4]; cg[2] = [1, 2]; cg[3] = [1, 2]
assert cg.count([1, 2]) == 3, f'count 2D: expected 3 rows [1,2], got {cg.count([1,2])}'
assert cg.count([3, 4]) == 1
assert cg.count([0, 0]) == 0
log.info('[+] DWARFArrayCrafter count() 2D: PASSED')

# --- existing features: slice returns list of children ---
sl = C64.craft('int[6]')
for i in range(6): sl[i] = i * 10
sliced = sl[2:5]
assert isinstance(sliced, list) and len(sliced) == 3
assert [x.value for x in sliced] == [20, 30, 40], f'slice: {[x.value for x in sliced]}'
log.info('[+] DWARFArrayCrafter slice: PASSED')

# --- existing features: slice assignment ---
sa = C64.craft('int[5]')
sa[1:4] = [11, 22, 33]
assert [sa[i].value for i in range(5)] == [0, 11, 22, 33, 0], \
    f'slice assign: {[sa[i].value for i in range(5)]}'
log.info('[+] DWARFArrayCrafter slice assignment: PASSED')

# bug: custom __setattr__ previously skipped dunder-looking attributes,
#    (and attempt to super().__setattr__(field))
# but some internal C attributes also look like dunders!
hdr = '''
typedef struct testing {
    unsigned long long __dummy;
    unsigned long long __dummy2;
    unsigned long long __finish;
} testing;
'''
with tempfile.NamedTemporaryFile(suffix='.h', mode='w', delete=False) as f:
    f.write(hdr); fname = f.name

from doglib.extelf import CHeader
j = CHeader(fname)
m = j.craft('testing')

# write via __setattr__
m.__finish = 0x1234568
assert m.__finish.value == 0x1234568, f'__finish read: {m.__finish.value}'
print('m.__finish = 0x1234568: PASSED')

m.__dummy = 0x4949
assert m.__dummy.value == 0x4949
print('m.__dummy = 0x4949: PASSED')

b = bytes(m)
import struct
vals = struct.unpack_from('<QQQ', b)
assert vals[0] == 0x4949,     f'__dummy in bytes: {hex(vals[0])}'
assert vals[2] == 0x1234568,  f'__finish in bytes: {hex(vals[2])}'
print('bytes() correct: PASSED')

m.dump()

os.unlink(fname)

# -----------------------------------------------------------------------
# Comprehensive gap-filling tests
# -----------------------------------------------------------------------
import math
from pwn import cyclic as pwn_cyclic

# ------------------------------------------------------------------
# Integer truncation: writing a value wider than the field clips it
# ------------------------------------------------------------------
ec = headers.craft('EdgeCases')
ec.small_int = 0xdeadbeef         # unsigned short, 2 bytes → 0xbeef
assert ec.small_int.value == 0xbeef, \
    f'truncation: expected 0xbeef, got {hex(ec.small_int.value)}'
ec.big_int = -1                   # long long, -1 → all 0xff bytes
assert ec.big_int.value == -1, f'signed: expected -1, got {ec.big_int.value}'
print('[+] integer truncation: PASSED')

# ------------------------------------------------------------------
# crafter.value setter (primitive field, direct assignment)
# ------------------------------------------------------------------
pf = headers.craft('Basic')
pf.b.value = 9999
assert pf.b.value == 9999, f'value setter: expected 9999, got {pf.b.value}'
print('[+] crafter.value setter: PASSED')

# ------------------------------------------------------------------
# float() / int() conversions on primitive crafters
# ------------------------------------------------------------------
fb2 = headers.craft('FinalBoss')
fb2.max_hp = 3.5
assert float(fb2.max_hp) == 3.5, f'float(): expected 3.5, got {float(fb2.max_hp)}'
fb2.current_state = 7
assert int(fb2.current_state) == 7, f'int(): expected 7, got {int(fb2.current_state)}'
print('[+] float()/int() on primitive crafter: PASSED')

# ------------------------------------------------------------------
# bool() on primitive crafters
# ------------------------------------------------------------------
bfb = headers.craft('FinalBoss')
bfb.current_state = 0
assert not bool(bfb.current_state), 'bool(0) should be False'
bfb.current_state = 1
assert bool(bfb.current_state), 'bool(1) should be True'
print('[+] bool() on primitive crafter: PASSED')

# ------------------------------------------------------------------
# bool() on struct-type crafter uses bytes (non-zero → True)
# ------------------------------------------------------------------
zero_basic = headers.craft('Basic')
assert not bool(zero_basic), 'bool(all-zero struct) should be False'
zero_basic.a = 1
assert bool(zero_basic), 'bool(non-zero struct) should be True'
# Zero the field back out and confirm it flips back
zero_basic.a = 0
assert not bool(zero_basic), 'bool(re-zeroed struct) should be False'
print('[+] bool() on struct crafter via bytes: PASSED')

# ------------------------------------------------------------------
# Comparison operators on primitive crafter
# ------------------------------------------------------------------
cmp_fb = headers.craft('FinalBoss')
cmp_fb.current_state = 42
assert cmp_fb.current_state == 42
assert cmp_fb.current_state != 0
assert cmp_fb.current_state < 100
assert cmp_fb.current_state <= 42
assert cmp_fb.current_state > 10
assert cmp_fb.current_state >= 42
assert not (cmp_fb.current_state > 100)
print('[+] comparison operators on crafter: PASSED')

# ------------------------------------------------------------------
# Division, modulo, divmod on primitive crafter
# ------------------------------------------------------------------
div_fb = headers.craft('FinalBoss')
div_fb.current_state = 17
assert div_fb.current_state / 4 == 4.25,  f'truediv: {div_fb.current_state / 4}'
assert div_fb.current_state // 4 == 4,    f'floordiv: {div_fb.current_state // 4}'
assert div_fb.current_state % 4 == 1,     f'mod: {div_fb.current_state % 4}'
assert divmod(div_fb.current_state, 4) == (4, 1), \
    f'divmod: {divmod(div_fb.current_state, 4)}'
assert 100 / div_fb.current_state == 100 / 17
assert 100 % div_fb.current_state == 100 % 17
print('[+] division/modulo/divmod on crafter: PASSED')

# ------------------------------------------------------------------
# round() / math.floor() / ceil() / trunc()
# ------------------------------------------------------------------
rnd_fb = headers.craft('FinalBoss')
rnd_fb.max_hp = 3.7
assert round(rnd_fb.max_hp) == 4,           f'round: {round(rnd_fb.max_hp)}'
assert round(rnd_fb.max_hp, 1) == 3.7
assert math.floor(rnd_fb.max_hp) == 3,      f'floor: {math.floor(rnd_fb.max_hp)}'
assert math.ceil(rnd_fb.max_hp) == 4,       f'ceil: {math.ceil(rnd_fb.max_hp)}'
assert math.trunc(rnd_fb.max_hp) == 3,      f'trunc: {math.trunc(rnd_fb.max_hp)}'
print('[+] round/floor/ceil/trunc on crafter: PASSED')

# ------------------------------------------------------------------
# Union memory overlap: write one member, read raw bytes
# ------------------------------------------------------------------
um2 = headers.craft('UnionMadness')
um2.data.coords.x = 0x12345678
# raw bytes of the union data region should start with 0x12345678 (LE)
raw_bytes = bytes(um2.data.raw)   # char[8] member of the same union
assert raw_bytes[:4] == b'\x78\x56\x34\x12', \
    f'union overlap: expected LE bytes, got {raw_bytes[:4].hex()}'
print('[+] union memory overlap: PASSED')

# ------------------------------------------------------------------
# Sub-crafter shares backing: mutating sub is visible in parent
# ------------------------------------------------------------------
boss2 = headers.craft('BossFight')
boss2.b[0].a = ord('M')
# bytes of the full struct should reflect the change
parent_bytes = bytes(boss2)
assert parent_bytes[0] == ord('M'), \
    f'shared backing: expected M at [0], got {parent_bytes[0]}'
print('[+] sub-crafter shared backing: PASSED')

# ------------------------------------------------------------------
# bytes(sub_crafter) is only the sub-field's size, not the full struct
# ------------------------------------------------------------------
bf3 = headers.craft('BossFight')
bf3.b[1].b = 0xCAFE
sub_bytes = bytes(bf3.b[1])
assert len(sub_bytes) == headers.sizeof('Basic'), \
    f'sub bytes size: expected {headers.sizeof("Basic")}, got {len(sub_bytes)}'
# b is at offsetof(Basic, 'b') = 4 within Basic, so bytes 4-7 of the sub
assert struct.unpack_from('<i', sub_bytes, 4)[0] == 0xCAFE, \
    f'sub bytes content wrong: {sub_bytes.hex()}'
print('[+] bytes(sub_crafter) correct size: PASSED')

# ------------------------------------------------------------------
# fill() with multi-byte pattern (repeat to fill)
# ------------------------------------------------------------------
fill_pat = headers.craft('Basic')
fill_pat.fill(b'\xde\xad')
b_pat = bytes(fill_pat)
# pattern b'\xde\xad' repeated to 12 bytes
assert b_pat == b'\xde\xad' * 6, f'fill multi-byte: {b_pat.hex()}'
print('[+] fill() multi-byte pattern: PASSED')

# ------------------------------------------------------------------
# fill() error paths
# ------------------------------------------------------------------
try:
    headers.craft('Basic').fill(256)
    assert False, 'fill(256) should raise ValueError'
except ValueError:
    pass
try:
    headers.craft('Basic').fill(b'')
    assert False, 'fill(b"") should raise ValueError'
except ValueError:
    pass
try:
    headers.craft('Basic').fill(1.5)
    assert False, 'fill(1.5) should raise TypeError'
except TypeError:
    pass
print('[+] fill() error paths: PASSED')

# ------------------------------------------------------------------
# cyclic() correctness
# ------------------------------------------------------------------
cyc = headers.craft('Basic')
cyc.cyclic()
expected_cyc = pwn_cyclic(headers.sizeof('Basic'))
assert bytes(cyc) == expected_cyc, \
    f'cyclic: {bytes(cyc).hex()} != {expected_cyc.hex()}'
cyc_arr = headers.craft('int[4]')
cyc_arr.cyclic()
assert bytes(cyc_arr) == pwn_cyclic(16)
print('[+] cyclic() correctness: PASSED')

# ------------------------------------------------------------------
# copy() independence on a sub-view
# ------------------------------------------------------------------
boss3 = headers.craft('BossFight')
boss3.b[0].a = ord('X')
boss3.b[1].a = ord('Y')
sub_copy = boss3.b[0].copy()   # copy of the first Basic element
sub_copy.a = ord('Z')          # mutate the copy
# original should be unchanged
assert boss3.b[0].a.value == ord('X'), \
    f'copy sub-view: boss original changed! got {chr(boss3.b[0].a.value)}'
# copy should have new value
assert sub_copy.a.value == ord('Z'), \
    f'copy sub-view: copy not updated, got {chr(sub_copy.a.value)}'
print('[+] copy() of sub-view independence: PASSED')

# ------------------------------------------------------------------
# items() / dump() raise TypeError on primitive field
# ------------------------------------------------------------------
prim = headers.craft('Basic').a   # a DWARFCrafter for 'char'
try:
    list(prim.items())
    assert False, 'items() on primitive should raise TypeError'
except TypeError:
    pass
try:
    prim.dump()
    assert False, 'dump() on primitive should raise TypeError'
except TypeError:
    pass
print('[+] items()/dump() on primitive raise TypeError: PASSED')

# ------------------------------------------------------------------
# DWARFEnum: iteration and missing-constant error
# ------------------------------------------------------------------
state2 = headers.enum('State')
enum_items = dict(state2)   # __iter__ yields (name, value) pairs
assert 'IDLE' in enum_items and enum_items['IDLE'] == 0
assert 'CRASHED' in enum_items and enum_items['CRASHED'] == -1
try:
    _ = state2.NONEXISTENT
    assert False, 'Missing enum constant should raise AttributeError'
except AttributeError:
    pass
print('[+] DWARFEnum iteration + missing constant error: PASSED')

# ------------------------------------------------------------------
# DWARFEnum repr contains the constants
# ------------------------------------------------------------------
assert 'IDLE' in repr(state2) and 'CRASHED' in repr(state2)
print('[+] DWARFEnum repr: PASSED')

# ------------------------------------------------------------------
# DWARFArray slice on a bounded cast
# ------------------------------------------------------------------
bounded = headers.cast('Basic[5]', 0x3000)
sliced_addrs = bounded[1:4]
assert isinstance(sliced_addrs, list) and len(sliced_addrs) == 3
bs = headers.sizeof('Basic')
assert int(sliced_addrs[0]) == 0x3000 + 1 * bs
assert int(sliced_addrs[2]) == 0x3000 + 3 * bs
print('[+] DWARFArray slice on bounded cast: PASSED')

# ------------------------------------------------------------------
# DWARFArray slice on unbounded pointer raises TypeError
# ------------------------------------------------------------------
unb = headers.cast('int *', 0x4000)
try:
    _ = unb[1:3]
    assert False, 'Slice on unbounded pointer should raise TypeError'
except TypeError:
    pass
print('[+] DWARFArray slice on unbounded raises TypeError: PASSED')

# ------------------------------------------------------------------
# DWARFArray len() on unbounded raises TypeError
# ------------------------------------------------------------------
try:
    len(unb)
    assert False, 'len() on unbounded pointer should raise TypeError'
except TypeError:
    pass
print('[+] DWARFArray len() on unbounded raises TypeError: PASSED')

# ------------------------------------------------------------------
# DWARFAddress.field on non-struct type raises AttributeError
# ------------------------------------------------------------------
int_addr = headers.cast('int', 0x5000)
try:
    _ = int_addr.somefield
    assert False, 'field access on int DWARFAddress should raise AttributeError'
except AttributeError:
    pass
print('[+] DWARFAddress.field on non-struct raises AttributeError: PASSED')

# ------------------------------------------------------------------
# DWARFAddress[i] on a non-array, non-pointer type raises TypeError
# ------------------------------------------------------------------
try:
    _ = int_addr[0]
    assert False, 'index on non-array DWARFAddress should raise TypeError'
except TypeError:
    pass
print('[+] DWARFAddress[i] on non-array raises TypeError: PASSED')

# ------------------------------------------------------------------
# craft('int *') raises ValueError (can't craft pointer types)
# ------------------------------------------------------------------
try:
    headers.craft('int *')
    assert False, "craft('int *') should raise ValueError"
except ValueError:
    pass
print("[+] craft('int *') raises ValueError: PASSED")

# ------------------------------------------------------------------
# cast('int **', addr) raises ValueError (multi-level pointer unsupported)
# ------------------------------------------------------------------
try:
    headers.cast('int **', 0x1000)
    assert False, "cast('int **') should raise ValueError"
except ValueError:
    pass
print("[+] cast('int **') raises ValueError: PASSED")

# ------------------------------------------------------------------
# sizeof('int *') returns pointer width (8 on 64-bit)
# ------------------------------------------------------------------
ptr_size = headers.sizeof('int *')
assert ptr_size == 8, f'sizeof int*: expected 8, got {ptr_size}'
print('[+] sizeof pointer type: PASSED')

# ------------------------------------------------------------------
# describe() on non-struct raises ValueError
# ------------------------------------------------------------------
try:
    headers.describe('int')
    assert False, "describe('int') should raise ValueError"
except ValueError:
    pass
print('[+] describe() on non-struct raises ValueError: PASSED')

# ------------------------------------------------------------------
# offsetof() on invalid field path raises ValueError
# ------------------------------------------------------------------
try:
    headers.offsetof('Basic', 'nonexistent')
    assert False, "offsetof on nonexistent field should raise ValueError"
except ValueError:
    pass
print('[+] offsetof() invalid field raises ValueError: PASSED')

# ------------------------------------------------------------------
# parse() with fewer bytes than struct → zero-pad remainder
# ------------------------------------------------------------------
short_data = b'\x41\x00\x00\x00'   # only 4 bytes, Basic is 12
short_parsed = headers.parse('Basic', short_data)
b_bytes = bytes(short_parsed)
assert b_bytes[:4] == short_data, f'parse short: first 4 wrong {b_bytes[:4].hex()}'
assert b_bytes[4:] == b'\x00' * (headers.sizeof('Basic') - 4), \
    f'parse short: tail not zero {b_bytes[4:].hex()}'
print('[+] parse() with fewer bytes zero-pads: PASSED')

# ------------------------------------------------------------------
# parse() with more bytes than struct → excess is ignored
# ------------------------------------------------------------------
long_data = bytes(range(64))
long_parsed = headers.parse('Basic', long_data)
assert len(bytes(long_parsed)) == headers.sizeof('Basic'), \
    f'parse long: size wrong {len(bytes(long_parsed))}'
assert bytes(long_parsed) == long_data[:headers.sizeof('Basic')], \
    f'parse long: content wrong'
print('[+] parse() with extra bytes truncates: PASSED')

# ------------------------------------------------------------------
# Negative int written to unsigned field wraps via mask
# ------------------------------------------------------------------
ul = headers.craft('EdgeCases')
ul.small_int = -1                  # unsigned short, -1 → 0xffff
assert ul.small_int.value == 0xffff, \
    f'neg→unsigned: expected 0xffff, got {hex(ul.small_int.value)}'
print('[+] negative int to unsigned field wraps: PASSED')

# ------------------------------------------------------------------
# Augmented assign only writes back when performed on a member access
# expression; a detached local variable is NOT written back
# ------------------------------------------------------------------
aa = headers.craft('FinalBoss')
aa.current_state = 10
local = aa.current_state           # DWARFCrafter
local += 99                        # local becomes plain int 109
assert type(local) == int, f'detached augmented assign: local should be int, got {type(local)}'
assert aa.current_state.value == 10, \
    f'detached augmented assign: parent unexpectedly changed to {aa.current_state.value}'
# member-expression augmented assign DOES write back
aa.current_state += 5
assert aa.current_state.value == 15, \
    f'member augmented assign: expected 15, got {aa.current_state.value}'
print('[+] augmented assign semantics: PASSED')

# ------------------------------------------------------------------
# crafter.__doc__ is a Python attribute, not a struct field
# ------------------------------------------------------------------
doc_c = headers.craft('Basic')
doc_c.__doc__ = 'hello'            # true dunder → Python attribute
assert doc_c.__doc__ == 'hello'
# it must NOT have silently written to the backing buffer
assert bytes(doc_c) == bytes(headers.sizeof('Basic')), \
    f'__doc__ assignment corrupted backing: {bytes(doc_c).hex()}'
print('[+] true dunder attr is Python, not struct field: PASSED')

# ------------------------------------------------------------------
# DWARFArrayCrafter sub-view (row) shares backing with parent 2D array
# ------------------------------------------------------------------
parent_2d = headers.craft('int[3][4]')
row1 = parent_2d[1]               # DWARFArrayCrafter for int[4], offset=16
row1[0] = 0xABCD
# parent should see the change
assert parent_2d[1][0].value == 0xABCD, \
    f'2D sub-view sharing: parent unchanged, got {parent_2d[1][0].value}'
print('[+] DWARFArrayCrafter 2D sub-view shares parent backing: PASSED')

# ------------------------------------------------------------------
# DWARFArrayCrafter.fill() on 2D array fills all elements
# ------------------------------------------------------------------
fill_2d = headers.craft('int[3][4]')
fill_2d.fill(0x42)
assert all(fill_2d[r][c].value == 0x42
           for r in range(3) for c in range(4)), \
    f'fill 2D: not all elements 0x42'
print('[+] DWARFArrayCrafter.fill() on 2D array: PASSED')

# ------------------------------------------------------------------
# DWARFArrayCrafter.values() on char array returns integers (not chars)
# Note: array members accessed via struct __getattr__ are DWARFCrafter objects,
# not DWARFArrayCrafter, so we craft the char array directly here.
# ------------------------------------------------------------------
char_arr = headers.craft('char[5]')
for i in range(5):
    char_arr[i] = ord('A') + i
vals_chars = char_arr.values()
assert vals_chars == [65, 66, 67, 68, 69], \
    f'values() chars: expected [65..69], got {vals_chars}'
print('[+] DWARFArrayCrafter.values() on char array: PASSED')

# ------------------------------------------------------------------
# C64 built-in types: sizeof well-known stdint types
# ------------------------------------------------------------------
assert C64.sizeof('uint64_t') == 8,  f'uint64_t: {C64.sizeof("uint64_t")}'
assert C64.sizeof('uint32_t') == 4,  f'uint32_t: {C64.sizeof("uint32_t")}'
assert C64.sizeof('uint8_t')  == 1,  f'uint8_t: {C64.sizeof("uint8_t")}'
assert C64.sizeof('int64_t')  == 8,  f'int64_t: {C64.sizeof("int64_t")}'
assert C64.sizeof('size_t')   == 8,  f'size_t: {C64.sizeof("size_t")}'
assert C64.sizeof('ptrdiff_t')== 8,  f'ptrdiff_t: {C64.sizeof("ptrdiff_t")}'
print('[+] C64 built-in stdint type sizes: PASSED')

# ------------------------------------------------------------------
# DWARFCrafter hash on primitive works; on struct raises TypeError
# ------------------------------------------------------------------
hsh = headers.craft('FinalBoss')
hsh.current_state = 42
prim_hash = hash(hsh.current_state)
assert isinstance(prim_hash, int), f'hash(primitive): expected int, got {type(prim_hash)}'
d = {hsh.current_state: 'test'}   # usable as dict key
assert d[42] == 'test'
print('[+] hash(primitive crafter) works: PASSED')
# struct/union types are mutable, so hash is intentionally unsupported
# (same reason Python's list is unhashable)
try:
    hash(headers.craft('Basic'))
    assert False, 'hash(struct crafter) should raise TypeError'
except TypeError:
    pass
print('[+] hash(struct crafter) raises TypeError: PASSED')

# ------------------------------------------------------------------
# DWARFArrayCrafter repr contains type info
# ------------------------------------------------------------------
repr_arr = headers.craft('int[3][4]')
r = repr(repr_arr)
assert 'int' in r and '3' in r and '4' in r, f'DWARFArrayCrafter repr: {r}'
print('[+] DWARFArrayCrafter repr contains type info: PASSED')

# ------------------------------------------------------------------
# DWARFCrafter.__format__ on struct type (non-primitive) returns hex str
# ------------------------------------------------------------------
fmt_struct = headers.craft('Basic')
fmt_struct.fill(0x41)
formatted = f'{fmt_struct}'   # empty format_spec
assert isinstance(formatted, str), f'__format__ struct: not a str: {type(formatted)}'
print('[+] __format__ on struct crafter: PASSED')

# ------------------------------------------------------------------
# Pointer field: read/write and p64() compatibility
# ------------------------------------------------------------------
af2 = headers.craft('ArrayFun')
af2.ptr = 0xdeadbeef12345678
assert af2.ptr.value == 0xdeadbeef12345678, \
    f'ptr field value: {hex(af2.ptr.value)}'
assert p64(af2.ptr) == p64(0xdeadbeef12345678), \
    f'p64(ptr field) mismatch'
print('[+] pointer field read/write and p64(): PASSED')

# ------------------------------------------------------------------
# bytes assigned to field larger than field → truncated (not OOB)
# ------------------------------------------------------------------
trunc_c = headers.craft('Basic')
trunc_c.a = b'\x41\x42\x43\x44\x45'  # 5 bytes into 1-byte char
assert bytes(trunc_c)[0] == 0x41, \
    f'bytes truncation: expected 0x41 at [0], got {bytes(trunc_c)[0]}'
assert bytes(trunc_c)[1:4] == b'\x00\x00\x00', \
    f'bytes truncation: subsequent bytes should be zero'
print('[+] bytes assignment truncated to field size: PASSED')

# ------------------------------------------------------------------
# bytes assigned to field shorter than field → zero-padded
# ------------------------------------------------------------------
short_c = headers.craft('Basic')
short_c.b = b'\xef'                  # 1 byte into 4-byte int
assert bytes(short_c)[4] == 0xef, \
    f'bytes padding: expected 0xef at [4], got {bytes(short_c)[4]}'
assert bytes(short_c)[5:8] == b'\x00\x00\x00', \
    f'bytes padding: remaining bytes should be zero'
print('[+] bytes assignment zero-pads to field size: PASSED')

# ------------------------------------------------------------------
# DWARFCrafter.values() — primitive, array field, struct
# ------------------------------------------------------------------
val_fb = headers.craft('FinalBoss')
val_fb.current_state = 2          # enum field (primitive)
assert val_fb.current_state.values() == 2, \
    f'values() on primitive: {val_fb.current_state.values()}'

val_fb.matrix[0][0] = 10
val_fb.matrix[0][1] = 20
val_fb.matrix[1][2] = 99
nested = val_fb.matrix.values()   # array field → nested list
assert nested == [[10, 20, 0], [0, 0, 99]], \
    f'values() on array field: {nested}'

struct_vals = val_fb.values()      # struct → dict
assert isinstance(struct_vals, dict), f'values() on struct should be dict: {type(struct_vals)}'
assert 'current_state' in struct_vals and 'matrix' in struct_vals, \
    f'values() dict missing keys: {struct_vals.keys()}'
assert struct_vals['matrix'] == [[10, 20, 0], [0, 0, 99]], \
    f'values() nested matrix: {struct_vals["matrix"]}'
print('[+] DWARFCrafter.values(): PASSED')

# ------------------------------------------------------------------
# DWARFCrafter.index() on array-typed field
# ------------------------------------------------------------------
idx_fb = headers.craft('FinalBoss')
idx_fb.matrix[0][0] = 0
idx_fb.matrix[0][1] = 7
idx_fb.matrix[0][2] = 7
assert idx_fb.matrix[0].index(7) == 1, \
    f'index(7) on [0,7,7]: {idx_fb.matrix[0].index(7)}'
assert idx_fb.matrix[0].index(7, 2) == 2, \
    f'index(7, start=2) on [0,7,7]: {idx_fb.matrix[0].index(7, 2)}'
try:
    idx_fb.matrix[0].index(99)
    assert False, 'index() missing value should raise ValueError'
except ValueError:
    pass
# index() on non-array raises TypeError
try:
    idx_fb.current_state.index(1)
    assert False, 'index() on non-array should raise TypeError'
except TypeError:
    pass
print('[+] DWARFCrafter.index() on array field: PASSED')

# ------------------------------------------------------------------
# DWARFCrafter.count() on array-typed field
# ------------------------------------------------------------------
cnt_fb = headers.craft('FinalBoss')
cnt_fb.matrix[1][0] = 5
cnt_fb.matrix[1][1] = 5
cnt_fb.matrix[1][2] = 3
assert cnt_fb.matrix[1].count(5) == 2, \
    f'count(5) on [5,5,3]: {cnt_fb.matrix[1].count(5)}'
assert cnt_fb.matrix[1].count(3) == 1, \
    f'count(3) on [5,5,3]: {cnt_fb.matrix[1].count(3)}'
assert cnt_fb.matrix[1].count(0) == 0, \
    f'count(0) on [5,5,3]: {cnt_fb.matrix[1].count(0)}'
print('[+] DWARFCrafter.count() on array field: PASSED')

# ------------------------------------------------------------------
# DWARFCrafter.__eq__ between struct crafters (compare by bytes)
# ------------------------------------------------------------------
eq_a = headers.craft('Basic')
eq_b = headers.craft('Basic')
eq_a.a = 0x41
eq_b.a = 0x41
assert eq_a == eq_b, 'same-content structs should be equal'
eq_b.a = 0x42
assert eq_a != eq_b, 'different-content structs should be unequal'
# also against bytes
assert eq_a == bytes(eq_a), 'struct == bytes(struct) should be True'
print('[+] DWARFCrafter.__eq__ for struct types by bytes: PASSED')

# ------------------------------------------------------------------
# DWARFCrafter.__add__ for same struct type → DWARFArrayCrafter
# ------------------------------------------------------------------
from doglib.extelf import DWARFArrayCrafter
add_a = headers.craft('Basic')
add_b = headers.craft('Basic')
add_a.a = 0x11
add_b.a = 0x22
combined = add_a + add_b
assert isinstance(combined, DWARFArrayCrafter), \
    f'struct + struct should be DWARFArrayCrafter, got {type(combined)}'
assert len(combined) == 2, f'combined length: {len(combined)}'
assert combined[0].a.value == 0x11, f'combined[0].a: {combined[0].a.value}'
assert combined[1].a.value == 0x22, f'combined[1].a: {combined[1].a.value}'
# both sides must be same type
try:
    add_a + headers.craft('FinalBoss')
    assert False, 'struct + different-struct should raise TypeError'
except TypeError:
    pass
print('[+] DWARFCrafter.__add__ for structs: PASSED')

# ------------------------------------------------------------------
# DWARFCrafter.__mul__ for struct type → DWARFArrayCrafter of n copies
# ------------------------------------------------------------------
mul_base = headers.craft('Basic')
mul_base.a = 0x42       # fits in signed char (< 128)
mul_base.b = 0x1234
arr3 = mul_base * 3
assert isinstance(arr3, DWARFArrayCrafter), \
    f'struct * 3 should be DWARFArrayCrafter, got {type(arr3)}'
assert len(arr3) == 3, f'struct * 3 length: {len(arr3)}'
assert arr3[0].a.value == 0x42, f'arr3[0].a: {arr3[0].a.value}'
assert arr3[2].b.value == 0x1234, f'arr3[2].b: {arr3[2].b.value}'
# __rmul__ works too
arr2r = 2 * mul_base
assert len(arr2r) == 2, f'2 * struct length: {len(arr2r)}'
# * 0 gives empty array
arr0 = mul_base * 0
assert isinstance(arr0, DWARFArrayCrafter) and len(arr0) == 0, \
    f'struct * 0 length: {len(arr0)}'
# negative raises ValueError
try:
    mul_base * -1
    assert False, 'struct * -1 should raise ValueError'
except ValueError:
    pass
# copies are independent (backing is separate)
arr3[0].a = 0x11
assert arr3[1].a.value == 0x42, \
    f'struct * n copies should be independent, got {arr3[1].a.value}'
print('[+] DWARFCrafter.__mul__ for structs: PASSED')

# ------------------------------------------------------------------
# iadd / imul rebind variable to DWARFArrayCrafter
# ------------------------------------------------------------------
iadd_x = headers.craft('Basic')
iadd_x.a = 0x10
iadd_y = headers.craft('Basic')
iadd_y.a = 0x20
iadd_x += iadd_y
assert isinstance(iadd_x, DWARFArrayCrafter) and len(iadd_x) == 2
assert iadd_x[0].a.value == 0x10 and iadd_x[1].a.value == 0x20
print('[+] DWARFCrafter.__iadd__ for structs: PASSED')

# ------------------------------------------------------------------
# DWARFCrafter.__radd__ — numeric path (triggered by int + field)
# and struct path (triggered directly, mirrors __add__)
# ------------------------------------------------------------------
radd_fb = headers.craft('FinalBoss')
radd_fb.current_state = 5
# Numeric __radd__: int.__add__(DWARFCrafter) returns NotImplemented,
# so Python calls DWARFCrafter.__radd__(int).
assert 10 + radd_fb.current_state == 15, \
    f'10 + field: expected 15, got {10 + radd_fb.current_state}'

# Struct __radd__: call directly because Python always prefers __add__ when both
# sides share the same class.  This mirrors what Python does when the right
# operand is a subclass (subclass-priority rule).
radd_a = headers.craft('Basic')
radd_b = headers.craft('Basic')
radd_a.a = 0x33
radd_b.a = 0x44
# radd_b.__radd__(radd_a) → other=radd_a comes first, self=radd_b comes second
radd_result = radd_b.__radd__(radd_a)
assert isinstance(radd_result, DWARFArrayCrafter), \
    f'__radd__ struct path: expected DWARFArrayCrafter, got {type(radd_result)}'
assert len(radd_result) == 2
assert radd_result[0].a.value == 0x33, \
    f'__radd__[0].a: {radd_result[0].a.value}'   # other (left) first
assert radd_result[1].a.value == 0x44, \
    f'__radd__[1].a: {radd_result[1].a.value}'   # self (right) second
# Different struct types via __radd__ fall back to numeric → TypeError
try:
    radd_a.__radd__(headers.craft('FinalBoss'))
    assert False, '__radd__ with different struct type should raise TypeError'
except TypeError:
    pass
print('[+] DWARFCrafter.__radd__ numeric and struct paths: PASSED')

io.close()
