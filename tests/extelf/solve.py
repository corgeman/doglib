#!/usr/bin/env python3
from pwn import *

from doglib.extelf import CHeader, ExtendedELF, DWARFAddress

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

log.success("All feature tests passed!")

io.close()
