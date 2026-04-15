"""
Integration tests: solve CTF challenge binaries using doglib.orc.
These tests exercise the full stack (DWARF parsing -> craft -> send) on
real compiled binaries. Fixtures and cwd setup live in conftest.py.

Run from the project root:
    pytest tests/orc/test_challenge.py
"""
import pytest
from pwnlib.util.packing import p64


def test_challenge_solve(headers, chal_elf, chal_pwn_elf, challenge_gcc):
    """Send correctly crafted structs through every level of the challenge."""
    from pwnlib.tubes.process import process
    io = process(f"./{challenge_gcc}")
    try:
        # Level 1: Padding & Basics
        basic = headers.craft('Basic')
        basic.a = ord('X')
        basic.b = 0x1337
        basic.c = 0x42
        io.sendafter(b"Basic\n", bytes(basic))

        # Level 2: Arrays & Pointers
        arr_fun = headers.craft('ArrayFun')
        arr_fun.arr[0] = 10
        arr_fun.arr[4] = 50
        arr_fun.ptr = 0xdeadbeef
        io.sendafter(b"ArrayFun\n", bytes(arr_fun))

        # Level 3: Unions & Anonymous Structs
        union_madness = headers.craft('UnionMadness')
        union_madness.type = 1
        union_madness.data.coords.x = 0x11223344
        union_madness.data.coords.y = 0x55667788
        io.sendafter(b"UnionMadness\n", bytes(union_madness))

        # Level 4: Deep Nesting & Array Bytes
        boss = headers.craft('BossFight')
        boss.b[1].a = ord('Z')
        boss.b[1].b = 999
        boss.u.data.raw = b"AAAAAAAW"
        io.sendafter(b"BossFight\n", bytes(boss))

        # Level 5: Truncation & Overflows
        edge = headers.craft('EdgeCases')
        edge.small_int = 0xdeadbeef
        edge.small_buf = b"AAAA\x00TRASH_DATA_THAT_GETS_DROPPED"
        edge.big_int = -1
        io.sendafter(b"EdgeCases\n", bytes(edge))

        # Level 6: DWARF Array Strides & Offset Math
        target_addr = int(chal_pwn_elf.sym_obj['target_sym'].arr[2].ptr)
        io.sendafter(b"(8 bytes)\n", p64(target_addr))

        # Level 7: Enums, Signed Values, Multi-Dimensional Arrays & Floats
        final = headers.craft('FinalBoss')
        final.current_state = -1   # CRASHED
        final.negative_val = -1337
        final.matrix[1][2] = 9999
        final.max_hp = 1000.5
        final.current_hp = 1337.75
        io.sendafter(b"FinalBoss\n", bytes(final))

        # Level 8: Multi-Dimensional Array Proper Indexing (2D + 3D)
        md = headers.craft('MultiDimTest')
        md.grid[1][2] = 42
        md.grid[2][3] = 99
        md.cube[1][0][2] = ord('Q')
        md.cube[0][2][3] = ord('Z')
        io.sendafter(b"MultiDimTest\n", bytes(md))

        # Level 9: Anonymous Struct/Union Members
        am = headers.craft('AnonMember')
        am.type = 5
        am.as_int = 0xCAFE
        am.x = 100
        am.y = 200
        io.sendafter(b"AnonMember\n", bytes(am))

        # Level 10: Sub-Struct Assignment & Value Readback
        hdr = headers.craft('Basic')
        hdr.a = ord('A')
        hdr.b = 1234
        hdr.c = 42
        wrapper = headers.craft('Wrapper')
        wrapper.header = hdr
        wrapper.payload = 0xBEEF
        assert wrapper.payload.value == 0xBEEF
        assert wrapper.header.a.value == ord('A')
        assert wrapper.header.b.value == 1234
        io.sendafter(b"Wrapper\n", bytes(wrapper))

        io.wait_for_close()
    finally:
        io.close()


def test_cpp_challenge_solve(change_to_test_dir, challenge_gpp):
    """End-to-end solve of the C++ challenge binary using ORC."""
    from doglib.orc import ORC
    from pwnlib.elf.elf import ELF
    from pwnlib.tubes.process import process as pwnprocess
    import pwnlib.context
    pwnlib.context.context.log_level = 'error'

    orc = ORC(f"./{challenge_gpp}")
    pwn_elf = ELF(f"./{challenge_gpp}", checksec=False)
    p = pwnprocess(f"./{challenge_gpp}")

    # Level 1: Simple class
    coords = orc.craft('Coords')
    coords.x = 10
    coords.y = 20
    coords.z = 30
    p.readuntil(b'Level 1:')
    p.readline()
    p.send(bytes(coords))
    assert b'passed' in p.readline()

    # Level 2: Nested class
    entity = orc.craft('Entity')
    entity.id = 42
    entity.pos.x = 100
    entity.pos.y = 200
    entity.pos.z = 300
    entity.name = b'hero\x00'
    p.readuntil(b'Level 2:')
    p.readline()
    p.send(bytes(entity))
    assert b'passed' in p.readline()

    # Level 3: Inheritance
    player = orc.craft('Player')
    player.id = 1
    player.pos.x = 50
    player.health = 100
    player.weapon.damage = 25
    player.weapon.durability = 75
    p.readuntil(b'Level 3:')
    p.readline()
    p.send(bytes(player))
    assert b'passed' in p.readline()

    # Level 4: Vtable hijack
    win_addr = pwn_elf.symbols['_Z3winv']
    fake_vt = pwn_elf.symbols['fake_vtable']
    monster = orc.craft('Monster')
    monster['_vptr.Monster'] = fake_vt
    monster.hp = 0x1337
    p.readuntil(b'Level 4:')
    p.readline()
    p.send(p64(win_addr))
    p.send(bytes(monster))
    assert b'passed' in p.readline()

    p.close()
