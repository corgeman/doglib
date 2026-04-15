"""
Shared pytest fixtures for the orc test suite.

All tests run with `tests/orc/` as the working directory so that relative
paths like `"./challenge.challenge.elf"` and `"complex_structs.h"` resolve
correctly.

Challenge binaries are compiled at test-session start. Tests that require a
specific compiler skip automatically if that compiler is not on PATH or
compilation fails.
"""
import os
import shutil
import subprocess

import pytest
from pathlib import Path

from pwnlib.elf.elf import ELF
from doglib.orc import ORCHeader, ORC
import doglib._hijack  # patches sym_obj, resolve_field, orc onto ELF

TEST_DIR = Path(__file__).parent


@pytest.fixture(scope="session", autouse=True)
def change_to_test_dir():
    """Change cwd to the test directory for the whole session."""
    original = os.getcwd()
    os.chdir(TEST_DIR)
    yield
    os.chdir(original)


def _compile(cmd, binary_name):
    """
    Run a compile command. Returns the output path on success.
    Calls pytest.skip() if the compiler is missing or compilation fails.
    """
    compiler = cmd[0]
    if not shutil.which(compiler):
        pytest.skip(f"compiler '{compiler}' not found on PATH")
    result = subprocess.run(cmd, capture_output=True, text=True)
    if result.returncode != 0:
        pytest.skip(f"failed to compile {binary_name}:\n{result.stderr}")
    return binary_name


@pytest.fixture(scope="session")
def challenge_gcc(change_to_test_dir):
    """Compile challenge.c with gcc. Skips if gcc is unavailable."""
    return _compile(
        ["gcc", "challenge.c", "-o", "challenge.challenge.elf", "-g", "-no-pie"],
        "challenge.challenge.elf",
    )


@pytest.fixture(scope="session")
def challenge_gpp(change_to_test_dir):
    """Compile challenge_cpp.cpp with g++. Skips if g++ is unavailable."""
    return _compile(
        [
            "g++",
            "challenge_cpp.cpp",
            "-o",
            "challenge_cpp.challenge.elf",
            "-g",
            "-no-pie",
            "-fno-stack-protector",
        ],
        "challenge_cpp.challenge.elf",
    )


@pytest.fixture(scope="session")
def challenge_clang(change_to_test_dir):
    """Compile challenge.c with clang. Skips if clang is unavailable."""
    return _compile(
        ["clang", "challenge.c", "-o", "challenge_clang.challenge.elf", "-g", "-no-pie"],
        "challenge_clang.challenge.elf",
    )


@pytest.fixture(scope="session")
def headers(change_to_test_dir):
    """ORCHeader loaded from complex_structs.h (compiled once per session)."""
    return ORCHeader("complex_structs.h")


@pytest.fixture(scope="session")
def chal_elf(challenge_gcc):
    """ORC for the compiled challenge binary (DWARF only)."""
    return ORC(f"./{challenge_gcc}")


@pytest.fixture(scope="session")
def chal_pwn_elf(challenge_gcc):
    """Pwntools ELF for the challenge binary (has symbols + orc bridge)."""
    return ELF(f"./{challenge_gcc}", checksec=False)
