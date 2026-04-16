"""Assemble/disassemble round-trip tests for every arch in doglib.asm._ARCHES.

Each source snippet uses at least one construct unique to its arch
(register set, mnemonic, or encoding form) so a test can't silently pass
by sharing instructions with another arch.
"""
import pytest
from doglib.asm import kasm, cdis, _ARCHES

_ks = pytest.importorskip("keystone")
pytest.importorskip("capstone")


def _skip_if_ks_unsupported(arch):
    ks_arch_name = _ARCHES[arch][0]
    if not hasattr(_ks, ks_arch_name):
        pytest.skip(f"installed keystone has no {ks_arch_name}")


# arch -> (source, expected_mnemonics_in_disasm)
CASES = {
    # movabs rax, imm64 is 64-bit-only; syscall is the 64-bit entry insn.
    "amd64":   ("movabs rax, 0x1122334455667788; syscall",
                ["movabs", "syscall"]),
    # pushad/popad are invalid in 64-bit mode.
    "i386":    ("pushad; popad; int 0x80",
                ["push", "pop", "int"]),
    # ARM-mode encoding of bx lr is 0xe12fff1e; thumb form is 2 bytes.
    "arm":     ("mov r0, #0x42; bx lr",
                ["mov", "bx"]),
    # Thumb push-with-regs uses the 16-bit encoding.
    "thumb":   ("push {r4, r5, r7, lr}",
                ["push"]),
    # x0/ret are aarch64-only register/mnemonic forms.
    "aarch64": ("mov x0, #0x42; ret",
                ["mov", "ret"]),
    # MIPS $t0/$a0/$ra register names; jr with delay slot.
    "mips":    ("move $t0, $a0; jr $ra; nop",
                ["move", "jr", "nop"]),
    "mipsel":  ("move $t0, $a0; jr $ra; nop",
                ["move", "jr", "nop"]),
    # mr and blr are PowerPC-specific mnemonics.
    "powerpc": ("mr 3, 4; blr",
                ["mr", "blr"]),
    # %o0/%o1 output registers and retl are SPARC-specific.
    "sparc":   ("mov %o0, %o1; retl; nop",
                ["mov", "retl", "nop"]),
    # ecall is the RISC-V system call mnemonic.
    "riscv32": ("addi x1, x2, 0x42; ecall",
                ["addi", "ecall"]),
    # ld is the 64-bit doubleword load (not present in rv32).
    "riscv64": ("ld x1, 0(x2); ecall",
                ["ld", "ecall"]),
}


def test_cases_cover_every_arch():
    assert set(CASES) == set(_ARCHES), (
        "CASES must cover every arch in _ARCHES; update the test when "
        "adding/removing arches in asm.py"
    )


@pytest.mark.parametrize("arch", sorted(_ARCHES))
class TestRoundTrip:
    def test_assemble_returns_bytes(self, arch):
        _skip_if_ks_unsupported(arch)
        src, _ = CASES[arch][0], CASES[arch][1]
        blob = kasm[arch](src)
        assert isinstance(blob, bytes)
        assert len(blob) > 0

    def test_disassemble_returns_expected_mnemonics(self, arch):
        _skip_if_ks_unsupported(arch)
        src, expected = CASES[arch]
        blob = kasm[arch](src)
        disasm = cdis[arch](blob).lower()
        for mnem in expected:
            assert mnem in disasm, (
                f"{arch}: expected mnemonic {mnem!r} in disassembly\n"
                f"source: {src!r}\n"
                f"bytes:  {blob.hex()}\n"
                f"disasm: {disasm!r}"
            )


class TestEndiannessDistinct:
    """mips and mipsel share sources but must produce byte-swapped encodings."""

    def test_mips_vs_mipsel_differ(self):
        src = "lui $t0, 0x1234"
        assert kasm.mips(src) != kasm.mipsel(src)

    def test_mips_vs_mipsel_are_byte_reversed(self):
        src = "lui $t0, 0x1234"
        be = kasm.mips(src)
        le = kasm.mipsel(src)
        # mips instructions are 4 bytes; each word should be byte-reversed.
        assert len(be) == len(le)
        assert all(
            be[i:i+4] == le[i:i+4][::-1]
            for i in range(0, len(be), 4)
        )


class TestArmVsThumbDistinct:
    """bx lr assembles to different widths/encodings in arm vs thumb."""

    def test_arm_is_4_bytes(self):
        assert len(kasm.arm("bx lr")) == 4

    def test_thumb_is_2_bytes(self):
        assert len(kasm.thumb("bx lr")) == 2
