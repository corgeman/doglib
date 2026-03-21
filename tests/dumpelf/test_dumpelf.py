"""
Integration tests for doglib.dumpelf.

Strategy: compile a small C program, launch it, and use /proc/pid/mem
as the arbitrary-read primitive.  This avoids needing networking while
still exercising the full dump+reconstruct pipeline.
"""
import os
import stat
import struct
import subprocess
import tempfile

import pytest
from pwn import ELF, context, process

from doglib.dumpelf import DumpELF
from doglib.dumpelf._libc import find_build_id, find_version_string
from doglib.dumpelf._reconstruct import (
    _ElfHeader,
    _Phdr,
    reconstruct_elf,
    PT_LOAD,
)

context.log_level = "info"


# ── Helpers ─────────────────────────────────────────────────────────

def _proc_mem_leak(pid):
    """Return a leak function that reads via /proc/<pid>/mem."""
    fd = os.open(f"/proc/{pid}/mem", os.O_RDONLY)

    def leak(addr):
        try:
            os.lseek(fd, addr, os.SEEK_SET)
            return os.read(fd, 8)
        except OSError:
            return None

    leak._fd = fd
    return leak


def _launch_and_get_leak(binary_path):
    """Launch the test target and return (process, leak_func, entry_point)."""
    elf = ELF(binary_path, checksec=False)
    p = process(binary_path)
    line = p.recvline()
    assert line.startswith(b"PID:")
    pid = int(line.split(b":")[1])
    leak = _proc_mem_leak(pid)
    return p, leak, elf


# ── Tests ───────────────────────────────────────────────────────────

class TestDumpELFNoPIE:
    """Test with a non-PIE binary (ET_EXEC)."""

    def test_find_base(self, target_no_pie):
        p, leak, elf = _launch_and_get_leak(target_no_pie)
        try:
            d = DumpELF(leak, elf.address + 0x100)
            assert d.base == elf.address
            assert d.elfclass == 64
            assert d.elftype == "EXEC"
            assert d.is_pie is False
        finally:
            p.send(b"q\n")
            p.close()
            os.close(leak._fd)

    def test_dump_and_reconstruct(self, target_no_pie):
        p, leak, elf = _launch_and_get_leak(target_no_pie)
        try:
            d = DumpELF(leak, elf.address + 0x100)

            with tempfile.NamedTemporaryFile(suffix=".elf", delete=False) as f:
                tmp_path = f.name

            elf_bytes = d.dump(tmp_path)

            assert elf_bytes[:4] == b"\x7fELF"
            assert os.path.exists(tmp_path)
            assert os.path.getsize(tmp_path) > 0

            # Verify the reconstructed ELF can be loaded by pwntools
            with context.local(log_level="error"):
                reconstructed = ELF(tmp_path, checksec=False)

            assert reconstructed.entry > 0
            assert len(reconstructed.sections) > 2

            os.unlink(tmp_path)
        finally:
            p.send(b"q\n")
            p.close()
            os.close(leak._fd)

    def test_segments_have_data(self, target_no_pie):
        p, leak, elf = _launch_and_get_leak(target_no_pie)
        try:
            d = DumpELF(leak, elf.address + 0x100)
            segs = d.segments
            assert len(segs) >= 2

            # First segment should contain the ELF header
            first_addr = min(segs.keys())
            assert segs[first_addr][:4] == b"\x7fELF"
        finally:
            p.send(b"q\n")
            p.close()
            os.close(leak._fd)


class TestDumpELFPIE:
    """Test with a PIE binary (ET_DYN)."""

    def test_find_base_pie(self, target_pie):
        p, leak, elf = _launch_and_get_leak(target_pie)
        try:
            # For PIE, the runtime base differs from the ELF's load address.
            # We get a valid pointer from /proc/pid/maps.
            with open(f"/proc/{p.pid}/maps") as f:
                first_line = f.readline()
            runtime_base = int(first_line.split("-")[0], 16)

            d = DumpELF(leak, runtime_base + 0x100)
            assert d.base == runtime_base
            assert d.elfclass == 64
            assert d.elftype == "DYN"
            assert d.is_pie is True
        finally:
            p.send(b"q\n")
            p.close()
            os.close(leak._fd)

    def test_dump_pie(self, target_pie):
        p, leak, elf = _launch_and_get_leak(target_pie)
        try:
            with open(f"/proc/{p.pid}/maps") as f:
                first_line = f.readline()
            runtime_base = int(first_line.split("-")[0], 16)

            d = DumpELF(leak, runtime_base + 0x100)

            with tempfile.NamedTemporaryFile(suffix=".elf", delete=False) as f:
                tmp_path = f.name

            elf_bytes = d.dump(tmp_path)
            assert elf_bytes[:4] == b"\x7fELF"

            with context.local(log_level="error"):
                reconstructed = ELF(tmp_path, checksec=False)

            assert reconstructed.entry > 0

            os.unlink(tmp_path)
        finally:
            p.send(b"q\n")
            p.close()
            os.close(leak._fd)


class TestReconstruct:
    """Unit tests for the reconstruction module (no remote needed)."""

    def test_elfheader_parse(self, target_no_pie):
        with open(target_no_pie, "rb") as f:
            data = f.read()
        ehdr = _ElfHeader(data)
        assert ehdr.elfclass in (32, 64)
        assert ehdr.e_entry > 0
        assert ehdr.e_phnum > 0

    def test_reconstruct_from_file_segments(self, target_no_pie):
        """Simulate reconstruction using segments extracted from a real ELF file."""
        with open(target_no_pie, "rb") as f:
            file_data = f.read()

        ehdr = _ElfHeader(file_data)
        phdrs = []
        for i in range(ehdr.e_phnum):
            off = ehdr.e_phoff + i * ehdr.e_phentsize
            phdrs.append(_Phdr.from_bytes(file_data[off:off + ehdr.e_phentsize], ehdr.is64))

        # Build segments dict as DumpELF would produce
        segments = {}
        for p in phdrs:
            if p.p_type == PT_LOAD and p.p_filesz > 0:
                segments[p.p_vaddr] = file_data[p.p_offset:p.p_offset + p.p_filesz]

        base = min(segments.keys())
        result = reconstruct_elf(segments, base, ehdr.elfclass)

        assert result[:4] == b"\x7fELF"

        # Should be loadable
        with tempfile.NamedTemporaryFile(suffix=".elf", delete=False) as f:
            f.write(result)
            tmp = f.name

        with context.local(log_level="error"):
            rec = ELF(tmp, checksec=False)

        assert rec.entry == ehdr.e_entry
        assert len(rec.sections) > 2
        os.unlink(tmp)


class TestDumpedBinaryRuns:
    """Verify the reconstructed ELF is actually executable."""

    def test_dumped_nopie_runs(self, target_no_pie):
        """Dump a non-PIE binary from memory, write it, run it with --confirm."""
        p, leak, elf = _launch_and_get_leak(target_no_pie)
        try:
            d = DumpELF(leak, elf.address + 0x100)

            with tempfile.NamedTemporaryFile(suffix=".elf", delete=False) as f:
                tmp_path = f.name

            d.dump(tmp_path)

            # Make executable
            os.chmod(tmp_path, os.stat(tmp_path).st_mode | stat.S_IEXEC)

            # Run the reconstructed binary with --confirm
            result = subprocess.run(
                [tmp_path, "--confirm"],
                capture_output=True, timeout=5,
            )
            assert b"CONFIRMED WORKS" in result.stdout, (
                f"Expected 'CONFIRMED WORKS' in stdout, got: {result.stdout!r}\n"
                f"stderr: {result.stderr!r}\nreturncode: {result.returncode}"
            )

            os.unlink(tmp_path)
        finally:
            p.send(b"q\n")
            p.close()
            os.close(leak._fd)


class TestLibcIdentification:
    """Test remote libc identification (build ID, version string, link map)."""

    def test_version_string_from_file(self):
        """Unit test: find_version_string on a known libc file."""
        libc_path = "/home/corgo/pwn/tools/latest_glibc/libc6_2.39-0ubuntu8.5_amd64.so"
        if not os.path.exists(libc_path):
            pytest.skip("test libc not available")

        with open(libc_path, "rb") as f:
            data = f.read()

        result = find_version_string(data)
        assert result is not None, "version string not found in libc"

        version, distro = result
        assert "2.39" in version
        assert distro == "ubuntu"

    def test_build_id_from_leak(self, target_patched_libc):
        """Extract the libc build ID via a /proc/pid/mem leak primitive."""
        info = target_patched_libc
        p = process(info["bin_path"])
        try:
            line = p.recvline()
            assert line.startswith(b"PID:")
            pid = int(line.split(b":")[1])
            leak = _proc_mem_leak(pid)

            # Find libc base from /proc/pid/maps
            libc_base = None
            with open(f"/proc/{pid}/maps") as f:
                for map_line in f:
                    if "libc.so" in map_line and "r-" in map_line:
                        libc_base = int(map_line.split("-")[0], 16)
                        break
            assert libc_base is not None, "could not find libc in /proc/pid/maps"

            from pwnlib.memleak import MemLeak
            ml = MemLeak(leak)
            build_id = find_build_id(ml, libc_base)
            assert build_id is not None, "build ID not found via leak"
            assert build_id == info["build_id"], (
                f"build ID mismatch: got {build_id}, expected {info['build_id']}"
            )

            os.close(leak._fd)
        finally:
            p.send(b"q\n")
            p.close()

    def test_bases_contains_libc(self, target_patched_libc):
        """DumpELF.bases should list libc when running a patched binary."""
        info = target_patched_libc
        p = process(info["bin_path"])
        try:
            line = p.recvline()
            assert line.startswith(b"PID:")
            pid = int(line.split(b":")[1])
            leak = _proc_mem_leak(pid)

            # Get the binary's base from /proc/pid/maps (first entry)
            with open(f"/proc/{pid}/maps") as f:
                first_line = f.readline()
            bin_base = int(first_line.split("-")[0], 16)

            d = DumpELF(leak, bin_base + 0x100)
            bases = d.bases
            assert len(bases) > 0, "link map is empty"

            libc_found = any(b"libc" in name for name in bases)
            assert libc_found, f"libc not found in bases: {list(bases.keys())}"

            os.close(leak._fd)
        finally:
            p.send(b"q\n")
            p.close()
