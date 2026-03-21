import os
import shutil
import subprocess
import tempfile

import pytest

TEST_DIR = os.path.dirname(__file__)
LIBC_DIR = "/home/corgo/pwn/tools/latest_glibc"
TEST_LIBC = os.path.join(LIBC_DIR, "libc6_2.39-0ubuntu8.5_amd64.so")


@pytest.fixture(autouse=True)
def change_to_test_dir(monkeypatch):
    monkeypatch.chdir(TEST_DIR)


@pytest.fixture(scope="session")
def target_pie():
    """Compile the PIE test target (default on modern GCC)."""
    src = os.path.join(TEST_DIR, "target.c")
    out = os.path.join(TEST_DIR, "target_pie")
    subprocess.check_call(["gcc", "-o", out, src, "-pie"])
    yield out
    if os.path.exists(out):
        os.unlink(out)


@pytest.fixture(scope="session")
def target_no_pie():
    """Compile the non-PIE test target."""
    src = os.path.join(TEST_DIR, "target.c")
    out = os.path.join(TEST_DIR, "target_nopie")
    subprocess.check_call(["gcc", "-o", out, src, "-no-pie"])
    yield out
    if os.path.exists(out):
        os.unlink(out)


@pytest.fixture(scope="session")
def target_patched_libc():
    """Compile a non-PIE binary and patch it to use a known libc via pwninit.

    Yields a dict with:
        bin_path:  path to the patched binary
        libc_path: path to the libc used
        build_id:  expected build ID of the libc (hex string)
        work_dir:  temporary directory (cleaned up after tests)
    """
    if not os.path.exists(TEST_LIBC):
        pytest.skip("Test libc not found at %s" % TEST_LIBC)

    work_dir = tempfile.mkdtemp(prefix="dumpelf_libc_test_")
    src = os.path.join(TEST_DIR, "target.c")
    bin_path = os.path.join(work_dir, "target")
    libc_dst = os.path.join(work_dir, "libc.so")

    subprocess.check_call(["gcc", "-o", bin_path, src, "-no-pie"])
    shutil.copy2(TEST_LIBC, libc_dst)

    subprocess.check_call(
        ["pwninit", "--bin", bin_path, "--libc", libc_dst],
        cwd=work_dir,
    )

    patched = os.path.join(work_dir, "target_patched")
    assert os.path.exists(patched), "pwninit did not create target_patched"

    # pwninit sets a relative interpreter (./ld-X.XX.so); fix to absolute
    # so the binary works regardless of CWD.
    ld_candidates = [f for f in os.listdir(work_dir) if f.startswith("ld-")]
    assert ld_candidates, "pwninit did not download a linker"
    ld_abs = os.path.join(work_dir, ld_candidates[0])
    subprocess.check_call([
        "patchelf",
        "--set-interpreter", ld_abs,
        "--set-rpath", work_dir,
        patched,
    ])

    yield {
        "bin_path": patched,
        "libc_path": libc_dst,
        "build_id": "282c2c16e7b6600b0b22ea0c99010d2795752b5f",
        "work_dir": work_dir,
    }

    shutil.rmtree(work_dir, ignore_errors=True)
