"""
Download, cache, and extract Ubuntu .ddeb debug-symbol packages.

Usage:
    from tests._ddeb_fetcher import get_ddeb_so

    path = get_ddeb_so("libsqlite3-0", "libsqlite3-0-dbgsym", "sqlite3", "libsqlite3.so.0*")
    if path is None:
        pytest.skip("could not obtain libsqlite3-0-dbgsym")

The cache lives at tests/_cache/ddebs/ (gitignored).
Set SKIP_NETWORK_TESTS=1 to bypass all downloads.
"""
import fnmatch
import hashlib
import io
import os
import re
import shutil
import subprocess
import tarfile
import urllib.error
import urllib.parse
import urllib.request

_TESTS_DIR = os.path.dirname(__file__)
_CACHE_DIR = os.path.join(_TESTS_DIR, "_cache", "ddebs")
_DDEBS_BASE = "http://ddebs.ubuntu.com/pool/main"


# ── ar / tar extraction ───────────────────────────────────────────────────────

def _iter_ar(data: bytes):
    """Yield (name, content) from a Debian ``ar`` archive."""
    import struct as _struct
    if data[:8] != b"!<arch>\n":
        return
    f = io.BytesIO(data)
    f.seek(8)
    while True:
        hdr = f.read(60)
        if len(hdr) < 60:
            break
        name, _, _, _, _, size_s, _, _ = _struct.unpack("16s12s6s6s8s10sbb", hdr)
        name = name.decode().rstrip().rstrip("/")
        size = int(size_s.decode().rstrip())
        content = f.read(size)
        if size & 1:
            f.seek(1, 1)
        if name in ("/", "//"):
            continue
        yield name, content


def _extract_matching(deb_data: bytes, pattern: str, out_path: str) -> str | None:
    """
    Extract the first entry whose basename matches ``pattern`` (fnmatch) from a
    .deb / .ddeb archive and write it to ``out_path``.  Returns ``out_path`` on
    success, ``None`` if nothing matched.
    """
    tar_name = tar_data = None
    for name, content in _iter_ar(deb_data):
        if name.startswith("data.tar"):
            tar_name, tar_data = name, content
            break
    if tar_data is None:
        return None

    if tar_name.endswith((".zst", ".zstd")):
        import zstandard
        tar_data = zstandard.ZstdDecompressor().decompress(
            tar_data, max_output_size=256 * 1024 * 1024
        )

    with tarfile.open(fileobj=io.BytesIO(tar_data)) as tf:
        for member in tf.getmembers():
            if not member.isfile():
                continue
            if fnmatch.fnmatch(os.path.basename(member.name), pattern):
                fobj = tf.extractfile(member)
                if fobj is None:
                    continue
                with open(out_path, "wb") as out:
                    out.write(fobj.read())
                return out_path
    return None


# ── dpkg helpers ──────────────────────────────────────────────────────────────

def _dpkg_version(pkg: str) -> str | None:
    """Return the installed version of ``pkg``, or None."""
    if not shutil.which("dpkg"):
        return None
    try:
        r = subprocess.run(
            ["dpkg", "-s", pkg], capture_output=True, text=True, timeout=5
        )
        for line in r.stdout.splitlines():
            if line.startswith("Version: "):
                return line[9:].strip()
    except Exception:
        pass
    return None


def _dpkg_arch() -> str:
    """Return the dpkg host architecture, e.g. ``'amd64'``."""
    try:
        r = subprocess.run(
            ["dpkg", "--print-architecture"],
            capture_output=True, text=True, timeout=5,
        )
        return r.stdout.strip() or "amd64"
    except Exception:
        return "amd64"


def _gcc_major() -> str | None:
    """Return the major version of the system gcc (e.g. ``'14'``)."""
    try:
        r = subprocess.run(["gcc", "--version"], capture_output=True, text=True)
        m = re.search(r"(\d+)\.\d+\.\d+", r.stdout)
        if m:
            return m.group(1)
    except Exception:
        pass
    return None


# ── main API ──────────────────────────────────────────────────────────────────

def get_ddeb_so(
    installed_pkg: str,
    ddeb_name: str,
    src_pkg: str,
    so_pattern: str,
    sha256: str | None = None,
) -> str | None:
    """
    Ensure a shared library from a Ubuntu ddeb is available locally.

    Looks up the currently-installed version of ``installed_pkg``, constructs a
    ``ddebs.ubuntu.com`` URL, downloads once to the test cache, extracts the
    matching ``.so`` file, and returns its path.

    Returns ``None`` (never raises) if:
    - ``SKIP_NETWORK_TESTS`` env var is non-empty / non-zero
    - ``dpkg`` is not available (non-Debian system)
    - ``installed_pkg`` is not installed
    - the download fails (404, timeout, etc.)
    - the extracted file is not found inside the ddeb
    - ``sha256`` is provided and does not match

    Args:
        installed_pkg: apt package to query for its installed version
                       (e.g. ``"libsqlite3-0"``).
        ddeb_name:     debug-symbol package name
                       (e.g. ``"libsqlite3-0-dbgsym"``).
        src_pkg:       Debian source package, used for the pool URL path
                       (e.g. ``"sqlite3"``).
        so_pattern:    fnmatch glob for the .so to extract from the ddeb
                       (e.g. ``"libsqlite3.so.0*"``).
        sha256:        expected hex digest of the downloaded .ddeb; if given and
                       mismatched the result is discarded and ``None`` returned.
    """
    skip_env = os.environ.get("SKIP_NETWORK_TESTS", "")
    if skip_env and skip_env not in ("0", "false", "no"):
        return None

    version = _dpkg_version(installed_pkg)
    if version is None:
        return None

    arch = _dpkg_arch()
    os.makedirs(_CACHE_DIR, exist_ok=True)

    # Ubuntu ddeb packages contain detached debug ELFs under
    # /usr/lib/debug/.build-id/xx/yyyy.debug — store with .debug extension.
    safe_ver = version.replace(":", "_").replace("/", "_")
    cache_so = os.path.join(_CACHE_DIR, f"{ddeb_name}_{safe_ver}_{arch}.debug")
    if os.path.exists(cache_so):
        return cache_so

    initial = src_pkg[0]
    ver_encoded = urllib.parse.quote(version, safe="")
    url = (
        f"{_DDEBS_BASE}/{initial}/{src_pkg}/"
        f"{ddeb_name}_{ver_encoded}_{arch}.ddeb"
    )

    try:
        req = urllib.request.Request(url, headers={"User-Agent": "doglib-tests/1.0"})
        with urllib.request.urlopen(req, timeout=60) as resp:
            deb_data = resp.read()
    except (urllib.error.URLError, OSError):
        return None

    if sha256 is not None:
        if hashlib.sha256(deb_data).hexdigest() != sha256:
            return None

    return _extract_matching(deb_data, so_pattern, cache_so)


# ── curated package list ──────────────────────────────────────────────────────

def _libstdc_src_pkg() -> str:
    """Return the source package name for libstdc++6 on this machine."""
    ver = _gcc_major()
    return f"gcc-{ver}" if ver else "gcc"


#: Entries for the standard ddeb parity suite.
#: Each tuple: (label, installed_pkg, ddeb_name, src_pkg_fn, so_pattern)
#: ``src_pkg_fn`` may be a callable (evaluated at runtime) or a plain string.
DDEB_SUITE = [
    # Ubuntu ddeb packages contain detached debug ELFs (*.debug) under
    # /usr/lib/debug/.build-id/xx/yyyy.debug — we match all *.debug entries.
    ("sqlite3",   "libsqlite3-0",   "libsqlite3-0-dbgsym",   "sqlite3",        "*.debug"),
    ("zlib",      "zlib1g",          "zlib1g-dbgsym",          "zlib",           "*.debug"),
    # libssl3 (Ubuntu 22.04) / libssl3t64 (Ubuntu 24.04) — try both
    ("ssl",       "libssl3",         "libssl3-dbgsym",         "openssl",        "*.debug"),
    ("ssl-t64",   "libssl3t64",      "libssl3t64-dbgsym",      "openssl",        "*.debug"),
    ("libstdc++", "libstdc++6",      "libstdc++6-dbgsym",      _libstdc_src_pkg, "*.debug"),
]


def collect_ddeb_suite() -> list[tuple[str, str]]:
    """
    Return a list of ``(label, path)`` pairs for all packages in DDEB_SUITE
    that could be downloaded successfully.  Packages that fail are silently
    omitted.
    """
    results = []
    for entry in DDEB_SUITE:
        label, installed, ddeb, src_fn, pattern = entry
        src = src_fn() if callable(src_fn) else src_fn
        path = get_ddeb_so(installed, ddeb, src, pattern)
        if path is not None:
            results.append((label, path))
    return results
