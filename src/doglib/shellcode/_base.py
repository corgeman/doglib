from collections.abc import Iterator
from importlib.resources import files


class ShellcodeSet:
    """A lazily-loaded collection of shellcode blobs keyed by architecture.

    Files are resolved from ``doglib.data/shellcode/<subdir>/<arch>`` using
    :mod:`importlib.resources`, so the blobs are always found correctly whether
    the package is installed as a wheel or run from source.

    Attribute access returns raw bytes for the named arch::

        minshell.amd64            # bytes
        minshell.for_context()    # uses pwntools context.arch
        minshell.arches           # ['aarch64', 'amd64', ...]

    Adding a new shellcode set is two steps:

    1. Place arch-named blob files into ``src/doglib/data/shellcode/<name>/``.
    2. Instantiate in ``src/doglib/shellcode/__init__.py``::

           <name> = ShellcodeSet("<name>")
    """

    def __init__(self, subdir: str) -> None:
        self._subdir = subdir
        self._cache: dict[str, bytes] = {}

    def _data_root(self):
        return files("doglib.data").joinpath("shellcode").joinpath(self._subdir)

    def _load(self, arch: str) -> bytes:
        if arch not in self._cache:
            resource = self._data_root().joinpath(arch)
            try:
                self._cache[arch] = resource.read_bytes()
            except (FileNotFoundError, TypeError):
                raise AttributeError(
                    f"No shellcode for arch {arch!r} in {self._subdir!r}. "
                    f"Available: {self.arches}"
                )
        return self._cache[arch]

    @property
    def arches(self) -> list[str]:
        """Return the list of available architecture names."""
        return sorted(p.name for p in self._data_root().iterdir())

    def __getattr__(self, arch: str) -> bytes:
        if arch.startswith("_"):
            raise AttributeError(arch)
        return self._load(arch)

    def __iter__(self) -> Iterator[tuple[str, bytes]]:
        """Yield ``(arch, shellcode_bytes)`` for every available arch."""
        for arch in self.arches:
            yield arch, self._load(arch)

    def for_context(self) -> bytes:
        """Return shellcode matching the current pwntools ``context.arch``.

        Raises :exc:`AttributeError` if no blob exists for the current arch.
        """
        from pwnlib.context import context

        arch = context.arch
        try:
            return self._load(arch)
        except AttributeError:
            raise AttributeError(
                f"No shellcode for pwntools arch {arch!r}. Available: {self.arches}"
            )

    def __repr__(self) -> str:
        return f"ShellcodeSet({self._subdir!r}, arches={self.arches})"
