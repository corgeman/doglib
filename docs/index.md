# doglib

`doglib` is my personal extension to the `pwntools` framework-- things that I always wished it had after years of usage. the only required dependency is `pwntools` itself, with some optional dependencies for speed or extra utility.

you can install it like so:
```bash
# install directly
pip install git+https://github.com/corgeman/doglib.git
# or install with rust extensions (recommended if supported)
pip install "doglib[rust] @ git+https://github.com/corgeman/doglib.git"

# or install from local clone
pip install .
# with rust extensions
pip install .[rust]
```

note that `doglib` is currently in beta, and you may see major refactors of modules before an official release happens.

