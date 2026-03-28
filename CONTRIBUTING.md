# contributing

## layout
`tests/`: pytest tests, make some if you think your code is complex (or don't i don't care)  
`src/dog`: top level `dog` module, simply imports everything from `doglib`  
`src/doglib`: where all the important python code goes  
`src/doglib_rs`: doglib features in rust. inside `crates` should be each 'module'  
`src/doglib/data`: important files for modules. always separate by folder.  
`src/doglib/commandline`: cli tooling  
`docs/`: documentation for complex modules

## adding code
when adding a new feature, follow this:
- try to find a matching module for your feature and put it in there
- if you can't, add it to `misc.py`
- if it's a new big feature (say, >80 lines), make it its own script. 
- if it's a very big feature (or makes an existing script very big), make it its own folder and split it into submodules if possible


for any new functions you make, ensure you have it added to `__all__` at the bottom of the module  
and if it's a new module, make sure you import it in `dog/__init__.py`  

## rules
ideally this should never use any external libraries other than what `pwntools` already uses.  
if you need an external library, try to:
- extract the important features of it (if it's not enormous)
- load the library at function run-time, so it's only required if someone tries to use it (see how `doglib/asm.py` imports `keystone`, which is not part of pwntools)
- use a fallback (see how `doglib/pow.py` selects the fastest solver library available)
- worst case, do not add it to `dog/__init__.py` and require explicit import through `doglib`
you should never write `from pwn import *`, please import what's necessary from `pwnlib` instead