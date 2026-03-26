# fancy printing
import inspect
import dis
import ast
import linecache

from pwnlib.log import getLogger
log = getLogger("pwnlib.exploit")

def logx(*args, **kwargs):
    """
    Log expressions and values while preserving the caller-side expression text.

    This is similar to writing ``log.info(f"{value=}")``, but it inspects the
    calling frame so you can pass arbitrary expressions instead of formatting
    them yourself.

    .. code-block:: python

        base = elf.address
        logx(base, base + 0x123, libc.sym.system)

    Would print out something like::

        base=0x401000
        base + 291=0x401123
        libc.sym.system=0x7ffff7c58750

    Integers are logged in hex. Other values are logged with ``repr()``. You
    can also pass keyword arguments when you want an explicit label.

    .. code-block:: python

        logx(heap_base, target=ptr, payload=rop.chain())

    If source recovery fails, positional arguments are logged as
    ``<unknown>=...`` instead. Requires Python 3.11+.
    """

    frame = inspect.currentframe().f_back
    _encode = lambda var: (hex if type(var) is int else repr)(var)

    try:
        lasti = frame.f_lasti
        instructions = {inst.offset: inst for inst in dis.get_instructions(frame.f_code)}
        
        while lasti not in instructions or instructions[lasti].opname == "CACHE":
            lasti -= 2
            
        pos = instructions[lasti].positions
        if not pos or not pos.lineno:
            raise RuntimeError("Position data missing. Are you on Python 3.11+?")

        lines = linecache.getlines(frame.f_code.co_filename)
        
        call_text = ""
        for i in range(pos.lineno, pos.end_lineno+1):
            start = pos.col_offset if i == pos.lineno else None
            end = pos.end_col_offset if i == pos.end_lineno else None
            call_text += lines[i - 1][start:end]
            
        tree = ast.parse(call_text)
        var_names = tree.body[0].value.args
        if sum(int(isinstance(name, ast.Starred)) for name in var_names) >= 2:
            raise RuntimeError("Do not use multiple starred expressions. "
                               "Try using kwargs instead.")

        arg_idx = 0
        for i, name in enumerate(var_names):
            str_name = ast.unparse(name)
            if isinstance(name, ast.Starred):
                arg_count = len(args) - len(var_names) + 1
                for j in range(arg_count):
                    log.info("%s[%d]=%s" % (str_name[1:], j, _encode(args[arg_idx + j])))

                arg_idx += arg_count
            else:
                log.info("%s=%s" % (str_name, _encode(args[arg_idx])))
                arg_idx += 1

    except Exception:
        for arg in args:
            log.info("<unknown>=%s" % _encode(arg))
        
    finally:
        del frame
    
    # simple kwargs print
    for name, arg in kwargs.items():
        log.info("%s=%s" % (name, _encode(arg)))


def log_printf(leaks: list | tuple, start_offset=1):
    """
    Convenience function for printf-related challenges when you want a neat list of positional offsets and values

    .. code-block:: python
        leaks = send_printf("%p." * 50).split(".")
        log_printf(leaks)

    Would print out something like::

        [1] 0xdeadbeef
        [2] 0x0
        [3] 0xabcdef
        ...
    
    If your starting offset isn't ``1``, you can specify it as the second arg

    .. code-block:: python

        log_printf(leaks, start_offset=7)
    """
    assert isinstance(leaks, (list, tuple))
    
    # try to convert the output values to integers if possible
    fixed_leaks = []
    for leak in leaks:
        try:
            fixed_leaks.append(int(leak, 0))
        except ValueError:
            fixed_leaks.append(leak)
    
    _encode = lambda var: (hex if type(var) is int else repr)(var)
    for i, val in enumerate(fixed_leaks, start=start_offset):
        log.info("[%d] %s" % (i, _encode(val)))

if __name__ == "__main__":
    from pwnlib.log import install_default_handler
    install_default_handler()
    test = 69
    test2 = "lmfao"
    lst = [6, 7]
    logx(test, test2,
                *lst,
         test + 0x123,
         waow=True)
    
    leaks = "(nil).0x1.0x2.0xdeadbeef".split('.')
    log_printf(leaks)
