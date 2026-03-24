# fancy printing
import inspect
import dis
import ast
import linecache

from pwnlib.log import getLogger
log = getLogger("pwnlib.exploit")

# requires py3.11+
# equivalent to info(f"{var=:#x}")
# but 'var' is preserved through this function
def infoleak(var: int):
    frame = inspect.currentframe().f_back
    
    try:
        lasti = frame.f_lasti
        instructions = {inst.offset: inst for inst in dis.get_instructions(frame.f_code)}
        
        while lasti not in instructions or instructions[lasti].opname == "CACHE":
            lasti -= 2
            
        pos = instructions[lasti].positions
        if not pos or not pos.lineno:
            raise RuntimeError("Position data missing. Are you on Python 3.11+?")

        lines = linecache.getlines(frame.f_code.co_filename)

        if pos.lineno == pos.end_lineno: # single-line function call
            call_text = lines[pos.lineno - 1][pos.col_offset:pos.end_col_offset]
        else: # multi-line function call
            extracted = [lines[pos.lineno - 1][pos.col_offset:]]
            for i in range(pos.lineno, pos.end_lineno - 1):
                extracted.append(lines[i])
            extracted.append(lines[pos.end_lineno - 1][:pos.end_col_offset])
            call_text = "".join(extracted)
            
        tree = ast.parse(call_text)
        call_node = tree.body[0].value
        var_name = ast.unparse(call_node.args[0])
        
        log.info(f"{var_name}={var:#x}")
        
    except Exception:
        log.info(f"<unknown>={var:#x}")
        
    finally:
        del frame