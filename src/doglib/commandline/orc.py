"""dog orc — DWARF-powered C type introspection from the shell."""

import argparse
import fnmatch
import sys


def register(subparsers) -> None:
    p = subparsers.add_parser(
        "orc",
        help="Inspect C types from ELF debuginfo, headers, or built-in stdlib",
        description=(
            "Inspect C types from DWARF info. Source can be an ELF binary "
            "(-f ELF), a C header (-f file.h), inline C source (-c '...'), "
            "or omitted to use the bundled stdlib types (CTypes)."
        ),
    )
    sub = p.add_subparsers(dest="orc_cmd")

    source_parent = argparse.ArgumentParser(add_help=False)
    src_grp = source_parent.add_mutually_exclusive_group()
    src_grp.add_argument(
        "-f", "--from", dest="src_from", metavar="PATH",
        help="ELF binary or C header file (auto-detected by ELF magic).",
    )
    src_grp.add_argument(
        "-c", "--code", dest="src_code", metavar="SRC",
        help="Inline C source. Pass '-' to read from stdin.",
    )
    source_parent.add_argument(
        "-b", "--bits", type=int, choices=(32, 64), default=None,
        help="Target bits (32 or 64). Selects C32/C64 builtin if no source.",
    )
    source_parent.add_argument(
        "-I", action="append", dest="includes", metavar="DIR", default=[],
        help="Header include dir (repeatable). Used with -f HEADER.",
    )

    d = sub.add_parser(
        "describe", parents=[source_parent],
        help="Pretty-print struct/union layout",
        description="Print a struct/union's memory layout as a table. "
                    "With --sym, resolve a global's type from DWARF and "
                    "describe that, prefixed with the symbol's address.",
    )
    d.add_argument("name", help="Type name (or symbol name with --sym).")
    d.add_argument("-s", "--sym", action="store_true",
                   help="Treat NAME as an ELF global symbol; describe its type.")
    d.set_defaults(func=_safe(_describe))

    s = sub.add_parser(
        "sizeof", parents=[source_parent],
        help="Print byte size of a type (or symbol's type)",
    )
    s.add_argument("name")
    s.add_argument("-s", "--sym", action="store_true",
                   help="Treat NAME as an ELF global symbol.")
    s.set_defaults(func=_safe(_sizeof))

    o = sub.add_parser(
        "offsetof", parents=[source_parent],
        help="Print byte offset of a struct field",
        description="Accepts 'Type.field' (single arg). With --sym, the leading "
                    "name is treated as a global symbol and the absolute address "
                    "(symbol + offset) is also printed.",
    )
    o.add_argument("path", metavar="PATH",
                   help="Either 'Type.field' or 'sym.field' with --sym.")
    o.add_argument("-s", "--sym", action="store_true",
                   help="Resolve leading name as an ELF symbol.")
    o.set_defaults(func=_safe(_offsetof))

    fa = sub.add_parser(
        "field_at", parents=[source_parent],
        help="Reverse offsetof: which field lives at OFFSET?",
        description="Print the field path at OFFSET in TYPE. With --sym, "
                    "TYPE is treated as a global symbol — useful for decoding "
                    "GDB-style displacements like 'main_arena+1280'.",
    )
    fa.add_argument("name", help="Type name (or symbol name with --sym).")
    fa.add_argument("offset", help="Byte offset (decimal or 0x...)")
    fa.add_argument("-s", "--sym", action="store_true",
                    help="Treat NAME as an ELF global symbol.")
    fa.set_defaults(func=_safe(_field_at))

    rt = sub.add_parser(
        "resolve_type", parents=[source_parent],
        help="Resolve a typedef to its underlying type",
    )
    rt.add_argument("name")
    rt.set_defaults(func=_safe(_resolve_type))

    e = sub.add_parser(
        "enum", parents=[source_parent],
        help="List enum constants",
    )
    e.add_argument("name")
    e.set_defaults(func=_safe(_enum))

    co = sub.add_parser(
        "containerof", parents=[source_parent],
        help="Compute base address from a member pointer",
        description="Linux container_of(): given 'Type.field' and a member "
                    "address, print the base address of the enclosing struct.",
    )
    co.add_argument("path", metavar="PATH", help="'Type.field'")
    co.add_argument("addr", metavar="ADDR", help="Address (decimal or 0x...).")
    co.set_defaults(func=_safe(_containerof))

    t = sub.add_parser(
        "types",
        help="List type names from an ELF, header, or built-in CTypes",
        description="List C type names. SOURCE is an ELF binary or header file "
                    "(auto-detected). With no SOURCE and no -c, uses the bundled "
                    "CTypes (stdlib types). Use -p to filter with an fnmatch glob.",
    )
    t.add_argument("src_from", nargs="?", default=None, metavar="SOURCE",
                   help="ELF binary or C header path. Omit for CTypes. "
                        "Mutually exclusive with -c.")
    t.add_argument("-c", "--code", dest="src_code", metavar="SRC", default=None,
                   help="Inline C source ('-' for stdin). Mutually exclusive with SOURCE.")
    t.add_argument("-b", "--bits", type=int, choices=(32, 64), default=None,
                   help="Target bits (selects C32/C64 builtin if no source).")
    t.add_argument("-I", action="append", dest="includes", metavar="DIR", default=[],
                   help="Header include dir (repeatable).")
    t.add_argument("-p", "--pattern", default="*",
                   help="fnmatch glob, e.g. '*chunk*'. Default: all.")
    t.add_argument("-l", "--long", action="store_true",
                   help="Append size and kind columns.")
    t.set_defaults(func=_safe(_types))

    v = sub.add_parser(
        "vars",
        help="List global variables from an ELF binary",
        description="List global variables found in an ELF's DWARF info. "
                    "Only ELF binaries are supported (headers and inline source "
                    "have no globals).",
    )
    v.add_argument("src_from", metavar="ELF",
                   help="Path to an ELF binary with DWARF info.")
    v.add_argument("-p", "--pattern", default="*",
                   help="fnmatch glob, e.g. '*hook*'. Default: all.")
    v.add_argument("-l", "--long", action="store_true",
                   help="Append type and size columns.")
    v.set_defaults(func=_safe(_vars))

    p.set_defaults(func=lambda args: (p.print_help(), sys.exit(1)))


def _safe(fn):
    """Wrap a handler so user-facing errors print a clean message instead of a traceback."""
    def wrapped(args):
        try:
            fn(args)
        except (ValueError, FileNotFoundError, IsADirectoryError, OSError) as e:
            print(f"error: {e}", file=sys.stderr)
            sys.exit(2)
    return wrapped


def _open_source(args):
    """Build an ORC instance based on parsed source-selection args."""
    src_from = getattr(args, "src_from", None)
    src_code = getattr(args, "src_code", None)
    bits = getattr(args, "bits", None)
    includes = getattr(args, "includes", None) or None

    if src_from is not None and src_code is not None:
        print("error: SOURCE and -c are mutually exclusive", file=sys.stderr)
        sys.exit(2)

    if src_code is not None:
        from doglib.orc import ORCInline
        if src_code == "-":
            src_code = sys.stdin.read()
        return ORCInline(src_code, bits=bits)

    if src_from is not None:
        with open(src_from, "rb") as f:
            magic = f.read(4)
        if magic == b"\x7fELF":
            from doglib.orc import ORC
            return ORC(src_from, bits=bits)
        from doglib.orc import ORCHeader
        return ORCHeader(src_from, include_dirs=includes, bits=bits)

    from doglib import orc as orcmod
    return orcmod.C32 if bits == 32 else orcmod.C64


def _is_elf_source(orc) -> bool:
    """True iff orc was loaded from an actual ELF binary (not header / inline / CTypes)."""
    from doglib.orc import ORCHeader
    return not isinstance(orc, ORCHeader)


def _resolve_sym_type(orc, sym_name):
    """Look up sym_name in DWARF global vars, return (type_name, sym_addr).
    Errors out cleanly if source is not ELF or symbol is missing."""
    if not _is_elf_source(orc):
        print("error: --sym requires an ELF source (-f ELF)", file=sys.stderr)
        sys.exit(2)
    orc._build_dwarf_cache()
    var_ref = orc._dwarf_vars.get(sym_name)
    if var_ref is None:
        print(f"error: symbol '{sym_name}' not found in DWARF info", file=sys.stderr)
        sys.exit(2)
    var_die = orc._get_die(var_ref)
    type_die = orc._get_die_from_attr(var_die, "DW_AT_type")
    if type_die is None:
        print(f"error: symbol '{sym_name}' has no type info", file=sys.stderr)
        sys.exit(2)
    # Walk the type-modifier chain (typedef/const/volatile) until we find a
    # DW_AT_name that matches a key in _dwarf_types — that's the bare name
    # the public ORC methods expect ('BossFight', not 'struct BossFight').
    type_name = None
    die = type_die
    while die is not None:
        name_attr = die.attributes.get("DW_AT_name")
        if name_attr:
            candidate = name_attr.value.decode("utf-8")
            if candidate in orc._dwarf_types:
                type_name = candidate
                break
        if die.tag in ("DW_TAG_typedef", "DW_TAG_const_type", "DW_TAG_volatile_type"):
            die = orc._get_die_from_attr(die, "DW_AT_type")
        else:
            break
    if type_name is None:
        print(f"error: symbol '{sym_name}' resolves to an unnamed type", file=sys.stderr)
        sys.exit(2)

    from pwnlib.elf import ELF
    elf = ELF(orc.path, checksec=False)
    sym_addr = elf.symbols.get(sym_name)
    return type_name, sym_addr


def _parse_int(s):
    return int(s, 0)


def _describe(args) -> None:
    orc = _open_source(args)
    if args.sym:
        type_name, sym_addr = _resolve_sym_type(orc, args.name)
        if sym_addr is not None:
            print(f"(symbol {args.name} @ {hex(sym_addr)})")
        orc.describe(type_name)
    else:
        orc.describe(args.name)


def _sizeof(args) -> None:
    orc = _open_source(args)
    if args.sym:
        type_name, _ = _resolve_sym_type(orc, args.name)
        print(orc.sizeof(type_name))
    else:
        print(orc.sizeof(args.name))


def _offsetof(args) -> None:
    orc = _open_source(args)
    path = args.path
    if args.sym:
        dot = path.find(".")
        if dot == -1:
            print("error: --sym requires 'sym.field' form", file=sys.stderr)
            sys.exit(2)
        sym_name, field_path = path[:dot], path[dot + 1:]
        type_name, sym_addr = _resolve_sym_type(orc, sym_name)
        offset = orc.offsetof(type_name, field_path)
        print(f"field offset: {hex(offset)}")
        if sym_addr is not None:
            print(f"absolute:     {hex(sym_addr + offset)}")
    else:
        offset = orc.offsetof(path)
        print(hex(offset))


def _field_at(args) -> None:
    orc = _open_source(args)
    offset = _parse_int(args.offset)
    if args.sym:
        type_name, sym_addr = _resolve_sym_type(orc, args.name)
        if sym_addr is not None:
            print(f"(symbol {args.name} @ {hex(sym_addr)}, +{hex(offset)} = {hex(sym_addr + offset)})")
    else:
        type_name = args.name
    result = orc.field_at(type_name, offset)
    paths = result if isinstance(result, list) else [result]
    for p in paths:
        if p.startswith("+"):
            print(f"(padding {p})")
        else:
            print(p)


def _resolve_type(args) -> None:
    orc = _open_source(args)
    print(orc.resolve_type(args.name))


def _enum(args) -> None:
    orc = _open_source(args)
    e = orc.enum(args.name)
    pairs = sorted(e, key=lambda kv: kv[1])
    width = max((len(n) for n, _ in pairs), default=0)
    for name, val in pairs:
        print(f"{name:<{width}} = {val}")


def _containerof(args) -> None:
    orc = _open_source(args)
    dot = args.path.find(".")
    if dot == -1:
        print("error: containerof requires 'Type.field' form", file=sys.stderr)
        sys.exit(2)
    type_name, field_path = args.path[:dot], args.path[dot + 1:]
    addr = _parse_int(args.addr)
    print(hex(orc.containerof(type_name, field_path, addr)))


def _types(args) -> None:
    orc = _open_source(args)
    orc._build_dwarf_cache()
    names = sorted(fnmatch.filter(orc._dwarf_types.keys(), args.pattern))
    if not args.long:
        for n in names:
            print(n)
        return
    rows = []
    for n in names:
        try:
            ref = orc._dwarf_types[n]
            die = orc._get_die(ref)
            unwrapped = orc._unwrap_type(die)
            kind = unwrapped.tag.replace("DW_TAG_", "").replace("_type", "") if unwrapped else "?"
            size = orc._get_byte_size(unwrapped) if unwrapped else 0
        except Exception:
            kind, size = "?", 0
        rows.append((n, size, kind))
    width = max((len(n) for n, _, _ in rows), default=0)
    for n, size, kind in rows:
        print(f"{n:<{width}}  {size:<6}  {kind}")


def _vars(args) -> None:
    # vars takes an ELF positional directly; reject non-ELF inputs hard.
    with open(args.src_from, "rb") as f:
        magic = f.read(4)
    if magic != b"\x7fELF":
        print(f"error: '{args.src_from}' is not an ELF binary", file=sys.stderr)
        sys.exit(2)
    from doglib.orc import ORC
    orc = ORC(args.src_from)
    orc._build_dwarf_cache()
    names = sorted(fnmatch.filter(orc._dwarf_vars.keys(), args.pattern))
    if not args.long:
        for n in names:
            print(n)
        return
    rows = []
    for n in names:
        try:
            ref = orc._dwarf_vars[n]
            die = orc._get_die(ref)
            type_die = orc._get_die_from_attr(die, "DW_AT_type")
            type_name = orc._get_type_name(type_die) if type_die else "?"
            unwrapped = orc._unwrap_type(type_die) if type_die else None
            size = orc._get_byte_size(unwrapped) if unwrapped else 0
        except Exception:
            type_name, size = "?", 0
        rows.append((n, type_name, size))
    name_w = max((len(n) for n, _, _ in rows), default=0)
    type_w = max((len(t) for _, t, _ in rows), default=0)
    for n, t, size in rows:
        print(f"{n:<{name_w}}  {t:<{type_w}}  {size}")
