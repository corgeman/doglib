import os
import re
import json
import hashlib
import struct
from pwnlib.log import getLogger
from pwnlib.elf.elf import ELF
from pwnlib.context import context
from elftools.elf.elffile import ELFFile

try:
    import doglib_dwarf_parser as _dwarf_parser_rs
except ImportError:
    _dwarf_parser_rs = None

log = getLogger(__name__)

from ._address import DWARFAddress, DWARFArray
from ._constants import CACHEABLE_TAGS, STRUCT_TAGS, array_stride, dims_str, va_mask
from ._crafter import DWARFCrafter, DWARFArrayCrafter
from ._enum import DWARFEnum
from ._resolver import DWARFResolver

class _CVarAccessor:
    def __init__(self, elf):
        self._elf = elf

    def __getitem__(self, name):
        self._elf._build_dwarf_cache()

        base_addr = self._elf.symbols.get(name)
        if base_addr is None:
            raise KeyError(f"Symbol '{name}' not found in ELF symbol table.")

        var_die_offset = self._elf._dwarf_vars.get(name)
        if not var_die_offset:
            raise KeyError(f"Variable '{name}' not found in DWARF info. Does it have debug symbols?")

        dwarfinfo = self._elf._get_dwarfinfo()
        var_die = dwarfinfo.get_DIE_from_refaddr(var_die_offset)
        type_die = self._elf._get_die_from_attr(var_die, 'DW_AT_type')

        if not type_die:
            raise KeyError(f"Missing type info for variable '{name}'.")

        return DWARFAddress(base_addr, self._elf, type_die.offset)

    def __contains__(self, name):
        self._elf._build_dwarf_cache()
        return name in self._elf.symbols and name in self._elf._dwarf_vars


class ExtendedELF(ELF):
    """
    An extension of the pwntools ELF class that adds support for resolving
    complex C-struct offsets dynamically using DWARF debug information.
    """
    _CACHE_VERSION = 5

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self._dwarf_vars = {}
        self._dwarf_types = {}
        self._dwarf_parsed = False
        self._dwarf_file = None
        self._dwarfinfo = None

        self.sym_obj = _CVarAccessor(self)
        self._resolver = None

    def _get_resolver(self):
        """Lazy-build the DWARF resolver. Requires dwarfinfo to be available."""
        if self._resolver is None:
            dwarfinfo = self._get_dwarfinfo()
            if dwarfinfo is None:
                raise RuntimeError("No DWARF info available")
            self._resolver = DWARFResolver(dwarfinfo, self.bits)
        return self._resolver

    _BASE_TYPE_ALIASES = {
        'short': 'short int',
        'unsigned short': 'short unsigned int',
        'long': 'long int',
        'unsigned long': 'long unsigned int',
        'long long': 'long long int',
        'unsigned long long': 'long long unsigned int',
        'unsigned': 'unsigned int',
        'signed': 'int',
        'signed int': 'int',
        'signed short': 'short int',
        'signed long': 'long int',
        'signed long long': 'long long int',
        'bool': '_Bool',
    }

    def _resolve_type_name(self, name):
        """Look up a type name in the cache, falling back to common C aliases."""
        offset = self._dwarf_types.get(name)
        if offset is not None:
            return offset
        alias = self._BASE_TYPE_ALIASES.get(name)
        if alias:
            return self._dwarf_types.get(alias)
        return None

    def close(self):
        """Close the DWARF file handle."""
        dwarf_file = getattr(self, '_dwarf_file', None)
        if dwarf_file:
            dwarf_file.close()
            self._dwarf_file = None
        self._dwarfinfo = None
        self._resolver = None

    def __del__(self):
        try:
            self.close()
        except Exception:
            pass

    def __enter__(self):
        return self

    def __exit__(self, *args):
        self.close()

    def _get_dwarfinfo(self):
        """Lazy-loads and caches the DWARF info to avoid reopening the file repeatedly."""
        if self._dwarfinfo is None:
            self._dwarf_file = open(self.path, 'rb')
            elffile = ELFFile(self._dwarf_file)
            if elffile.has_dwarf_info():
                self._dwarfinfo = elffile.get_dwarf_info()
        return self._dwarfinfo

    def _get_die_from_attr(self, die, attr_name):
        return self._get_resolver().get_die_from_attr(die, attr_name)

    def _unwrap_type(self, die):
        return self._get_resolver().unwrap_type(die)

    def _parse_member_offset(self, member_die):
        return self._get_resolver().parse_member_offset(member_die)

    def _find_member(self, struct_die, name):
        return self._get_resolver().find_member(struct_die, name)

    def _get_array_subranges(self, array_die):
        return self._get_resolver().get_array_subranges(array_die)

    def _get_byte_size(self, die, subrange_start=0):
        return self._get_resolver().get_byte_size(die, subrange_start)

    def _get_type_name(self, die):
        return self._get_resolver().get_type_name(die)

    @staticmethod
    def _parse_type_string(type_string):
        """
        Parse a type string into (base_name, dims, pointer_depth).
          'Foo[2][3]' → ('Foo', (2, 3), 0)
          'int *'     → ('int', None, 1)
          'Foo **'    → ('Foo', None, 2)
          'Foo'       → ('Foo', None, 0)
        """
        s = type_string.strip()
        pointer_depth = 0
        while s.endswith('*'):
            pointer_depth += 1
            s = s[:-1].rstrip()
        match = re.match(r'^(.+?)((?:\[\d+\])+)$', s)
        if match:
            base = match.group(1).strip()
            dims = tuple(int(d) for d in re.findall(r'\[(\d+)\]', match.group(2)))
            return base, dims, pointer_depth
        return s, None, pointer_depth

    @staticmethod
    def _tokenize_path(field_path):
        """Parse a field path string like 'a.b[2].c' into a list of tokens."""
        tokens = []
        for part in field_path.replace(']', '').split('['):
            for subpart in part.split('.'):
                if subpart:
                    try:
                        tokens.append(int(subpart))
                    except ValueError:
                        tokens.append(subpart)
        return tokens

    def _walk_field_path(self, start_die, tokens):
        """
        Walk a tokenized field path from a starting DIE, accumulating byte offsets.
        Returns (total_offset, final_die).
        Raises ValueError on resolution failure.
        """
        current_die = start_die
        offset = 0
        subrange_start = 0

        for token in tokens:
            current_die = self._unwrap_type(current_die)

            if current_die.tag == 'DW_TAG_pointer_type':
                raise ValueError(f"Cannot statically resolve through a pointer at token '{token}'.")

            if isinstance(token, int):
                if current_die.tag != 'DW_TAG_array_type':
                    raise ValueError(f"Expected array type for index '{token}', got {current_die.tag}")

                stride, elem_type, remaining_len = array_stride(self, current_die, subrange_start)

                offset += token * stride

                if remaining_len <= 1:
                    current_die = elem_type
                    subrange_start = 0
                else:
                    subrange_start += 1  # advance to next dimension
            else:
                subrange_start = 0

                if current_die.tag == 'DW_TAG_array_type':
                    current_die = self._unwrap_type(self._get_die_from_attr(current_die, 'DW_AT_type'))

                if current_die.tag not in STRUCT_TAGS:
                    raise ValueError(f"Expected struct/union for field '{token}', got {current_die.tag}")

                result = self._find_member(current_die, token)
                if result is None:
                    raise ValueError(f"Field '{token}' not found in struct")

                offset += result[0]
                current_die = result[1]

        return offset, current_die

    def _build_dwarf_cache(self):
        """Parses the DWARF tree and caches variable/struct DIE offsets to disk as JSON."""
        if self._dwarf_parsed:
            return

        extelf_cache_dir = os.path.join(context.cache_dir, 'extelf_cache')
        os.makedirs(extelf_cache_dir, exist_ok=True)

        if hasattr(self, 'buildid') and self.buildid:
            bid = self.buildid.hex()
        else:
            with open(self.path, 'rb') as f:
                bid = hashlib.sha256(f.read()).hexdigest()[:16]

        cache_file = os.path.join(extelf_cache_dir, f"dwarf_{bid}.json")

        if os.path.exists(cache_file):
            try:
                with open(cache_file, 'r') as f:
                    data = json.load(f)
                if data.get('cache_version') != self._CACHE_VERSION:
                    raise ValueError("stale cache version")
                self._dwarf_vars = data.get('vars', {})
                self._dwarf_types = data.get('types', {})
                self._dwarf_parsed = True
                return
            except Exception as e:
                log.warning(f"Rebuilding DWARF cache: {e}")

        log.info(f"Parsing DWARF info for {os.path.basename(self.path)}... (This will be cached)")
        if _dwarf_parser_rs is not None:
            try:
                self._dwarf_vars, self._dwarf_types = _dwarf_parser_rs.parse_dwarf(self.path)
                if not self._dwarf_vars and not self._dwarf_types:
                    raise ValueError("Rust DWARF parser returned an empty index")
                self._save_dwarf_cache(cache_file)
                return
            except Exception as e:
                log.warning(f"Rust DWARF parser failed ({e}), falling back to pyelftools")
                self._dwarf_vars = {}
                self._dwarf_types = {}

        dwarfinfo = self._get_dwarfinfo()
        if not dwarfinfo:
            log.warning("ELF has no DWARF info. Path resolution won't work.")
            self._dwarf_parsed = True
            return

        for CU in dwarfinfo.iter_CUs():
            for die in CU.iter_DIEs():
                if die.tag in CACHEABLE_TAGS:
                    name_attr = die.attributes.get('DW_AT_name')
                    if name_attr:
                        is_decl = die.attributes.get('DW_AT_declaration')
                        if is_decl and is_decl.value:
                            continue
                        name = name_attr.value.decode('utf-8', errors='ignore')
                        if die.tag == 'DW_TAG_variable':
                            self._dwarf_vars[name] = die.offset
                        else:
                            self._dwarf_types[name] = die.offset

        self._save_dwarf_cache(cache_file)

    def _save_dwarf_cache(self, cache_file):
        """Write the current DWARF vars/types cache to disk and mark as parsed."""
        with open(cache_file, 'w') as f:
            json.dump({
                'cache_version': self._CACHE_VERSION,
                'vars': self._dwarf_vars,
                'types': self._dwarf_types,
            }, f)
        self._dwarf_parsed = True

    def _resolve_dotpath_die(self, type_name):
        """
        Resolve a type name that may contain a dot-separated field path.

        Returns (field_offset, type_die) where:
          - field_offset is the byte offset of the named field within the
            top-level type (0 when no dot-path is given).
          - type_die is the DWARF DIE for the resolved type.

        Examples:
          '_IO_FILE_plus'          -> (0,  die for _IO_FILE_plus)
          '_IO_FILE_plus.file'     -> (0,  die for FILE, the type of the
                                         'file' member)
          'BossFight.b[1].c'      -> (offset, die for short)
        """
        self._build_dwarf_cache()
        dot = type_name.find('.')
        if dot == -1:
            offset = self._resolve_type_name(type_name)
            if offset is None:
                raise ValueError(f"Type '{type_name}' not found in DWARF info.")
            return 0, self._get_dwarfinfo().get_DIE_from_refaddr(offset)

        base_name = type_name[:dot]
        field_path = type_name[dot + 1:]

        base_offset = self._resolve_type_name(base_name)
        if base_offset is None:
            raise ValueError(f"Type '{base_name}' not found in DWARF info.")
        base_die = self._get_dwarfinfo().get_DIE_from_refaddr(base_offset)

        tokens = self._tokenize_path(field_path)
        try:
            field_offset, final_die = self._walk_field_path(base_die, tokens)
        except ValueError as e:
            raise ValueError(f"In type path '{type_name}': {e}") from e

        return field_offset, final_die

    def _get_type_die(self, type_name):
        """
        Look up a type by name (supporting dot-path navigation) and return its DIE.
        Raises ValueError if not found.
        """
        _, die = self._resolve_dotpath_die(type_name)
        return die

    def cast(self, type_name, address, count=None):
        """
        Cast an arbitrary memory address to a DWARF C-type object.
        Supports array, pointer, and dot-path syntax in the type name.

        When a dot-path is given (e.g. 'Foo.bar'), *address* is treated as the
        base address of the top-level type (Foo) and the field offset is added
        automatically.  The returned object reflects the type of the named field.

        Example:
            libc.cast('malloc_chunk', 0x55555555b000).fd
            libc.cast('Bar', arr_addr, count=64)[3].field
            libc.cast('int[4][8]', matrix_addr)[1][2]
            libc.cast('int *', heap_base)[520292]
            libc.cast('_IO_FILE_plus.file', vtable_addr)  # -> DWARFAddress<FILE>
        """
        self._build_dwarf_cache()
        base_name, parsed_dims, ptr_depth = self._parse_type_string(type_name)
        # _resolve_dotpath_die handles 'Foo.bar.baz' paths; for pointer types
        # the offset is always 0 (pointer itself sits at the given address).
        if ptr_depth > 0:
            field_offset = 0
            type_die_offset = self._resolve_type_name(base_name)
            if type_die_offset is None:
                raise ValueError(f"Struct/Type '{base_name}' not found in DWARF info.")
        else:
            field_offset, field_die = self._resolve_dotpath_die(base_name)
            type_die_offset = field_die.offset
        if ptr_depth > 0:
            if ptr_depth > 1:
                raise ValueError(
                    f"Multi-level pointer ('{'*' * ptr_depth}') not supported in cast. "
                    "Use 'unsigned long *' to treat as an array of pointer-sized values."
                )
            return DWARFArray(address, self, type_die_offset, (None,))
        effective_addr = address + field_offset
        dims = parsed_dims
        if dims is None and count is not None:
            dims = count if isinstance(count, tuple) else (count,)
        if dims is not None:
            return DWARFArray(effective_addr, self, type_die_offset, dims)
        return DWARFAddress(effective_addr, self, type_die_offset)

    def craft(self, type_name, count=None, pad=0):
        """
        Creates a zeroed byte-backed structure for assigning C-fields dynamically.
        Use bytes(obj) to extract the raw crafted payload.
        Supports array, pointer, and dot-path syntax in the type name.
        Pass pad=N to add N extra bytes for intentional OOB writes.

        Example:
            chunk = libc.craft('malloc_chunk')
            chunk.size = 0x21
            payload = bytes(chunk)

            arr = headers.craft('Foo[4][8]')
            arr[1][2].field = 42
            bytes(arr)

            # Craft using a field type resolved from a parent struct
            headers.craft('BossFight.u')   # -> DWARFCrafter for UnionMadness

            # OOB-capable crafting for exploitation
            arr = headers.craft('int[5][6]', pad=64)
            arr[4][6] = 0xdeadbeef  # one past the end, no warning
        """
        self._build_dwarf_cache()
        base_name, parsed_dims, ptr_depth = self._parse_type_string(type_name)
        if ptr_depth > 0:
            raise ValueError("Cannot craft a pointer type. Use craft('type[N]') for arrays.")
        _, field_die = self._resolve_dotpath_die(base_name)
        type_die_offset = field_die.offset
        dims = parsed_dims
        if dims is None and count is not None:
            dims = count if isinstance(count, tuple) else (count,)
        if dims is None:
            unwrapped = self._unwrap_type(field_die)
            if unwrapped and unwrapped.tag == 'DW_TAG_array_type':
                dims = tuple(self._get_array_subranges(unwrapped))
                elem_die = self._get_die_from_attr(unwrapped, 'DW_AT_type')
                if elem_die and dims:
                    type_die_offset = elem_die.offset
        if dims:
            crafter = DWARFArrayCrafter(self, type_die_offset, dims)
        else:
            crafter = DWARFCrafter(self, type_die_offset)
        if pad > 0:
            crafter._backing.extend(b'\x00' * pad)
        return crafter

    def parse(self, type_name, data, count=None):
        """
        Parse raw bytes into a struct, the reverse of craft().
        Supports array syntax: parse('Bar[64]', data).

        Example:
            chunk = libc.parse('malloc_chunk', leaked)
            log.info(f"fd = {hex(chunk.fd.value)}")

            arr = headers.parse('int[4][8]', big_leak)
            arr[1][2].value
        """
        crafter = self.craft(type_name, count=count)
        raw = bytes(data)
        size = min(len(raw), len(bytes(crafter)))
        crafter._backing[:size] = raw[:size]
        return crafter

    def enum(self, type_name):
        """
        Get named access to an enum's constants.

        Example:
            state = headers.enum('State')
            state.CRASHED   # -> -1
            state.RUNNING   # -> 1
            'IDLE' in state  # -> True
        """
        die = self._get_type_die(type_name)
        unwrapped = self._unwrap_type(die)
        if not unwrapped or unwrapped.tag != 'DW_TAG_enumeration_type':
            raise ValueError(f"'{type_name}' is not an enum type.")
        return DWARFEnum(self, die.offset)

    def sizeof(self, type_name):
        """
        Get the byte size of a named type.
        Supports array, pointer, and dot-path syntax.
        Example: headers.sizeof('int[100]') -> 400
                 headers.sizeof('int *') -> 8 (on 64-bit)
                 headers.sizeof('BossFight.u') -> size of the 'u' member's type
        """
        base_name, parsed_dims, ptr_depth = self._parse_type_string(type_name)
        if ptr_depth > 0:
            return self.bits // 8
        die = self._get_type_die(base_name)
        size = self._get_byte_size(die)
        if parsed_dims:
            for d in parsed_dims:
                size *= d
        return size

    def offsetof(self, type_name, field_path):
        """
        Get the byte offset of a field within a struct.
        Supports dotted paths and array indices.

        Example:
            headers.offsetof('FinalBoss', 'matrix')        -> 8
            headers.offsetof('FinalBoss', 'matrix[1][2]')  -> 28
            headers.offsetof('BossFight', 'u.data.raw')    -> 24
        """
        die = self._get_type_die(type_name)
        tokens = self._tokenize_path(field_path)
        offset, _ = self._walk_field_path(die, tokens)
        return offset

    def containerof(self, type_name, field_path, member_addr):
        """
        Calculate the base address of a struct given a pointer to one of its
        members. Equivalent to the Linux kernel container_of() macro.

        Example:
            base = headers.containerof('task_struct', 'tasks', list_entry_addr)
        """
        return (member_addr - self.offsetof(type_name, field_path)) & va_mask(self.bits)

    def describe(self, type_name):
        """
        Print the memory layout of a struct/union type as a formatted table.
        Recursively inlines anonymous struct/union members.
        Supports dot-path syntax to describe a nested field's type directly.

        Example:
            headers.describe('FinalBoss')
            headers.describe('BossFight.u')  # layout of the 'u' member's type
        """
        die = self._get_type_die(type_name)
        unwrapped = self._unwrap_type(die)

        array_suffix = ''
        if unwrapped and unwrapped.tag == 'DW_TAG_array_type':
            dims = self._get_array_subranges(unwrapped)
            array_suffix = dims_str(dims)
            elem_die = self._get_die_from_attr(unwrapped, 'DW_AT_type')
            if elem_die:
                unwrapped = self._unwrap_type(elem_die)

        if not unwrapped or unwrapped.tag not in STRUCT_TAGS:
            raise ValueError(f"'{type_name}' is not a struct/union type.")

        total_size = self._get_byte_size(unwrapped)
        if unwrapped.tag == 'DW_TAG_union_type':
            label = 'union'
        elif unwrapped.tag == 'DW_TAG_class_type':
            label = 'class'
        else:
            label = 'struct'

        rows = self._collect_describe_rows(unwrapped)

        size_label = f"{total_size} bytes"
        if array_suffix:
            size_label += f", element of {array_suffix}"
        print(f"{label} {type_name} ({size_label}):")
        print(f"  {'offset':<8} {'size':<6} {'type':<28} {'name'}")
        print(f"  {'------':<8} {'----':<6} {'----':<28} {'----'}")
        for off, sz, tname, fname in rows:
            print(f"  0x{off:<6x} {sz:<6} {tname:<28} {fname}")

    def _collect_describe_rows(self, die, base_offset=0):
        """Walk struct members for describe(), inlining anonymous and inherited members."""
        rows = []
        for child in die.iter_children():
            if child.tag == 'DW_TAG_inheritance':
                base_type = self._get_die_from_attr(child, 'DW_AT_type')
                if base_type:
                    base_unwrapped = self._unwrap_type(base_type)
                    if base_unwrapped:
                        inherit_offset = self._parse_member_offset(child) + base_offset
                        rows.extend(self._collect_describe_rows(base_unwrapped, inherit_offset))
                continue

            if child.tag != 'DW_TAG_member':
                continue
            name_attr = child.attributes.get('DW_AT_name')
            offset = self._parse_member_offset(child) + base_offset
            member_type = self._get_die_from_attr(child, 'DW_AT_type')

            if not name_attr and member_type:
                unwrapped = self._unwrap_type(member_type)
                if unwrapped and unwrapped.tag in STRUCT_TAGS:
                    rows.extend(self._collect_describe_rows(unwrapped, offset))
                    continue

            name = name_attr.value.decode('utf-8') if name_attr else '<anonymous>'
            type_str = self._get_type_name(member_type) if member_type else '?'
            size = self._get_byte_size(member_type) if member_type else 0
            rows.append((offset, size, type_str, name))
        return rows

    def resolve_type(self, type_name):
        """
        Resolve a typedef to its underlying type name.
        Example: headers.resolve_type('size_t') -> 'long unsigned int'
        """
        die = self._get_type_die(type_name)
        unwrapped = self._unwrap_type(die)
        return self._get_type_name(unwrapped)

    def resolve_field(self, symbol_name, field_path=None, struct_name=None):
        """
        Dynamically calculates the exact memory address of a field inside a struct/array.
        Supports multi-dimensional array paths like 'matrix[1][2]'.
        """
        base_addr = self.symbols.get(symbol_name)
        if base_addr is None:
            log.error(f"Symbol '{symbol_name}' not found in standard ELF symbol table.")
            return None

        if not field_path:
            return base_addr

        self._build_dwarf_cache()
        dwarfinfo = self._get_dwarfinfo()

        if struct_name:
            start_die_offset = self._resolve_type_name(struct_name)
            if not start_die_offset:
                log.error(f"Struct '{struct_name}' not found in DWARF info.")
                return None
        else:
            var_die_offset = self._dwarf_vars.get(symbol_name)
            if not var_die_offset:
                log.error(f"Variable '{symbol_name}' not found in DWARF info. Try passing struct_name explicitly.")
                return None
            var_die = dwarfinfo.get_DIE_from_refaddr(var_die_offset)
            type_die = self._get_die_from_attr(var_die, 'DW_AT_type')
            if not type_die:
                return None
            start_die_offset = type_die.offset

        start_die = dwarfinfo.get_DIE_from_refaddr(start_die_offset)
        tokens = self._tokenize_path(field_path)

        try:
            offset, _ = self._walk_field_path(start_die, tokens)
        except ValueError as e:
            log.error(str(e))
            return None

        return (base_addr + offset) & va_mask(self.bits)
