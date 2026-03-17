import os
import re
import json
import hashlib
import subprocess
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
from ._enum import DWARFEnum
from ._crafter import DWARFCrafter, DWARFArrayCrafter

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
    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self._dwarf_vars = {}
        self._dwarf_types = {}
        self._dwarf_parsed = False
        self._dwarf_file = None
        self._dwarfinfo = None

        self.sym_obj = _CVarAccessor(self)

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
        """Helper to follow DWARF type references (e.g., DW_AT_type)."""
        if attr_name not in die.attributes:
            return None
        attr = die.attributes[attr_name]
        offset = attr.value

        if attr.form in ('DW_FORM_ref1', 'DW_FORM_ref2', 'DW_FORM_ref4', 'DW_FORM_ref8', 'DW_FORM_ref_udata'):
            offset += die.cu.cu_offset

        return die.cu.dwarfinfo.get_DIE_from_refaddr(offset)

    def _unwrap_type(self, die):
        """Strips away typedefs, const, volatile, restrict, and _Atomic modifiers."""
        passthrough = (
            'DW_TAG_typedef', 'DW_TAG_const_type', 'DW_TAG_volatile_type',
            'DW_TAG_restrict_type', 'DW_TAG_atomic_type',
        )
        while die and die.tag in passthrough:
            die = self._get_die_from_attr(die, 'DW_AT_type')
        return die

    def _decode_uleb128(self, data):
        """Decode a ULEB128 value from a sequence of bytes."""
        val, shift = 0, 0
        for b in data:
            val |= (b & 0x7f) << shift
            if (b & 0x80) == 0:
                break
            shift += 7
        return val

    def _parse_member_offset(self, member_die):
        """Parse DW_AT_data_member_location from a member DIE, handling various DWARF expression forms."""
        if 'DW_AT_bit_size' in member_die.attributes or 'DW_AT_data_bit_offset' in member_die.attributes:
            name = member_die.attributes.get('DW_AT_name')
            fname = name.value.decode('utf-8') if name else '<anonymous>'
            log.warning(f"Field '{fname}' is a bit-field. Bit-field access is not fully supported and may produce incorrect results.")

        loc = member_die.attributes.get('DW_AT_data_member_location')
        if not loc:
            return 0

        if isinstance(loc.value, int):
            return loc.value

        if isinstance(loc.value, (list, bytes)):
            expr = list(loc.value)
            if not expr:
                return 0

            op = expr[0]

            if op == 0x23:  # DW_OP_plus_uconst
                return self._decode_uleb128(expr[1:])

            if op == 0x10:  # DW_OP_constu (often followed by DW_OP_plus)
                return self._decode_uleb128(expr[1:])

            if 0x30 <= op <= 0x4f:  # DW_OP_lit0 through DW_OP_lit31
                return op - 0x30

            if op == 0x08 and len(expr) >= 2:  # DW_OP_const1u
                return expr[1]

            if op == 0x0a and len(expr) >= 3:  # DW_OP_const2u
                return expr[1] | (expr[2] << 8)

            if op == 0x0c and len(expr) >= 5:  # DW_OP_const4u
                return expr[1] | (expr[2] << 8) | (expr[3] << 16) | (expr[4] << 24)

            log.warning(f"Unhandled DWARF location expression opcode: 0x{op:02x}")

        return 0

    def _find_member(self, struct_die, name):
        """
        Find a member by name in a struct/union/class DIE. Recurses into:
        - Anonymous struct/union members (C11 anonymous access patterns)
        - Base classes via DW_TAG_inheritance (C++ inheritance)
        Returns (offset, type_die) or None.
        """
        for child in struct_die.iter_children():
            if child.tag == 'DW_TAG_member':
                name_attr = child.attributes.get('DW_AT_name')
                if name_attr and name_attr.value.decode('utf-8') == name:
                    offset = self._parse_member_offset(child)
                    type_die = self._get_die_from_attr(child, 'DW_AT_type')
                    if not type_die:
                        return None
                    return (offset, type_die)

                if not name_attr:
                    anon_type = self._get_die_from_attr(child, 'DW_AT_type')
                    if anon_type:
                        anon_unwrapped = self._unwrap_type(anon_type)
                        if anon_unwrapped and anon_unwrapped.tag in ('DW_TAG_structure_type', 'DW_TAG_class_type', 'DW_TAG_union_type'):
                            result = self._find_member(anon_unwrapped, name)
                            if result:
                                anon_offset = self._parse_member_offset(child)
                                return (anon_offset + result[0], result[1])

            elif child.tag == 'DW_TAG_inheritance':
                base_type = self._get_die_from_attr(child, 'DW_AT_type')
                if base_type:
                    base_unwrapped = self._unwrap_type(base_type)
                    if base_unwrapped:
                        result = self._find_member(base_unwrapped, name)
                        if result:
                            base_offset = self._parse_member_offset(child)
                            return (base_offset + result[0], result[1])

        return None

    def _get_array_subranges(self, array_die):
        """Extract dimension sizes from a DWARF array type's subrange children."""
        dims = []
        for child in array_die.iter_children():
            if child.tag == 'DW_TAG_subrange_type':
                if 'DW_AT_count' in child.attributes:
                    dims.append(child.attributes['DW_AT_count'].value)
                elif 'DW_AT_upper_bound' in child.attributes:
                    dims.append(child.attributes['DW_AT_upper_bound'].value + 1)
        return dims

    def _get_byte_size(self, die, subrange_start=0):
        """
        Recursively determines the byte size of a DWARF type.
        For multi-dimensional arrays, subrange_start controls which
        dimensions are included in the size calculation.
        """
        die = self._unwrap_type(die)
        if not die:
            log.warning("Could not determine byte size for type (None die)")
            return 0

        if die.tag == 'DW_TAG_array_type':
            elem_type = self._unwrap_type(self._get_die_from_attr(die, 'DW_AT_type'))
            elem_size = self._get_byte_size(elem_type)
            subranges = self._get_array_subranges(die)
            relevant = subranges[subrange_start:]
            if not relevant:
                return 0
            count = 1
            for dim in relevant:
                count *= dim
            return elem_size * count

        if 'DW_AT_byte_size' in die.attributes:
            return die.attributes['DW_AT_byte_size'].value

        if die.tag == 'DW_TAG_pointer_type':
            return self.elfclass // 8

        if die.tag == 'DW_TAG_enumeration_type':
            return 4

        log.warning(f"Could not determine byte size for DWARF tag {die.tag}")
        return 0

    def _get_type_name(self, die):
        """Get a human-readable type name string from a DWARF DIE."""
        if not die:
            return 'void'

        if die.tag == 'DW_TAG_typedef':
            name = die.attributes.get('DW_AT_name')
            if name:
                return name.value.decode('utf-8')

        die = self._unwrap_type(die)
        if not die:
            return 'void'

        if die.tag == 'DW_TAG_base_type':
            name = die.attributes.get('DW_AT_name')
            return name.value.decode('utf-8') if name else 'unknown'

        if die.tag == 'DW_TAG_pointer_type':
            pointee = self._get_die_from_attr(die, 'DW_AT_type')
            return self._get_type_name(pointee) + '*'

        if die.tag == 'DW_TAG_array_type':
            elem = self._get_die_from_attr(die, 'DW_AT_type')
            dims = ''.join(f'[{d}]' for d in self._get_array_subranges(die))
            return self._get_type_name(elem) + dims

        if die.tag in ('DW_TAG_structure_type', 'DW_TAG_class_type', 'DW_TAG_union_type'):
            prefix = 'struct' if die.tag == 'DW_TAG_structure_type' else 'union'
            name = die.attributes.get('DW_AT_name')
            return f"{prefix} {name.value.decode('utf-8')}" if name else f"<anon {prefix}>"

        if die.tag == 'DW_TAG_enumeration_type':
            name = die.attributes.get('DW_AT_name')
            return f"enum {name.value.decode('utf-8')}" if name else '<anon enum>'

        return '?'

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

                subranges = self._get_array_subranges(current_die)
                remaining = subranges[subrange_start:]

                elem_type = self._unwrap_type(self._get_die_from_attr(current_die, 'DW_AT_type'))
                elem_size = self._get_byte_size(elem_type)

                stride = elem_size
                for dim in remaining[1:]:
                    stride *= dim

                offset += token * stride

                if len(remaining) <= 1:
                    current_die = elem_type
                    subrange_start = 0
                else:
                    subrange_start += 1
            else:
                subrange_start = 0

                if current_die.tag not in ('DW_TAG_structure_type', 'DW_TAG_class_type', 'DW_TAG_union_type'):
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

        _CACHE_VERSION = 4

        if os.path.exists(cache_file):
            try:
                with open(cache_file, 'r') as f:
                    data = json.load(f)
                if data.get('cache_version') != _CACHE_VERSION:
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
                with open(cache_file, 'w') as f:
                    json.dump({
                        'cache_version': _CACHE_VERSION,
                        'vars': self._dwarf_vars,
                        'types': self._dwarf_types,
                    }, f)
                self._dwarf_parsed = True
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

        cacheable_tags = (
            'DW_TAG_variable', 'DW_TAG_structure_type', 'DW_TAG_class_type',
            'DW_TAG_union_type', 'DW_TAG_typedef', 'DW_TAG_enumeration_type',
            'DW_TAG_base_type',
        )
        for CU in dwarfinfo.iter_CUs():
            for die in CU.iter_DIEs():
                if die.tag in cacheable_tags:
                    name_attr = die.attributes.get('DW_AT_name')
                    if name_attr:
                        name = name_attr.value.decode('utf-8', errors='ignore')
                        if die.tag == 'DW_TAG_variable':
                            self._dwarf_vars[name] = die.offset
                        else:
                            self._dwarf_types[name] = die.offset

        with open(cache_file, 'w') as f:
            json.dump({
                'cache_version': _CACHE_VERSION,
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
        if dims is not None:
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
        mask = (1 << self.bits) - 1
        return (member_addr - self.offsetof(type_name, field_path)) & mask

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
        if not unwrapped or unwrapped.tag not in ('DW_TAG_structure_type', 'DW_TAG_class_type', 'DW_TAG_union_type'):
            raise ValueError(f"'{type_name}' is not a struct/union type.")

        total_size = self._get_byte_size(unwrapped)
        label = 'struct' if unwrapped.tag == 'DW_TAG_structure_type' else 'union'

        rows = self._collect_describe_rows(unwrapped)

        print(f"{label} {type_name} ({total_size} bytes):")
        print(f"  {'offset':<8} {'size':<6} {'type':<28} {'name'}")
        print(f"  {'------':<8} {'----':<6} {'----':<28} {'----'}")
        for off, sz, tname, fname in rows:
            print(f"  0x{off:<6x} {sz:<6} {tname:<28} {fname}")

    def _collect_describe_rows(self, die, base_offset=0):
        """Walk struct members for describe(), inlining anonymous members."""
        rows = []
        for child in die.iter_children():
            if child.tag != 'DW_TAG_member':
                continue
            name_attr = child.attributes.get('DW_AT_name')
            offset = self._parse_member_offset(child) + base_offset
            member_type = self._get_die_from_attr(child, 'DW_AT_type')

            if not name_attr and member_type:
                unwrapped = self._unwrap_type(member_type)
                if unwrapped and unwrapped.tag in ('DW_TAG_structure_type', 'DW_TAG_class_type', 'DW_TAG_union_type'):
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

        mask = (1 << self.bits) - 1
        return (base_addr + offset) & mask


class CHeader(ExtendedELF):
    """
    Takes a C header file, automatically compiles it into a temporary ELF
    with DWARF symbols via GCC, and wraps it in an ExtendedELF interface.

    Accepts optional include_dirs for headers that #include other files.
    Pass bits=32 to compile for 32-bit targets. If not provided, uses
    context.bits when the user has explicitly set context.arch or
    context.bits, otherwise falls back to the host architecture.
    """
    def __init__(self, header_path, include_dirs=None, bits=None, **kwargs):
        header_path = os.path.abspath(header_path)
        if not os.path.exists(header_path):
            raise FileNotFoundError(f"Header file not found: {header_path}")

        with open(header_path, 'rb') as f:
            header_data = f.read()

        host_bits = struct.calcsize('P') * 8
        if bits is None:
            if 'bits' in context._tls:
                bits = context.bits
            else:
                bits = host_bits

        hash_input = header_data + str(bits).encode()
        if include_dirs:
            hash_input += b'|' + '|'.join(sorted(os.path.abspath(d) for d in include_dirs)).encode()
        header_hash = hashlib.sha256(hash_input).hexdigest()[:16]

        extelf_cache_dir = os.path.join(context.cache_dir, 'extelf_cache')
        os.makedirs(extelf_cache_dir, exist_ok=True)

        elf_path = os.path.join(extelf_cache_dir, f"cheader_{header_hash}.elf")

        if not os.path.exists(elf_path):
            log.info(f"Compiling {os.path.basename(header_path)} to DWARF ELF...")
            try:
                cmd = ['gcc', '-x', 'c', '-c', '-g', '-fno-eliminate-unused-debug-types']
                if bits != host_bits:
                    cmd.append(f'-m{bits}')
                if include_dirs:
                    for d in include_dirs:
                        cmd.extend(['-I', os.path.abspath(d)])
                cmd.extend([header_path, '-o', elf_path])
                subprocess.run(cmd, check=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
            except FileNotFoundError:
                log.error("Failed to compile header: 'gcc' is not installed or not in PATH.")
                raise
            except subprocess.CalledProcessError as e:
                log.error(f"GCC failed to compile the header:\n{e.stderr.decode() if e.stderr else ''}")
                raise

        kwargs.setdefault('checksec', False)
        super().__init__(elf_path, **kwargs)

    # remove annoying pwntools warning
    def _populate_got(self): pass


class CInline(CHeader):
    """
    Like CHeader but accepts C source code directly as a string instead of a
    file path. Types are compiled to DWARF on the fly and cached by content
    hash, so repeated calls with identical source never recompile.

    Example:
        types = CInline('''
            typedef struct chunk {
                size_t prev_size;
                size_t size;
                struct chunk *fd, *bk;
            } chunk;
        ''')
        c = types.craft('chunk')
        c.size = 0x21

    # 32-bit layout
    types32 = CInline('typedef struct foo { int x; } foo;', bits=32)
    """
    def __init__(self, source, bits=None, **kwargs):
        import tempfile
        src_bytes = source.encode() if isinstance(source, str) else bytes(source)
        with tempfile.NamedTemporaryFile(suffix='.h', prefix='cinline_') as f:
            f.write(src_bytes)
            f.flush()
            super().__init__(f.name, bits=bits, **kwargs)
