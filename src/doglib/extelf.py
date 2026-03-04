import os
import json
import hashlib
import subprocess
import struct
from pwn import *
from elftools.elf.elffile import ELFFile

# Extension to pwntools ELF
# Lets you do struct math on symbols (if the elf has debuginfo)
'''
libc = ExtendedELF('./libc.so.6')
libc.address = 0x7ffff7a00000  # PIE slides are automatically respected dynamically!
target_fd = libc.sym_obj['main_arena'].bins[3].fd
'''
# Can also cast things as structs
'''
heap_chunk_addr = 0x55555555b000
chunk_struct = libc.cast('malloc_chunk', heap_chunk_addr)
log.info(f"Size field is at: {hex(chunk_struct.size)}")
'''
# Can also craft structs!
'''
chunk = libc.craft("malloc_chunk")
chunk.mchunk_prev_size = 0x420
chunk.fd = 0x123456789
chunk.bk_nextsize = 0x11037
bytes(chunk) # in memory
'''
# Also if the headers are in a .h file (like exported from ida) you can use that too
'''
structs = CHeader("custom_structs.h")
payload = structs.craft("MyVulnerableStruct")
payload.buffer = b"A" * 64
payload.func_ptr = 0xdeadbeef
'''


class DWARFAddress(int):
    """
    An integer subclass representing a memory address that retains its C-type.
    Allows attribute access (obj.field) and indexing (obj[index]),
    including multi-dimensional array indexing (arr[1][2]).
    """
    def __new__(cls, value, elf, type_die_offset, subrange_start=0):
        obj = super().__new__(cls, value)
        obj._elf = elf
        obj._type_die_offset = type_die_offset
        obj._subrange_start = subrange_start
        return obj

    def __getattr__(self, name):
        if name.startswith('_'):
            raise AttributeError(name)

        dwarfinfo = self._elf._get_dwarfinfo()
        die = dwarfinfo.get_DIE_from_refaddr(self._type_die_offset)
        current_die = self._elf._unwrap_type(die)

        if current_die.tag == 'DW_TAG_pointer_type':
            log.error(f"Cannot statically resolve through a pointer at '.{name}'. Dereference first.")
            raise AttributeError(name)

        if current_die.tag not in ('DW_TAG_structure_type', 'DW_TAG_union_type'):
            raise AttributeError(f"Type {current_die.tag} is not a struct/union. Cannot access '.{name}'")

        result = self._elf._find_member(current_die, name)
        if result is None:
            raise AttributeError(f"Field '{name}' not found in struct")

        member_offset, next_type_die = result
        return DWARFAddress(int(self) + member_offset, self._elf, next_type_die.offset)

    def __getitem__(self, index):
        if not isinstance(index, int):
            raise TypeError("Array indices must be integers")

        dwarfinfo = self._elf._get_dwarfinfo()
        die = dwarfinfo.get_DIE_from_refaddr(self._type_die_offset)
        current_die = self._elf._unwrap_type(die)

        if current_die.tag == 'DW_TAG_pointer_type':
            log.error("Cannot statically index a pointer variable. Dereference first.")
            raise IndexError(index)

        if current_die.tag != 'DW_TAG_array_type':
            raise TypeError(f"Cannot index into non-array type {current_die.tag}")

        subranges = self._elf._get_array_subranges(current_die)
        remaining = subranges[self._subrange_start:]
        if not remaining:
            raise TypeError("No more array dimensions to index")

        elem_type = self._elf._unwrap_type(self._elf._get_die_from_attr(current_die, 'DW_AT_type'))
        elem_size = self._elf._get_byte_size(elem_type)

        stride = elem_size
        for dim in remaining[1:]:
            stride *= dim

        new_addr = int(self) + index * stride

        if len(remaining) == 1:
            return DWARFAddress(new_addr, self._elf, elem_type.offset)
        return DWARFAddress(new_addr, self._elf, current_die.offset, self._subrange_start + 1)


class DWARFCrafter:
    """
    A mutable byte-array wrapper that allows C-style struct member assignments.
    Supports multi-dimensional array indexing and sub-struct assignment.
    Calling bytes(obj) yields the fully crafted memory structure.

    The .value property reads back the current value for primitive fields.
    Note: .value shadows any struct field literally named 'value'.
    """
    def __init__(self, elf, type_die_offset, backing=None, offset=0, subrange_start=0):
        super().__setattr__('_elf', elf)
        super().__setattr__('_type_die_offset', type_die_offset)
        super().__setattr__('_subrange_start', subrange_start)

        dwarfinfo = elf._get_dwarfinfo()
        die = dwarfinfo.get_DIE_from_refaddr(type_die_offset)
        current_die = elf._unwrap_type(die)
        size = elf._get_byte_size(current_die, subrange_start)

        super().__setattr__('_size', size)
        super().__setattr__('_offset', offset)

        if backing is None:
            super().__setattr__('_backing', bytearray(size))
        else:
            super().__setattr__('_backing', backing)

    def __bytes__(self):
        return bytes(self._backing[self._offset : self._offset + self._size])

    def __len__(self):
        return self._size

    def __repr__(self):
        hex_data = bytes(self).hex()
        preview = hex_data[:32] + ('...' if len(hex_data) > 32 else '')
        return f"<DWARFCrafter size={self._size} data={preview}>"

    @property
    def value(self):
        """Read back the current value of a primitive field from the backing array."""
        dwarfinfo = self._elf._get_dwarfinfo()
        die = dwarfinfo.get_DIE_from_refaddr(self._type_die_offset)
        current_die = self._elf._unwrap_type(die)

        raw = bytes(self._backing[self._offset : self._offset + self._size])
        byte_order = 'little' if self._elf.little_endian else 'big'

        if current_die.tag == 'DW_TAG_base_type':
            encoding = current_die.attributes.get('DW_AT_encoding')
            if encoding:
                enc = encoding.value
                if enc == 0x04:  # DW_ATE_float
                    fmt = ('<' if self._elf.little_endian else '>') + ('f' if self._size == 4 else 'd')
                    return struct.unpack(fmt, raw)[0]
                if enc in (0x05, 0x06):  # DW_ATE_signed, DW_ATE_signed_char
                    return int.from_bytes(raw, byteorder=byte_order, signed=True)
            return int.from_bytes(raw, byteorder=byte_order, signed=False)

        if current_die.tag in ('DW_TAG_pointer_type', 'DW_TAG_enumeration_type'):
            return int.from_bytes(raw, byteorder=byte_order, signed=False)

        return raw

    def _write_value(self, offset, type_die, value, subrange_start=0):
        size = self._elf._get_byte_size(type_die, subrange_start)
        absolute_offset = self._offset + offset

        if isinstance(value, DWARFCrafter):
            val_bytes = bytes(value).ljust(size, b'\x00')[:size]
        elif isinstance(value, int):
            byte_order = 'little' if self._elf.little_endian else 'big'
            val_bytes = (value & ((1 << (size * 8)) - 1)).to_bytes(size, byteorder=byte_order)
        elif isinstance(value, float):
            byte_order = '<' if self._elf.little_endian else '>'
            if size == 4:
                val_bytes = struct.pack(byte_order + 'f', value)
            elif size == 8:
                val_bytes = struct.pack(byte_order + 'd', value)
            else:
                raise ValueError(f"Unsupported float size {size} for struct crafting")
        elif isinstance(value, (bytes, bytearray)):
            val_bytes = bytes(value).ljust(size, b'\x00')[:size]
        else:
            raise TypeError(f"Unsupported type {type(value)} for struct crafting (must be int, float, bytes, or DWARFCrafter)")

        self._backing[absolute_offset : absolute_offset + size] = val_bytes

    def _resolve_field(self, name):
        """Resolve a struct field name to (offset, type_die)."""
        dwarfinfo = self._elf._get_dwarfinfo()
        die = dwarfinfo.get_DIE_from_refaddr(self._type_die_offset)
        current_die = self._elf._unwrap_type(die)

        if current_die.tag == 'DW_TAG_pointer_type':
            raise AttributeError(f"Cannot resolve through a pointer at '.{name}'. Set the pointer directly.")

        if current_die.tag not in ('DW_TAG_structure_type', 'DW_TAG_union_type'):
            raise AttributeError(f"Type {current_die.tag} is not a struct/union. Cannot access '.{name}'")

        result = self._elf._find_member(current_die, name)
        if result is None:
            raise AttributeError(f"Field '{name}' not found in struct")
        return result

    def _resolve_index(self, index):
        """Resolve an array index to (offset, type_die, subrange_start)."""
        if not isinstance(index, int):
            raise TypeError("Array indices must be integers")

        dwarfinfo = self._elf._get_dwarfinfo()
        die = dwarfinfo.get_DIE_from_refaddr(self._type_die_offset)
        current_die = self._elf._unwrap_type(die)

        if current_die.tag == 'DW_TAG_pointer_type':
            raise TypeError("Cannot index a pointer in struct crafter. Set the pointer address directly.")

        if current_die.tag != 'DW_TAG_array_type':
            raise TypeError(f"Cannot index into non-array type {current_die.tag}")

        subranges = self._elf._get_array_subranges(current_die)
        remaining = subranges[self._subrange_start:]
        if not remaining:
            raise TypeError("No more array dimensions to index")

        elem_type = self._elf._unwrap_type(self._elf._get_die_from_attr(current_die, 'DW_AT_type'))
        elem_size = self._elf._get_byte_size(elem_type)

        stride = elem_size
        for dim in remaining[1:]:
            stride *= dim

        elem_offset = index * stride

        if len(remaining) == 1:
            return elem_offset, elem_type, 0
        return elem_offset, current_die, self._subrange_start + 1

    def __getattr__(self, name):
        if name.startswith('_'):
            raise AttributeError(name)
        member_offset, member_type_die = self._resolve_field(name)
        return DWARFCrafter(self._elf, member_type_die.offset, self._backing, self._offset + member_offset)

    def __setattr__(self, name, value):
        if name.startswith('_'):
            return super().__setattr__(name, value)
        member_offset, member_type_die = self._resolve_field(name)
        self._write_value(member_offset, member_type_die, value)

    def __getitem__(self, index):
        elem_offset, type_die, sub_start = self._resolve_index(index)
        return DWARFCrafter(self._elf, type_die.offset, self._backing, self._offset + elem_offset, sub_start)

    def __setitem__(self, index, value):
        elem_offset, type_die, sub_start = self._resolve_index(index)
        self._write_value(elem_offset, type_die, value, sub_start)


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
        Find a member by name in a struct/union DIE. Recurses into anonymous
        struct/union members to support C11 anonymous access patterns.
        Returns (offset, type_die) or None.
        """
        for child in struct_die.iter_children():
            if child.tag != 'DW_TAG_member':
                continue

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
                    if anon_unwrapped and anon_unwrapped.tag in ('DW_TAG_structure_type', 'DW_TAG_union_type'):
                        result = self._find_member(anon_unwrapped, name)
                        if result:
                            anon_offset = self._parse_member_offset(child)
                            return (anon_offset + result[0], result[1])

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

        # Arrays need special handling for multi-dimensional sub-array sizing
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
                self._dwarf_vars = data.get('vars', {})
                self._dwarf_types = data.get('types', {})
                self._dwarf_parsed = True
                return
            except Exception as e:
                log.warning(f"Failed to load DWARF cache: {e}. Rebuilding...")

        log.info(f"Parsing DWARF info for {os.path.basename(self.path)}... (This will be cached)")
        dwarfinfo = self._get_dwarfinfo()
        if not dwarfinfo:
            log.warning("ELF has no DWARF info. Path resolution won't work.")
            self._dwarf_parsed = True
            return

        cacheable_tags = (
            'DW_TAG_variable', 'DW_TAG_structure_type', 'DW_TAG_union_type',
            'DW_TAG_typedef', 'DW_TAG_enumeration_type',
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
            json.dump({'vars': self._dwarf_vars, 'types': self._dwarf_types}, f)
        self._dwarf_parsed = True

    def cast(self, type_name, address):
        """
        Cast an arbitrary memory address to a DWARF C-type object.
        Example: libc.cast('malloc_chunk', 0x55555555b000).fd
        """
        self._build_dwarf_cache()
        type_die_offset = self._dwarf_types.get(type_name)
        if not type_die_offset:
            raise ValueError(f"Struct/Type '{type_name}' not found in DWARF info.")
        return DWARFAddress(address, self, type_die_offset)

    def craft(self, type_name):
        """
        Creates a byte-backed structure that allows assigning C-fields dynamically.
        Use bytes(obj) to extract the raw crafted payload.

        Example:
            chunk = libc.craft('malloc_chunk')
            chunk.size = 0x21
            chunk.fd = 0xdeadbeef
            payload = bytes(chunk)
        """
        self._build_dwarf_cache()
        type_die_offset = self._dwarf_types.get(type_name)
        if not type_die_offset:
            raise ValueError(f"Struct/Type '{type_name}' not found in DWARF info.")
        return DWARFCrafter(self, type_die_offset)

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

        tokens = []
        for part in field_path.replace(']', '').split('['):
            for subpart in part.split('.'):
                if subpart:
                    try:
                        tokens.append(int(subpart))
                    except ValueError:
                        tokens.append(subpart)

        self._build_dwarf_cache()

        dwarfinfo = self._get_dwarfinfo()
        start_die_offset = None

        if struct_name:
            start_die_offset = self._dwarf_types.get(struct_name)
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

        current_die = dwarfinfo.get_DIE_from_refaddr(start_die_offset)
        offset_accumulator = 0
        subrange_start = 0

        for token in tokens:
            current_die = self._unwrap_type(current_die)

            if current_die.tag == 'DW_TAG_pointer_type':
                log.error(f"Cannot statically resolve through a pointer at token '{token}'.")
                return None

            if isinstance(token, int):
                if current_die.tag != 'DW_TAG_array_type':
                    log.error(f"Expected array type for index '{token}', got {current_die.tag}")
                    return None

                subranges = self._get_array_subranges(current_die)
                remaining = subranges[subrange_start:]

                elem_type = self._unwrap_type(self._get_die_from_attr(current_die, 'DW_AT_type'))
                elem_size = self._get_byte_size(elem_type)

                stride = elem_size
                for dim in remaining[1:]:
                    stride *= dim

                offset_accumulator += token * stride

                if len(remaining) <= 1:
                    current_die = elem_type
                    subrange_start = 0
                else:
                    subrange_start += 1
            else:
                subrange_start = 0

                if current_die.tag not in ('DW_TAG_structure_type', 'DW_TAG_union_type'):
                    log.error(f"Expected struct/union for field '{token}', got {current_die.tag}")
                    return None

                result = self._find_member(current_die, token)
                if result is None:
                    log.error(f"Field '{token}' not found in struct.")
                    return None

                offset_accumulator += result[0]
                current_die = result[1]

        return base_addr + offset_accumulator


class CHeader(ExtendedELF):
    """
    Takes a C header file, automatically compiles it into a temporary ELF
    with DWARF symbols via GCC, and wraps it in an ExtendedELF interface.

    Accepts optional include_dirs for headers that #include other files.
    Pass bits=32 to compile for 32-bit targets (defaults to host architecture).
    """
    def __init__(self, header_path, include_dirs=None, bits=None, **kwargs):
        header_path = os.path.abspath(header_path)
        if not os.path.exists(header_path):
            raise FileNotFoundError(f"Header file not found: {header_path}")

        with open(header_path, 'rb') as f:
            header_data = f.read()

        host_bits = struct.calcsize('P') * 8
        if bits is None:
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
