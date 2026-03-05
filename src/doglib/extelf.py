import os
import re
import json
import hashlib
import subprocess
import struct
from pwn import *
from elftools.elf.elffile import ELFFile

# Extension to pwntools ELF -- see docs/extelf.md for full documentation.
# Quick examples:
'''
libc = ExtendedELF('./libc.so.6')
libc.address = 0x7ffff7a00000  # PIE slides are automatically respected dynamically!
target_fd = libc.sym_obj['main_arena'].bins[3].fd

# Cast addresses as C types
chunk_struct = libc.cast('malloc_chunk', 0x55555555b000)
log.info(f"Size field is at: {hex(chunk_struct.size)}")

# Craft structs
chunk = libc.craft("malloc_chunk")
chunk.fd = 0x123456789
payload = bytes(chunk)

# Parse leaked data back into structs
leaked = io.recv(libc.sizeof('malloc_chunk'))
chunk = libc.parse('malloc_chunk', leaked)
log.info(f"fd = {hex(chunk.fd.value)}")

# Compile C headers directly
structs = CHeader("custom_structs.h")
structs.sizeof('MyStruct')
structs.offsetof('MyStruct', 'field')
structs.describe('MyStruct')

# Enum constants
state = structs.enum('State')
chunk.current_state = state.CRASHED
'''
# been generally battle-tested, see tests/extelf


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

    def __repr__(self):
        try:
            dwarfinfo = self._elf._get_dwarfinfo()
            die = dwarfinfo.get_DIE_from_refaddr(self._type_die_offset)
            type_name = self._elf._get_type_name(die)
        except Exception:
            type_name = '?'
        return f"<DWARFAddress {hex(int(self))} type={type_name}>"

    def __add__(self, other):
        mask = (1 << self._elf.bits) - 1
        return DWARFAddress((int(self) + int(other)) & mask, self._elf, self._type_die_offset, self._subrange_start)

    def __radd__(self, other):
        return self.__add__(other)

    def __sub__(self, other):
        if isinstance(other, DWARFAddress):
            return int.__sub__(self, other)
        mask = (1 << self._elf.bits) - 1
        return DWARFAddress((int(self) - int(other)) & mask, self._elf, self._type_die_offset, self._subrange_start)

    def __getattr__(self, name):
        if name.startswith('_'):
            raise AttributeError(name)

        dwarfinfo = self._elf._get_dwarfinfo()
        die = dwarfinfo.get_DIE_from_refaddr(self._type_die_offset)
        current_die = self._elf._unwrap_type(die)
        mask = (1 << self._elf.bits) - 1

        if current_die.tag == 'DW_TAG_pointer_type':
            log.error(f"Cannot statically resolve through a pointer at '.{name}'. Dereference first.")
            raise AttributeError(name)

        if current_die.tag not in ('DW_TAG_structure_type', 'DW_TAG_union_type'):
            raise AttributeError(f"Type {current_die.tag} is not a struct/union. Cannot access '.{name}'")

        result = self._elf._find_member(current_die, name)
        if result is None:
            raise AttributeError(f"Field '{name}' not found in struct")

        member_offset, next_type_die = result
        return DWARFAddress((int(self) + member_offset) & mask, self._elf, next_type_die.offset)

    def __getitem__(self, index):
        if not isinstance(index, int):
            raise TypeError("Array indices must be integers")

        dwarfinfo = self._elf._get_dwarfinfo()
        die = dwarfinfo.get_DIE_from_refaddr(self._type_die_offset)
        current_die = self._elf._unwrap_type(die)
        mask = (1 << self._elf.bits) - 1

        if current_die.tag == 'DW_TAG_pointer_type':
            pointed = self._elf._get_die_from_attr(current_die, 'DW_AT_type')
            if pointed:
                pointed = self._elf._unwrap_type(pointed)
                elem_size = self._elf._get_byte_size(pointed)
                new_addr = (int(self) + index * elem_size) & mask
                return DWARFAddress(new_addr, self._elf, pointed.offset)
            elem_size = self._elf.bits // 8
            return (int(self) + index * elem_size) & mask

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

        new_addr = (int(self) + index * stride) & mask

        if len(remaining) == 1:
            return DWARFAddress(new_addr, self._elf, elem_type.offset)
        return DWARFAddress(new_addr, self._elf, current_die.offset, self._subrange_start + 1)


class DWARFArray:
    """
    A virtual array of DWARFAddress elements for address math.
    Supports multi-dimensional indexing and unbounded pointer-style arrays.
    Created via cast('Foo[4][8]', addr), cast('Foo', addr, count=N),
    or cast('Foo *', addr) for unbounded.
    """
    def __init__(self, base, elf, elem_type_offset, dims):
        self._base = base
        self._elf = elf
        self._elem_type_offset = elem_type_offset
        self._dims = (dims,) if isinstance(dims, int) else tuple(dims)
        self._mask = (1 << elf.bits) - 1
        die = elf._get_dwarfinfo().get_DIE_from_refaddr(elem_type_offset)
        self._elem_size = elf._get_byte_size(die)

    def _inner_count(self):
        result = 1
        for d in self._dims[1:]:
            if d is None:
                return 1
            result *= d
        return result

    def __getitem__(self, index):
        if isinstance(index, slice):
            if self._dims[0] is None:
                raise TypeError("Cannot slice an unbounded pointer array. Use integer indices.")
            return [self[i] for i in range(*index.indices(self._dims[0]))]
        if not isinstance(index, int):
            raise TypeError("Array indices must be integers")
        inner = self._inner_count()
        addr = (self._base + index * inner * self._elem_size) & self._mask
        if len(self._dims) > 1:
            return DWARFArray(addr, self._elf, self._elem_type_offset, self._dims[1:])
        return DWARFAddress(addr, self._elf, self._elem_type_offset)

    def __len__(self):
        if self._dims[0] is None:
            raise TypeError("Pointer arrays have no fixed length")
        return self._dims[0]

    def __iter__(self):
        if self._dims[0] is None:
            raise TypeError("Cannot iterate over an unbounded pointer array")
        for i in range(self._dims[0]):
            yield self[i]

    def __repr__(self):
        die = self._elf._get_dwarfinfo().get_DIE_from_refaddr(self._elem_type_offset)
        type_name = self._elf._get_type_name(die)
        if self._dims == (None,):
            return f"<DWARFArray {hex(self._base)} type={type_name}*>"
        dims_str = ''.join(f'[{d}]' for d in self._dims)
        return f"<DWARFArray {hex(self._base)} type={type_name}{dims_str}>"


class DWARFEnum:
    """
    Provides named access to enum constants from DWARF debug info.
    Supports attribute access, 'in' checks, and iteration.
    """
    def __init__(self, elf, type_die_offset):
        self._elf = elf
        self._type_die_offset = type_die_offset
        self._constants = {}
        dwarfinfo = elf._get_dwarfinfo()
        die = dwarfinfo.get_DIE_from_refaddr(type_die_offset)
        die = elf._unwrap_type(die)
        if die and die.tag == 'DW_TAG_enumeration_type':
            for child in die.iter_children():
                if child.tag == 'DW_TAG_enumerator':
                    name_attr = child.attributes.get('DW_AT_name')
                    val_attr = child.attributes.get('DW_AT_const_value')
                    if name_attr and val_attr:
                        self._constants[name_attr.value.decode('utf-8')] = val_attr.value

    def __getattr__(self, name):
        if name.startswith('_'):
            raise AttributeError(name)
        if name in self._constants:
            return self._constants[name]
        raise AttributeError(f"Enum constant '{name}' not found")

    def __contains__(self, name):
        return name in self._constants

    def __iter__(self):
        return iter(self._constants.items())

    def __repr__(self):
        return f"<DWARFEnum {self._constants}>"


class DWARFCrafter:
    """
    A mutable byte-array wrapper that allows C-style struct member assignments.
    Supports multi-dimensional array indexing, slice assignment, and sub-struct assignment.
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
        end = self._offset + self._size
        # Root views (offset 0) expose any OOB-extended backing so callers see what was written.
        if self._offset == 0 and len(self._backing) > end:
            end = len(self._backing)
        return bytes(self._backing[self._offset : end])

    def __len__(self):
        return self._size

    def __repr__(self):
        try:
            dwarfinfo = self._elf._get_dwarfinfo()
            die = dwarfinfo.get_DIE_from_refaddr(self._type_die_offset)
            current_die = self._elf._unwrap_type(die)
            type_name = self._elf._get_type_name(die)

            if current_die.tag == 'DW_TAG_base_type':
                v = self.value
                if isinstance(v, float):
                    return f"<{type_name} {v!r}>"
                if isinstance(v, bool):
                    return f"<{type_name} {v}>"
                if isinstance(v, int) and v < 0:
                    return f"<{type_name} {v}>"
                return f"<{type_name} {hex(v)}>"

            if current_die.tag == 'DW_TAG_pointer_type':
                return f"<{type_name} {hex(int.from_bytes(bytes(self), 'little' if self._elf.little_endian else 'big', signed=False))}>"

            if current_die.tag == 'DW_TAG_enumeration_type':
                return f"<{type_name} {hex(self.value)}>"

            if current_die.tag in ('DW_TAG_structure_type', 'DW_TAG_union_type'):
                parts = []
                for child in current_die.iter_children():
                    if child.tag != 'DW_TAG_member':
                        continue
                    name_attr = child.attributes.get('DW_AT_name')
                    if not name_attr:
                        continue
                    field_name = name_attr.value.decode('utf-8')
                    field_type_die = self._elf._get_die_from_attr(child, 'DW_AT_type')
                    if not field_type_die:
                        continue
                    field_unwrapped = self._elf._unwrap_type(field_type_die)
                    # Skip large/array fields to keep repr manageable
                    if field_unwrapped and field_unwrapped.tag == 'DW_TAG_array_type':
                        total = self._elf._get_byte_size(field_unwrapped)
                        dims = self._elf._get_array_subranges(field_unwrapped)
                        dims_str = ''.join(f'[{d}]' for d in dims)
                        parts.append(f"{field_name}=<array{dims_str}>")
                        continue
                    field_size = self._elf._get_byte_size(field_unwrapped) if field_unwrapped else 0
                    if field_size > 16:
                        parts.append(f"{field_name}=<{self._elf._get_type_name(field_type_die)}>")
                        continue
                    offset = self._elf._parse_member_offset(child)
                    sub = DWARFCrafter(self._elf, field_type_die.offset, self._backing, self._offset + offset)
                    parts.append(f"{field_name}={repr(sub)}")
                body = ', '.join(parts)
                return f"<{type_name} {{{body}}}>"

            if current_die.tag == 'DW_TAG_array_type':
                dims = self._elf._get_array_subranges(current_die)
                dims_str = ''.join(f'[{d}]' for d in dims[self._subrange_start:])
                return f"<array{dims_str} size={self._size}>"
        except Exception:
            pass
        hex_data = bytes(self).hex()
        preview = hex_data[:32] + ('...' if len(hex_data) > 32 else '')
        return f"<DWARFCrafter size={self._size} data={preview}>"

    def __index__(self):
        """Return the unsigned integer interpretation of this field's bytes.
        This ensures p64/p32/hex/etc always work. Use .value for signed."""
        raw = bytes(self._backing[self._offset : self._offset + self._size])
        dwarfinfo = self._elf._get_dwarfinfo()
        die = dwarfinfo.get_DIE_from_refaddr(self._type_die_offset)
        current_die = self._elf._unwrap_type(die)
        if current_die.tag in ('DW_TAG_base_type', 'DW_TAG_pointer_type', 'DW_TAG_enumeration_type'):
            byte_order = 'little' if self._elf.little_endian else 'big'
            return int.from_bytes(raw, byteorder=byte_order, signed=False)
        raise TypeError(f"Cannot convert {current_die.tag} to int (struct/union types have no single integer value; use bytes() for raw data)")

    def __int__(self):
        return self.__index__()

    def __float__(self):
        v = self.value
        if isinstance(v, float):
            return v
        if isinstance(v, int):
            return float(v)
        raise TypeError(f"Cannot convert {type(v).__name__} to float (struct/union types have no single numeric value; use bytes() for raw data)")

    def _numeric_value(self):
        v = self.value
        if isinstance(v, (int, float)):
            return v
        raise TypeError(f"Cannot perform arithmetic on {type(v).__name__} (struct/union types have no single numeric value)")

    # gross but seemingly no better solution
    def __add__(self, other):      return self._numeric_value() + other
    def __radd__(self, other):     return other + self._numeric_value()
    def __sub__(self, other):      return self._numeric_value() - other
    def __rsub__(self, other):     return other - self._numeric_value()
    def __mul__(self, other):      return self._numeric_value() * other
    def __rmul__(self, other):     return other * self._numeric_value()
    def __truediv__(self, other):  return self._numeric_value() / other
    def __rtruediv__(self, other): return other / self._numeric_value()
    def __floordiv__(self, other): return self._numeric_value() // other
    def __rfloordiv__(self, other):return other // self._numeric_value()
    def __mod__(self, other):      return self._numeric_value() % other
    def __rmod__(self, other):     return other % self._numeric_value()
    def __neg__(self):             return -self._numeric_value()
    def __pos__(self):             return +self._numeric_value()
    def __abs__(self):             return abs(self._numeric_value())
    def __lt__(self, other):       return self._numeric_value() < other
    def __le__(self, other):       return self._numeric_value() <= other
    def __eq__(self, other):       return self._numeric_value() == other
    def __ne__(self, other):       return self._numeric_value() != other
    def __gt__(self, other):       return self._numeric_value() > other
    def __ge__(self, other):       return self._numeric_value() >= other
    def __hash__(self):            return hash(self._numeric_value())

    def __and__(self, other):      return self._numeric_value() & other
    def __rand__(self, other):     return other & self._numeric_value()
    def __or__(self, other):       return self._numeric_value() | other
    def __ror__(self, other):      return other | self._numeric_value()
    def __xor__(self, other):      return self._numeric_value() ^ other
    def __rxor__(self, other):     return other ^ self._numeric_value()
    def __lshift__(self, other):   return self._numeric_value() << other
    def __rlshift__(self, other):  return other << self._numeric_value()
    def __rshift__(self, other):   return self._numeric_value() >> other
    def __rrshift__(self, other):  return other >> self._numeric_value()
    def __invert__(self):          return ~self._numeric_value()
    def __pow__(self, other):      return self._numeric_value() ** other
    def __rpow__(self, other):     return other ** self._numeric_value()
    def __divmod__(self, other):   return divmod(self._numeric_value(), other)
    def __rdivmod__(self, other):  return divmod(other, self._numeric_value())
    def __bool__(self):            return bool(self._numeric_value())
    def __round__(self, n=None):   return round(self._numeric_value(), n)
    def __trunc__(self):
        import math; return math.trunc(self._numeric_value())
    def __floor__(self):
        import math; return math.floor(self._numeric_value())
    def __ceil__(self):
        import math; return math.ceil(self._numeric_value())

    def __format__(self, format_spec):
        v = self.value
        if isinstance(v, (int, float, bool)):
            return format(v, format_spec)
        return format(bytes(self).hex(), format_spec)

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
                if enc == 0x02:  # DW_ATE_boolean
                    return bool(int.from_bytes(raw, byteorder=byte_order, signed=False))
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

        if absolute_offset < 0:
            raise IndexError(f"Negative offset {absolute_offset} would write before the backing buffer. "
                             "Use craft(..., pad=N) or a larger struct to include the target region.")

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

        end = absolute_offset + size
        if end > len(self._backing):
            needed = end - len(self._backing)
            log.warning(f"OOB write at offset {absolute_offset} extends backing by {needed} bytes (struct is {len(self._backing)} bytes). "
                        "Use craft(..., pad=N) to pre-allocate extra space.")
            self._backing.extend(b'\x00' * needed)
        self._backing[absolute_offset : end] = val_bytes

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

    def _current_array_length(self):
        """Get the current dimension's length for slice support."""
        dwarfinfo = self._elf._get_dwarfinfo()
        die = dwarfinfo.get_DIE_from_refaddr(self._type_die_offset)
        current_die = self._elf._unwrap_type(die)
        if current_die.tag != 'DW_TAG_array_type':
            raise TypeError("Cannot slice a non-array type")
        subranges = self._elf._get_array_subranges(current_die)
        remaining = subranges[self._subrange_start:]
        if not remaining:
            raise TypeError("No array dimensions available")
        return remaining[0]

    def __getattr__(self, name):
        if name.startswith('_'):
            raise AttributeError(name)
        member_offset, member_type_die = self._resolve_field(name)
        return DWARFCrafter(self._elf, member_type_die.offset, self._backing, self._offset + member_offset)

    def __setattr__(self, name, value):
        if name.startswith('_'):
            return super().__setattr__(name, value)
        if name == 'value':
            die = self._elf._get_dwarfinfo().get_DIE_from_refaddr(self._type_die_offset)
            self._write_value(0, die, value)
            return
        member_offset, member_type_die = self._resolve_field(name)
        self._write_value(member_offset, member_type_die, value)

    def __iter__(self):
        try:
            length = self._current_array_length()
        except TypeError:
            raise TypeError("Cannot iterate over a non-array DWARFCrafter")
        for i in range(length):
            yield self[i]

    def _check_crafter_offset(self, absolute_offset):
        if absolute_offset < 0:
            raise IndexError(f"Negative index would access offset {absolute_offset}, before the backing buffer.")

    def __getitem__(self, index):
        if isinstance(index, slice):
            length = self._current_array_length()
            return [self[i] for i in range(*index.indices(length))]
        elem_offset, type_die, sub_start = self._resolve_index(index)
        abs_off = self._offset + elem_offset
        self._check_crafter_offset(abs_off)
        return DWARFCrafter(self._elf, type_die.offset, self._backing, abs_off, sub_start)

    def __setitem__(self, index, value):
        if isinstance(index, slice):
            length = self._current_array_length()
            for i, idx in enumerate(range(*index.indices(length))):
                if i < len(value):
                    self[idx] = value[i]
            return
        elem_offset, type_die, sub_start = self._resolve_index(index)
        self._write_value(elem_offset, type_die, value, sub_start)

    def __contains__(self, name):
        """Check whether a named field exists in this struct/union."""
        try:
            self._resolve_field(name)
            return True
        except AttributeError:
            return False

    def items(self):
        """
        Yield (field_name, DWARFCrafter) pairs for each direct member.
        Only works on struct/union types.

        Example:
            for name, field in chunk.items():
                print(name, field.value)
        """
        dwarfinfo = self._elf._get_dwarfinfo()
        die = dwarfinfo.get_DIE_from_refaddr(self._type_die_offset)
        current_die = self._elf._unwrap_type(die)
        if current_die.tag not in ('DW_TAG_structure_type', 'DW_TAG_union_type'):
            raise TypeError(f"items() only works on struct/union types, not {current_die.tag}")
        for child in current_die.iter_children():
            if child.tag != 'DW_TAG_member':
                continue
            name_attr = child.attributes.get('DW_AT_name')
            if not name_attr:
                continue
            field_name = name_attr.value.decode('utf-8')
            field_type_die = self._elf._get_die_from_attr(child, 'DW_AT_type')
            if not field_type_die:
                continue
            offset = self._elf._parse_member_offset(child)
            yield field_name, DWARFCrafter(self._elf, field_type_die.offset, self._backing, self._offset + offset)

    def dump(self):
        """
        Pretty-print all struct fields and their current values.
        Skips array fields with more than 8 elements to avoid flooding output.

        Example:
            chunk = libc.parse('malloc_chunk', leak)
            chunk.dump()
        """
        dwarfinfo = self._elf._get_dwarfinfo()
        die = dwarfinfo.get_DIE_from_refaddr(self._type_die_offset)
        current_die = self._elf._unwrap_type(die)
        if current_die.tag not in ('DW_TAG_structure_type', 'DW_TAG_union_type'):
            raise TypeError(f"dump() only works on struct/union types, not {current_die.tag}")
        type_name = self._elf._get_type_name(die)
        print(f"{type_name}:")
        for field_name, field in self.items():
            field_die = dwarfinfo.get_DIE_from_refaddr(field._type_die_offset)
            field_unwrapped = self._elf._unwrap_type(field_die)
            if field_unwrapped and field_unwrapped.tag == 'DW_TAG_array_type':
                total = self._elf._get_byte_size(field_unwrapped)
                dims = self._elf._get_array_subranges(field_unwrapped)
                dims_str = ''.join(f'[{d}]' for d in dims)
                elem_type = self._elf._get_die_from_attr(field_unwrapped, 'DW_AT_type')
                elem_name = self._elf._get_type_name(elem_type) if elem_type else '?'
                total_elems = 1
                for d in dims:
                    total_elems *= d
                if total_elems <= 8:
                    def _fmt_val(v):
                        if isinstance(v, list):
                            return '[' + ', '.join(_fmt_val(x) for x in v) + ']'
                        if isinstance(v, float):
                            return repr(v)
                        if isinstance(v, int) and v < 0:
                            return str(v)
                        if isinstance(v, int):
                            return hex(v)
                        return repr(v)
                    def _collect_vals(crafter, remaining_dims):
                        if len(remaining_dims) == 1:
                            return [el.value for el in crafter]
                        return [_collect_vals(el, remaining_dims[1:]) for el in crafter]
                    nested = _collect_vals(field, dims)
                    print(f"  {field_name}: {elem_name}{dims_str} = {_fmt_val(nested)}")
                else:
                    print(f"  {field_name}: {elem_name}{dims_str} ({total} bytes)")
            else:
                v = field.value
                if isinstance(v, bool):
                    print(f"  {field_name} = {v}")
                elif isinstance(v, int) and v < 0:
                    print(f"  {field_name} = {v}")
                elif isinstance(v, int):
                    print(f"  {field_name} = {hex(v)}")
                elif isinstance(v, float):
                    print(f"  {field_name} = {v!r}")
                else:
                    print(f"  {field_name} = {bytes(field).hex()}")

    def copy(self):
        """
        Return an independent copy of this crafter with its own backing buffer.

        Example:
            original = libc.parse('malloc_chunk', leak)
            modified = original.copy()
            modified.fd = 0xdeadbeef
            # original is unchanged
        """
        new_backing = bytearray(self._backing)
        return DWARFCrafter(self._elf, self._type_die_offset, new_backing, self._offset, self._subrange_start)

    def fill(self, value):
        """
        Fill the backing region of this crafter with a repeated byte value (memset-style).
        value must be an int 0-255, or bytes/bytearray (which will be repeated to fill).

        Example:
            chunk = libc.craft('malloc_chunk')
            chunk.fill(0x41)   # fill all bytes with 'A'
            chunk.fill(b'\\xcc')
        """
        if isinstance(value, int):
            if not 0 <= value <= 255:
                raise ValueError(f"fill() byte value must be 0-255, got {value}")
            pattern = bytes([value])
        elif isinstance(value, (bytes, bytearray)):
            if not value:
                raise ValueError("fill() pattern cannot be empty")
            pattern = bytes(value)
        else:
            raise TypeError(f"fill() expects int (0-255) or bytes, got {type(value).__name__}")
        size = self._size
        filled = (pattern * (size // len(pattern) + 1))[:size]
        self._backing[self._offset : self._offset + size] = filled

    def cyclic(self, n=None):
        """
        Fill the backing region with pwntools cyclic() output.
        n defaults to the full size of the crafter.

        Example:
            chunk = libc.craft('malloc_chunk')
            chunk.cyclic()
            bytes(chunk)  # b'aaaabaaacaaa...'
        """
        from pwn import cyclic as pwn_cyclic
        size = n if n is not None else self._size
        data = pwn_cyclic(size)
        self._backing[self._offset : self._offset + size] = data


class DWARFArrayCrafter:
    """
    A byte-backed array of elements of a single type.
    Supports multi-dimensional indexing with shared backing buffer.
    Created via craft('Foo[4][8]') or craft('Foo', count=N).
    """
    def __init__(self, elf, type_die_offset, dims, backing=None, base_offset=0):
        self._elf = elf
        self._type_die_offset = type_die_offset
        self._dims = (dims,) if isinstance(dims, int) else tuple(dims)
        self._base_offset = base_offset
        die = elf._get_dwarfinfo().get_DIE_from_refaddr(type_die_offset)
        self._elem_size = elf._get_byte_size(die)
        total_elems = 1
        for d in self._dims:
            total_elems *= d
        self._total_bytes = self._elem_size * total_elems
        self._backing = backing if backing is not None else bytearray(self._total_bytes)

    def _inner_count(self):
        result = 1
        for d in self._dims[1:]:
            result *= d
        return result

    def __getitem__(self, index):
        if isinstance(index, slice):
            return [self[i] for i in range(*index.indices(self._dims[0]))]
        if not isinstance(index, int):
            raise TypeError("Array indices must be integers")
        inner = self._inner_count()
        offset = self._base_offset + index * inner * self._elem_size
        if offset < 0:
            raise IndexError(f"Negative index would access offset {offset}, before the backing buffer.")
        if len(self._dims) > 1:
            return DWARFArrayCrafter(self._elf, self._type_die_offset, self._dims[1:],
                                     backing=self._backing, base_offset=offset)
        return DWARFCrafter(self._elf, self._type_die_offset, self._backing, offset)

    def __setitem__(self, index, value):
        if isinstance(index, slice):
            for i, idx in enumerate(range(*index.indices(self._dims[0]))):
                if i < len(value):
                    self[idx] = value[i]
            return
        if isinstance(value, (int, float)):
            sub = self[index]
            if isinstance(sub, DWARFArrayCrafter):
                sub.fill(value)
            else:
                sub.value = value
            return
        inner = self._inner_count()
        offset = self._base_offset + index * inner * self._elem_size
        chunk_size = inner * self._elem_size
        if isinstance(value, (DWARFCrafter, DWARFArrayCrafter, bytes, bytearray)):
            raw = bytes(value)
        else:
            raise TypeError("Assign int, float, DWARFCrafter, DWARFArrayCrafter, bytes, or bytearray")
        size = min(len(raw), chunk_size)
        end = offset + size
        if end > len(self._backing):
            needed = end - len(self._backing)
            log.warning(f"OOB write at offset {offset} extends backing by {needed} bytes. "
                        "Use craft(..., pad=N) to pre-allocate extra space.")
            self._backing.extend(b'\x00' * needed)
        self._backing[offset : end] = raw[:size]

    def __len__(self):
        return self._dims[0]

    def __iter__(self):
        for i in range(self._dims[0]):
            yield self[i]

    def __bytes__(self):
        start = self._base_offset
        end = start + self._total_bytes
        # Root views (base_offset 0) expose any OOB-extended backing so callers see what was written.
        if start == 0 and len(self._backing) > end:
            end = len(self._backing)
        return bytes(self._backing[start : end])

    def __repr__(self):
        die = self._elf._get_dwarfinfo().get_DIE_from_refaddr(self._type_die_offset)
        type_name = self._elf._get_type_name(die)
        dims_str = ''.join(f'[{d}]' for d in self._dims)
        return f"<DWARFArrayCrafter {type_name}{dims_str} size={self._total_bytes}>"

    def values(self):
        """
        Return a (nested) list of Python primitive values for all elements.
        For multi-dimensional arrays, returns nested lists.

        Example:
            arr = headers.parse('int[4]', data)
            arr.values()  # [1, 2, 3, 4]

            grid = headers.parse('int[2][3]', data)
            grid.values()  # [[1, 2, 3], [4, 5, 6]]
        """
        if len(self._dims) == 1:
            return [elem.value for elem in self]
        return [self[i].values() for i in range(self._dims[0])]

    def fill(self, value):
        """
        Set all elements to the given value.

        Example:
            arr = headers.craft('int[8]')
            arr.fill(0)
            arr.fill(0x41)
        """
        for i in range(self._dims[0]):
            self[i] = value

    def cyclic(self, n=None):
        """
        Fill the backing region with pwntools cyclic() output.
        n defaults to the full size of the array.

        Example:
            arr = headers.craft('int[8]')
            arr.cyclic()
            bytes(arr)  # b'aaaabaaacaaa...'
        """
        from pwn import cyclic as pwn_cyclic
        size = n if n is not None else self._total_bytes
        data = pwn_cyclic(size)
        self._backing[self._base_offset : self._base_offset + size] = data

    def copy(self):
        """
        Return an independent copy of this array crafter with its own backing buffer.

        Example:
            original = headers.parse('int[8]', data)
            modified = original.copy()
            modified[0] = 0xdeadbeef
            # original[0] is unchanged
        """
        new_backing = bytearray(self._backing)
        return DWARFArrayCrafter(self._elf, self._type_die_offset, self._dims,
                                 backing=new_backing, base_offset=self._base_offset)


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

        if die.tag in ('DW_TAG_structure_type', 'DW_TAG_union_type'):
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

                if current_die.tag not in ('DW_TAG_structure_type', 'DW_TAG_union_type'):
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

        _CACHE_VERSION = 2

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
        dwarfinfo = self._get_dwarfinfo()
        if not dwarfinfo:
            log.warning("ELF has no DWARF info. Path resolution won't work.")
            self._dwarf_parsed = True
            return

        cacheable_tags = (
            'DW_TAG_variable', 'DW_TAG_structure_type', 'DW_TAG_union_type',
            'DW_TAG_typedef', 'DW_TAG_enumeration_type', 'DW_TAG_base_type',
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

    def _get_type_die(self, type_name):
        """Look up a type by name and return its DIE. Raises ValueError if not found."""
        self._build_dwarf_cache()
        type_die_offset = self._resolve_type_name(type_name)
        if type_die_offset is None:
            raise ValueError(f"Type '{type_name}' not found in DWARF info.")
        return self._get_dwarfinfo().get_DIE_from_refaddr(type_die_offset)

    def cast(self, type_name, address, count=None):
        """
        Cast an arbitrary memory address to a DWARF C-type object.
        Supports array syntax and pointer syntax in the type name.

        Example:
            libc.cast('malloc_chunk', 0x55555555b000).fd
            libc.cast('Bar', arr_addr, count=64)[3].field
            libc.cast('int[4][8]', matrix_addr)[1][2]
            libc.cast('int *', heap_base)[520292]
        """
        self._build_dwarf_cache()
        base_name, parsed_dims, ptr_depth = self._parse_type_string(type_name)
        type_die_offset = self._resolve_type_name(base_name)
        if type_die_offset is None:
            raise ValueError(f"Struct/Type '{base_name}' not found in DWARF info.")
        if ptr_depth > 0:
            if ptr_depth > 1:
                raise ValueError(
                    f"Multi-level pointer ('{'*' * ptr_depth}') not supported in cast. "
                    "Use 'unsigned long *' to treat as an array of pointer-sized values."
                )
            return DWARFArray(address, self, type_die_offset, (None,))
        dims = parsed_dims
        if dims is None and count is not None:
            dims = count if isinstance(count, tuple) else (count,)
        if dims is not None:
            return DWARFArray(address, self, type_die_offset, dims)
        return DWARFAddress(address, self, type_die_offset)

    def craft(self, type_name, count=None, pad=0):
        """
        Creates a zeroed byte-backed structure for assigning C-fields dynamically.
        Use bytes(obj) to extract the raw crafted payload.
        Supports array syntax: craft('Bar[64]') or craft('Bar', count=64).
        Pass pad=N to add N extra bytes for intentional OOB writes.

        Example:
            chunk = libc.craft('malloc_chunk')
            chunk.size = 0x21
            payload = bytes(chunk)

            arr = headers.craft('Foo[4][8]')
            arr[1][2].field = 42
            bytes(arr)

            # OOB-capable crafting for exploitation
            arr = headers.craft('int[5][6]', pad=64)
            arr[4][6] = 0xdeadbeef  # one past the end, no warning
        """
        self._build_dwarf_cache()
        base_name, parsed_dims, ptr_depth = self._parse_type_string(type_name)
        if ptr_depth > 0:
            raise ValueError("Cannot craft a pointer type. Use craft('type[N]') for arrays.")
        type_die_offset = self._resolve_type_name(base_name)
        if type_die_offset is None:
            raise ValueError(f"Struct/Type '{base_name}' not found in DWARF info.")
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
        Supports array and pointer syntax.
        Example: headers.sizeof('int[100]') -> 400
                 headers.sizeof('int *') -> 8 (on 64-bit)
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

        Example:
            headers.describe('FinalBoss')
        """
        die = self._get_type_die(type_name)
        unwrapped = self._unwrap_type(die)
        if not unwrapped or unwrapped.tag not in ('DW_TAG_structure_type', 'DW_TAG_union_type'):
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
                if unwrapped and unwrapped.tag in ('DW_TAG_structure_type', 'DW_TAG_union_type'):
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


# ---- built-in C type environment ----------------------------------------

# CHeader with every standard C type
class CTypes(CHeader):
    def __init__(self, bits=None):
        from importlib.resources import files
        header_src = files('doglib.data').joinpath('ctypes_builtin.h')
        super().__init__(str(header_src), bits=bits)


_CTYPES_SINGLETONS = {}


def __getattr__(name):
    if name in ('C', 'C32', 'C64'):
        inst = _CTYPES_SINGLETONS.get(name)
        if inst is None:
            if name == 'C':
                inst = CTypes()
            elif name == 'C32':
                inst = CTypes(bits=32)
            else:  # 'C64'
                inst = CTypes(bits=64)
            _CTYPES_SINGLETONS[name] = inst
        return inst
    raise AttributeError(name)
