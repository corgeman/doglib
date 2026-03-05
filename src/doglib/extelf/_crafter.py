import os
import re
import struct
from pwnlib.log import getLogger
from pwnlib.util.cyclic import cyclic as _pwn_cyclic

log = getLogger(__name__)

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

    def _struct_tag(self):
        """Return the unwrapped DWARF tag string for this crafter's type."""
        die = self._elf._get_dwarfinfo().get_DIE_from_refaddr(self._type_die_offset)
        return self._elf._unwrap_type(die).tag

    # ------------------------------------------------------------------ #
    #  Arithmetic / comparison operators                                   #
    # ------------------------------------------------------------------ #

    def __add__(self, other):
        """struct + struct of the same type → DWARFArrayCrafter of 2 elements.
        All other cases fall through to numeric addition."""
        if (isinstance(other, DWARFCrafter)
                and other._type_die_offset == self._type_die_offset
                and self._struct_tag() in ('DW_TAG_structure_type', 'DW_TAG_union_type')):
            combined = bytearray(bytes(self)) + bytearray(bytes(other))
            return DWARFArrayCrafter(self._elf, self._type_die_offset, (2,), backing=combined)
        return self._numeric_value() + other

    def __radd__(self, other):
        """other + self — mirrors __add__ for the struct-concatenation case.
        Python calls __radd__ when other.__add__(self) returns NotImplemented,
        which includes the subclass-priority rule where self is a subclass of other."""
        if (isinstance(other, DWARFCrafter)
                and other._type_die_offset == self._type_die_offset
                and self._struct_tag() in ('DW_TAG_structure_type', 'DW_TAG_union_type')):
            combined = bytearray(bytes(other)) + bytearray(bytes(self))
            return DWARFArrayCrafter(self._elf, self._type_die_offset, (2,), backing=combined)
        return other + self._numeric_value()
    def __sub__(self, other):      return self._numeric_value() - other
    def __rsub__(self, other):     return other - self._numeric_value()

    def __mul__(self, n):
        """struct * int → DWARFArrayCrafter of n independent copies.
        All other cases fall through to numeric multiplication."""
        if isinstance(n, int) and self._struct_tag() in ('DW_TAG_structure_type', 'DW_TAG_union_type'):
            if n < 0:
                raise ValueError("Repetition count must be non-negative")
            return DWARFArrayCrafter(self._elf, self._type_die_offset, (n,),
                                     backing=bytearray(bytes(self) * n))
        return self._numeric_value() * n

    def __rmul__(self, n):         return self.__mul__(n)
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

    def __eq__(self, other):
        try:
            return self._numeric_value() == other
        except TypeError:
            if isinstance(other, (DWARFCrafter, bytes, bytearray)):
                return bytes(self) == bytes(other)
            return NotImplemented

    def __ne__(self, other):
        result = self.__eq__(other)
        return result if result is NotImplemented else not result

    def __gt__(self, other):       return self._numeric_value() > other
    def __ge__(self, other):       return self._numeric_value() >= other

    # Struct/union/array types are mutable, so hashing them is intentionally
    # unsupported — mutating an object after using it as a dict key silently
    # breaks lookup semantics.  Primitive/enum/pointer fields remain hashable.
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
    def __bool__(self):
        try:
            return bool(self._numeric_value())
        except TypeError:
            return any(self._backing[self._offset : self._offset + self._size])
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
            if isinstance(index, str):
                raise TypeError(
                    f"String key {index!r} reached _resolve_index — use "
                    "crafter['fieldname'] for field access by name."
                )
            raise TypeError(f"Array indices must be integers, not {type(index).__name__}")

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
        # True Python dunders (__foo__) are not forwarded to DWARF field lookup —
        # they signal Python protocol queries (e.g. __len__, __iter__).
        # Use crafter['__foo__'] to read a C field whose name looks like a dunder.
        if name.startswith('__') and name.endswith('__'):
            raise AttributeError(name)
        try:
            member_offset, member_type_die = self._resolve_field(name)
        except AttributeError:
            raise AttributeError(name)
        return DWARFCrafter(self._elf, member_type_die.offset, self._backing, self._offset + member_offset)

    def __setattr__(self, name, value):
        # True Python dunders (__foo__) are stored on the Python object, not the
        # backing buffer.  Use crafter['__foo__'] = v to write to a C field whose
        # name looks like a dunder.  Fields shadowed by Python attributes (e.g.
        # 'value', 'items') are likewise accessible via crafter['fieldname'] = v.
        if name.startswith('__') and name.endswith('__'):
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
        if isinstance(index, str):
            # Escape hatch: crafter['fieldname'] bypasses __getattr__ guards,
            # giving explicit access to fields whose names collide with Python
            # attributes ('value', 'items', 'copy', ...) or look like dunders
            # ('__init__', '__foo__', etc.).
            try:
                member_offset, member_type_die = self._resolve_field(index)
            except AttributeError as e:
                raise KeyError(index) from e
            return DWARFCrafter(self._elf, member_type_die.offset, self._backing,
                                self._offset + member_offset)
        if isinstance(index, slice):
            length = self._current_array_length()
            return [self[i] for i in range(*index.indices(length))]
        elem_offset, type_die, sub_start = self._resolve_index(index)
        abs_off = self._offset + elem_offset
        self._check_crafter_offset(abs_off)
        return DWARFCrafter(self._elf, type_die.offset, self._backing, abs_off, sub_start)

    def __setitem__(self, index, value):
        if isinstance(index, str):
            # Escape hatch — mirrors __getitem__ string-key behaviour.
            try:
                member_offset, member_type_die = self._resolve_field(index)
            except AttributeError as e:
                raise KeyError(index) from e
            self._write_value(member_offset, member_type_die, value)
            return
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
        size = n if n is not None else self._size
        data = _pwn_cyclic(size)
        self._backing[self._offset : self._offset + size] = data

    def values(self):
        """
        Return the value(s) held by this crafter:
        - Primitive / enum / pointer field → the Python scalar (.value)
        - Array field (DW_TAG_array_type) → nested list of element values,
          matching the shape of the array (same as DWARFArrayCrafter.values())
        - Struct / union → dict mapping each field name to its values()

        Example:
            chunk.fd.values()             # 0xdeadbeef  (int)
            boss.matrix.values()          # [[1,2,3],[4,5,6]]
            chunk.values()                # {'prev_size': 0, 'size': 0x21, ...}
        """
        dwarfinfo = self._elf._get_dwarfinfo()
        die = dwarfinfo.get_DIE_from_refaddr(self._type_die_offset)
        current_die = self._elf._unwrap_type(die)
        if current_die.tag in ('DW_TAG_base_type', 'DW_TAG_pointer_type', 'DW_TAG_enumeration_type'):
            return self.value
        if current_die.tag == 'DW_TAG_array_type':
            length = self._current_array_length()
            return [self[i].values() for i in range(length)]
        if current_die.tag in ('DW_TAG_structure_type', 'DW_TAG_union_type'):
            return {name: field.values() for name, field in self.items()}
        return bytes(self)

    def index(self, value, start=0, stop=None):
        """
        Return the index of the first element equal to value.
        Only works on array-typed DWARFCrafter fields (DW_TAG_array_type).
        Raises TypeError if called on a non-array type.
        Raises ValueError if the value is not found.

        Example:
            boss.arr.index(42)
            boss.arr.index(42, 2)   # search from index 2
        """
        length = self._current_array_length()
        if stop is None:
            stop = length
        for i in range(start, stop):
            child = self[i]
            if isinstance(value, (int, float)) and child.value == value:
                return i
            if isinstance(value, (bytes, bytearray)) and bytes(child) == bytes(value):
                return i
            if isinstance(value, DWARFCrafter) and bytes(child) == bytes(value):
                return i
        raise ValueError(f"{value!r} is not in array")

    def count(self, value):
        """
        Count how many elements equal value.
        Only works on array-typed DWARFCrafter fields (DW_TAG_array_type).
        Raises TypeError if called on a non-array type.

        Example:
            boss.arr.count(0)
        """
        length = self._current_array_length()
        total = 0
        for i in range(length):
            child = self[i]
            if isinstance(value, (int, float)) and child.value == value:
                total += 1
            elif isinstance(value, (bytes, bytearray)) and bytes(child) == bytes(value):
                total += 1
            elif isinstance(value, DWARFCrafter) and bytes(child) == bytes(value):
                total += 1
        return total


class DWARFArrayCrafter:
    """
    A byte-backed array of elements of a single type.
    Supports multi-dimensional indexing with shared backing buffer.
    Created via craft('Foo[4][8]') or craft('Foo', count=N).
    Separate from DWARFCrafter because this is not a real type in the DWARF info,
    we must forge it ourselves. We could technically compile the array type and read
    that DWARF info but that is debatably not a good idea.
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
        if isinstance(value, (list, tuple)):
            sub = self[index]
            if isinstance(sub, DWARFArrayCrafter):
                for i, v in enumerate(value):
                    sub[i] = v
            else:
                sub.value = value[0] if value else 0
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
        size = n if n is not None else self._total_bytes
        data = _pwn_cyclic(size)
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

    # ------------------------------------------------------------------ #
    #  List-like methods                                                   #
    # ------------------------------------------------------------------ #

    def _leaf_values(self):
        """Yield all leaf element values depth-first (used for deep __contains__)."""
        if len(self._dims) == 1:
            for i in range(self._dims[0]):
                yield self[i].value
        else:
            for i in range(self._dims[0]):
                yield from self[i]._leaf_values()

    def _child_equals(self, child, value):
        """Return True if a direct child element matches value."""
        if isinstance(child, DWARFCrafter):
            if isinstance(value, (int, float)):
                return child.value == value
            if isinstance(value, (bytes, bytearray)):
                return bytes(child) == bytes(value)
            return False
        if isinstance(child, DWARFArrayCrafter):
            return child == value
        return False

    def __contains__(self, value):
        """
        For scalar (int/float) values, performs a deep search across all leaf
        elements, so ``42 in int_grid[3][3]`` works as expected.
        For structured values (list, bytes, DWARFArrayCrafter), checks direct
        children only, matching Python list semantics.

        Example:
            arr = C64.craft('int[4]')
            arr[2] = 99
            99 in arr   # True
            0  in arr   # True  (other elements are 0)

            grid = C64.craft('int[2][3]')
            grid[1] = [7, 8, 9]
            7 in grid          # True  (deep scan)
            [7,8,9] in grid    # True  (row match)
        """
        if isinstance(value, (int, float)):
            return any(v == value for v in self._leaf_values())
        for i in range(self._dims[0]):
            if self._child_equals(self[i], value):
                return True
        return False

    def __eq__(self, other):
        """
        Compare element-wise.  Accepts DWARFArrayCrafter, bytes/bytearray, or
        a plain list/tuple (compared recursively against direct children).

        Example:
            arr = C64.craft('int[3]')
            arr[0] = 1; arr[1] = 2; arr[2] = 3
            arr == [1, 2, 3]   # True
        """
        if isinstance(other, DWARFArrayCrafter):
            if self._dims != other._dims:
                return False
            return bytes(self) == bytes(other)
        if isinstance(other, (bytes, bytearray)):
            return bytes(self) == bytes(other)
        if isinstance(other, (list, tuple)):
            if len(other) != self._dims[0]:
                return False
            return all(self._child_equals(self[i], other[i]) for i in range(self._dims[0]))
        return NotImplemented

    def __ne__(self, other):
        result = self.__eq__(other)
        return result if result is NotImplemented else not result

    def __add__(self, other):
        """
        Concatenate two arrays of the same element type along the outermost
        dimension, returning a new independent copy.

        Example:
            a = C64.craft('int[3]')
            b = C64.craft('int[2]')
            c = a + b   # DWARFArrayCrafter int[5]
        """
        if not isinstance(other, DWARFArrayCrafter):
            return NotImplemented
        if self._type_die_offset != other._type_die_offset or self._dims[1:] != other._dims[1:]:
            raise TypeError("Cannot concatenate arrays with different element types or inner dimensions")
        new_dims = (self._dims[0] + other._dims[0],) + self._dims[1:]
        my_bytes = bytes(self._backing[self._base_offset : self._base_offset + self._total_bytes])
        other_bytes = bytes(other._backing[other._base_offset : other._base_offset + other._total_bytes])
        return DWARFArrayCrafter(self._elf, self._type_die_offset, new_dims,
                                 backing=bytearray(my_bytes + other_bytes))

    def __iadd__(self, other):
        """``arr += other`` — returns a new concatenated array (same semantics as __add__)."""
        return self.__add__(other)

    def __mul__(self, n):
        """
        Repeat this array n times along the outermost dimension, returning a
        new independent copy.  Each repetition is a fresh copy of the bytes,
        so mutations to the result do not alias each other.

        Example:
            a = C64.craft('int[3]')
            a[0] = 1
            b = a * 3   # DWARFArrayCrafter int[9]; b[0]==b[3]==b[6]==1
            b[0] = 99   # does not affect b[3] or b[6]
        """
        if not isinstance(n, int):
            return NotImplemented
        if n < 0:
            raise ValueError("Repetition count must be non-negative")
        new_dims = (self._dims[0] * n,) + self._dims[1:]
        my_bytes = bytes(self._backing[self._base_offset : self._base_offset + self._total_bytes])
        return DWARFArrayCrafter(self._elf, self._type_die_offset, new_dims,
                                 backing=bytearray(my_bytes * n))

    def __rmul__(self, n):
        """``3 * arr`` — same as ``arr * 3``."""
        return self.__mul__(n)

    def index(self, value, start=0, stop=None):
        """
        Return the index of the first direct child equal to value.
        For 1D arrays compares element .value to an int/float.
        For multi-D arrays compares sub-arrays via __eq__.
        Raises ValueError if not found.

        Example:
            arr = C64.craft('int[5]')
            arr[2] = 42
            arr.index(42)   # 2

            grid = C64.craft('int[3][2]')
            grid[1] = [10, 20]
            grid.index([10, 20])   # 1
        """
        if stop is None:
            stop = self._dims[0]
        for i in range(start, stop):
            if self._child_equals(self[i], value):
                return i
        raise ValueError(f"{value!r} is not in array")

    def count(self, value):
        """
        Count how many direct children equal value.
        For 1D arrays compares element .value to an int/float.
        For multi-D arrays compares sub-arrays via __eq__.

        Example:
            arr = C64.craft('int[6]')
            arr[0] = 5; arr[3] = 5
            arr.count(5)   # 2
        """
        return sum(1 for i in range(self._dims[0]) if self._child_equals(self[i], value))

