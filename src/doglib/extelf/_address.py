import re
import struct
from pwn import *

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
        if name.startswith('__') and name.endswith('__'):
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

