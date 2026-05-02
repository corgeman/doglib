import re
import struct
from pwnlib.log import getLogger

from ._constants import STRUCT_TAGS, array_stride, va_mask, inner_count, dims_str

log = getLogger(__name__)

class DWARFAddress(int):
    """
    An integer subclass representing a memory address that retains its C-type.
    Allows attribute access (obj.field) and indexing (obj[index]),
    including multi-dimensional array indexing (arr[1][2]).
    """
    def __new__(cls, value, orc, type_die_offset, subrange_start=0):
        obj = super().__new__(cls, value)
        obj._orc = orc
        obj._type_die_offset = type_die_offset
        obj._subrange_start = subrange_start
        return obj

    def __repr__(self):
        try:
            die = self._orc._get_die(self._type_die_offset)
            type_name = self._orc._get_type_name(die)
        except Exception:
            type_name = '?'
        return f"<DWARFAddress {hex(int(self))} type={type_name}>"

    def __add__(self, other):
        return DWARFAddress((int(self) + int(other)) & va_mask(self._orc.bits), self._orc, self._type_die_offset, self._subrange_start)

    def __radd__(self, other):
        return self.__add__(other)

    def __sub__(self, other):
        if isinstance(other, DWARFAddress):
            return int.__sub__(self, other)
        return DWARFAddress((int(self) - int(other)) & va_mask(self._orc.bits), self._orc, self._type_die_offset, self._subrange_start)

    def __getattr__(self, name):
        if name.startswith('__') and name.endswith('__'):
            raise AttributeError(name)

        die = self._orc._get_die(self._type_die_offset)
        current_die = self._orc._unwrap_type(die)
        mask = va_mask(self._orc.bits)

        if current_die.tag == 'DW_TAG_pointer_type':
            log.warning(f"Cannot statically resolve through a pointer at '.{name}'. Dereference first.")
            raise AttributeError(name)

        if current_die.tag not in STRUCT_TAGS:
            raise AttributeError(f"Type {current_die.tag} is not a struct/union. Cannot access '.{name}'")

        result = self._orc._find_member(current_die, name)
        if result is None:
            raise AttributeError(f"Field '{name}' not found in struct")

        member_offset, next_type_die = result
        return DWARFAddress((int(self) + member_offset) & mask, self._orc, self._orc._ref(next_type_die))

    def __dir__(self):
        names = set(super().__dir__())
        die = self._orc._get_die(self._type_die_offset)
        current_die = self._orc._unwrap_type(die)
        if current_die and current_die.tag in STRUCT_TAGS:
            names.update(self._orc._member_names(current_die))
        return sorted(names)

    def __getitem__(self, index):
        if not isinstance(index, int):
            raise TypeError("Array indices must be integers")

        die = self._orc._get_die(self._type_die_offset)
        current_die = self._orc._unwrap_type(die)
        mask = va_mask(self._orc.bits)

        if current_die.tag == 'DW_TAG_pointer_type':
            pointed = self._orc._get_die_from_attr(current_die, 'DW_AT_type')
            if pointed:
                pointed = self._orc._unwrap_type(pointed)
                elem_size = self._orc._get_byte_size(pointed)
                new_addr = (int(self) + index * elem_size) & mask
                return DWARFAddress(new_addr, self._orc, self._orc._ref(pointed))
            elem_size = self._orc.bits // 8
            return (int(self) + index * elem_size) & mask

        if current_die.tag != 'DW_TAG_array_type':
            raise TypeError(f"Cannot index into non-array type {current_die.tag}")

        subranges = self._orc._get_array_subranges(current_die)
        if not subranges[self._subrange_start:]:
            raise TypeError("No more array dimensions to index")

        stride, elem_type, remaining_len = array_stride(self._orc, current_die, self._subrange_start)
        new_addr = (int(self) + index * stride) & mask

        if remaining_len <= 1:
            return DWARFAddress(new_addr, self._orc, self._orc._ref(elem_type))
        return DWARFAddress(new_addr, self._orc, self._orc._ref(current_die), self._subrange_start + 1)


class DWARFArray:
    """
    A virtual array of DWARFAddress elements for address math.
    Supports multi-dimensional indexing and unbounded pointer-style arrays.
    Created via cast('Foo[4][8]', addr), cast('Foo', addr, count=N),
    or cast('Foo *', addr) for unbounded.
    """
    def __init__(self, base, orc, elem_type_offset, dims):
        self._base = base
        self._orc = orc
        self._elem_type_offset = elem_type_offset
        self._dims = (dims,) if isinstance(dims, int) else tuple(dims)
        self._mask = va_mask(orc.bits)
        die = orc._get_die(elem_type_offset)
        self._elem_size = orc._get_byte_size(die)

    def _inner_count(self):
        return inner_count(self._dims)

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
            return DWARFArray(addr, self._orc, self._elem_type_offset, self._dims[1:])
        return DWARFAddress(addr, self._orc, self._elem_type_offset)

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
        die = self._orc._get_die(self._elem_type_offset)
        type_name = self._orc._get_type_name(die)
        if self._dims == (None,):
            return f"<DWARFArray {hex(self._base)} type={type_name}*>"
        return f"<DWARFArray {hex(self._base)} type={type_name}{dims_str(self._dims)}>"
