"""
DWARFResolver: pure DWARF interpretation logic, separated from ELF loading/caching.
"""
from pwnlib.log import getLogger

from ._constants import PASSTHROUGH_TAGS, STRUCT_TAGS, dims_str

log = getLogger(__name__)


def _decode_uleb128(data):
    """Decode a ULEB128 value from a sequence of bytes."""
    val, shift = 0, 0
    for b in data:
        val |= (b & 0x7f) << shift
        if (b & 0x80) == 0:
            break
        shift += 7
    return val


class DWARFResolver:
    """
    Interprets DWARF DIE trees. Holds (dwarfinfo, bits) for type resolution.
    """
    def __init__(self, dwarfinfo, bits):
        self._dwarfinfo = dwarfinfo
        self._bits = bits

    def get_die_from_attr(self, die, attr_name):
        """Follow DWARF type references (e.g., DW_AT_type)."""
        if attr_name not in die.attributes:
            return None
        attr = die.attributes[attr_name]
        offset = attr.value

        if attr.form in ('DW_FORM_ref1', 'DW_FORM_ref2', 'DW_FORM_ref4', 'DW_FORM_ref8', 'DW_FORM_ref_udata'):
            offset += die.cu.cu_offset

        return die.cu.dwarfinfo.get_DIE_from_refaddr(offset)

    def unwrap_type(self, die):
        """Strip typedefs, const, volatile, restrict, and _Atomic modifiers."""
        while die and die.tag in PASSTHROUGH_TAGS:
            die = self.get_die_from_attr(die, 'DW_AT_type')
        return die

    def parse_member_offset(self, member_die):
        """Parse DW_AT_data_member_location from a member DIE."""
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
                return _decode_uleb128(expr[1:])

            if op == 0x10:  # DW_OP_constu
                return _decode_uleb128(expr[1:])

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

    def find_member(self, struct_die, name):
        """
        Find a member by name in a struct/union/class DIE. Recurses into
        anonymous struct/union members and base classes.
        Returns (offset, type_die) or None.
        """
        for child in struct_die.iter_children():
            if child.tag == 'DW_TAG_member':
                name_attr = child.attributes.get('DW_AT_name')
                if name_attr and name_attr.value.decode('utf-8') == name:
                    offset = self.parse_member_offset(child)
                    type_die = self.get_die_from_attr(child, 'DW_AT_type')
                    if not type_die:
                        return None
                    return (offset, type_die)

                if not name_attr:
                    anon_type = self.get_die_from_attr(child, 'DW_AT_type')
                    if anon_type:
                        anon_unwrapped = self.unwrap_type(anon_type)
                        if anon_unwrapped and anon_unwrapped.tag in STRUCT_TAGS:
                            result = self.find_member(anon_unwrapped, name)
                            if result:
                                anon_offset = self.parse_member_offset(child)
                                return (anon_offset + result[0], result[1])

            elif child.tag == 'DW_TAG_inheritance':
                base_type = self.get_die_from_attr(child, 'DW_AT_type')
                if base_type:
                    base_unwrapped = self.unwrap_type(base_type)
                    if base_unwrapped:
                        result = self.find_member(base_unwrapped, name)
                        if result:
                            base_offset = self.parse_member_offset(child)
                            return (base_offset + result[0], result[1])

        return None

    def get_array_subranges(self, array_die):
        """Extract dimension sizes from a DWARF array type's subrange children."""
        dims = []
        for child in array_die.iter_children():
            if child.tag == 'DW_TAG_subrange_type':
                if 'DW_AT_count' in child.attributes:
                    dims.append(child.attributes['DW_AT_count'].value)
                elif 'DW_AT_upper_bound' in child.attributes:
                    dims.append(child.attributes['DW_AT_upper_bound'].value + 1)
        return dims

    def get_byte_size(self, die, subrange_start=0):
        """Recursively determine the byte size of a DWARF type."""
        die = self.unwrap_type(die)
        if not die:
            log.warning("Could not determine byte size for type (None die)")
            return 0

        if die.tag == 'DW_TAG_array_type':
            elem_type = self.unwrap_type(self.get_die_from_attr(die, 'DW_AT_type'))
            elem_size = self.get_byte_size(elem_type)
            subranges = self.get_array_subranges(die)
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
            return self._bits // 8

        if die.tag == 'DW_TAG_enumeration_type':
            return 4

        log.warning(f"Could not determine byte size for DWARF tag {die.tag}")
        return 0

    def get_type_name(self, die):
        """Get a human-readable type name string from a DWARF DIE."""
        if not die:
            return 'void'

        if die.tag == 'DW_TAG_typedef':
            name = die.attributes.get('DW_AT_name')
            if name:
                return name.value.decode('utf-8')

        die = self.unwrap_type(die)
        if not die:
            return 'void'

        if die.tag == 'DW_TAG_base_type':
            name = die.attributes.get('DW_AT_name')
            return name.value.decode('utf-8') if name else 'unknown'

        if die.tag == 'DW_TAG_pointer_type':
            pointee = self.get_die_from_attr(die, 'DW_AT_type')
            return self.get_type_name(pointee) + '*'

        if die.tag == 'DW_TAG_array_type':
            elem = self.get_die_from_attr(die, 'DW_AT_type')
            return self.get_type_name(elem) + dims_str(self.get_array_subranges(die))

        if die.tag in STRUCT_TAGS:
            if die.tag == 'DW_TAG_union_type':
                prefix = 'union'
            elif die.tag == 'DW_TAG_class_type':
                prefix = 'class'
            else:
                prefix = 'struct'
            name = die.attributes.get('DW_AT_name')
            return f"{prefix} {name.value.decode('utf-8')}" if name else f"<anon {prefix}>"

        if die.tag == 'DW_TAG_enumeration_type':
            name = die.attributes.get('DW_AT_name')
            return f"enum {name.value.decode('utf-8')}" if name else '<anon enum>'

        return '?'
