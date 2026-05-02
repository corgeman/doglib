import os
import re
import json
import stat
import hashlib
import struct
from pwnlib.log import getLogger
from pwnlib.context import context
from elftools.elf.elffile import ELFFile

try:
    from doglib_rs import dwarf_parser as _dwarf_parser_rs
except ImportError:
    _dwarf_parser_rs = None

log = getLogger(__name__)

from ._address import DWARFAddress, DWARFArray
from ._constants import CACHEABLE_TAGS, STRUCT_TAGS, array_stride, dims_str, va_mask
from ._crafter import DWARFCrafter, DWARFArrayCrafter
from ._enum import DWARFEnum
from ._resolver import DWARFResolver


class ORC:
    """
    DWARF-powered C type toolkit. Parses debug information from ELF binaries
    to provide struct crafting, parsing, casting, and type introspection.
    """
    _CACHE_VERSION = 8

    # DIE references stored in the DWARF cache / on DWARFAddress / DWARFCrafter
    # etc. are 2-tuples: (die_offset, source) where source is 0 for the main
    # binary's .debug_info or 1 for a supplementary file (.dwz / .debug_sup).
    # JSON serializes these as [offset, source]; list-vs-tuple is immaterial to
    # consumers, which only index the pair.
    _SRC_MAIN = 0
    _SRC_SUP = 1

    def __init__(self, path: str | os.PathLike, bits=None):
        self.path = os.path.abspath(path)
        with open(self.path, 'rb') as f:
            elffile = ELFFile(f)
            self.little_endian = elffile.little_endian
            self.bits = bits if bits is not None else elffile.elfclass
            self.buildid = self._read_buildid(elffile)
        self._dwarf_vars = {}
        self._dwarf_types = {}
        self._dwarf_parsed = False
        self._dwarf_file = None
        self._dwarfinfo = None
        self._resolver = None

    @staticmethod
    def _read_buildid(elffile):
        """Extract GNU build-id from an ELF file, or None."""
        section = elffile.get_section_by_name('.note.gnu.build-id')
        if section:
            return section.data()[16:]
        return None

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

    def __getitem__(self, type_name):
        """
        Shortcut for cast(type_name, 0). Useful for quickly computing field
        offsets via attribute and array access — the returned DWARFAddress
        is an int subclass, so its value IS the offset.

        Example:
            headers['FinalBoss'].matrix          # -> 8
            headers['FinalBoss'].matrix[1][2]    # -> 28
            headers['BossFight'].u.data.raw      # -> 32
        """
        return self.cast(type_name, 0)

    def _get_dwarfinfo(self):
        """Lazy-loads and caches the DWARF info to avoid reopening the file repeatedly."""
        if self._dwarfinfo is None:
            self._dwarf_file = open(self.path, 'rb')
            elffile = ELFFile(self._dwarf_file)
            if elffile.has_dwarf_info():
                self._dwarfinfo = elffile.get_dwarf_info()
                sup = self._load_supplementary(elffile)
                if sup is not None:
                    self._dwarfinfo.supplementary_dwarfinfo = sup
        return self._dwarfinfo

    def _load_supplementary(self, elffile):
        """
        Load the supplementary DWARF file referenced by a .debug_sup (DWARF 5)
        or .gnu_debugaltlink (GNU extension) section, if one is present.

        Returns a DWARFInfo, or None if the supplementary file is unavailable.
        """
        sup_filename = self._dwarfinfo.parse_debugsupinfo()
        if sup_filename is None:
            return None
        if isinstance(sup_filename, bytes):
            sup_filename = sup_filename.decode('utf-8', errors='replace')

        candidates = [sup_filename]
        if not os.path.isabs(sup_filename):
            candidates.append(os.path.join(os.path.dirname(self.path), sup_filename))

        for candidate in candidates:
            try:
                # Skip non-regular files so we don't hang on FIFOs or read
                # arbitrarily-large data from device nodes.
                if not stat.S_ISREG(os.stat(candidate).st_mode):
                    continue
                with open(candidate, 'rb') as sup_f:
                    sup_elf = ELFFile(sup_f)
                    if not sup_elf.has_dwarf_info():
                        continue
                    # All section data is copied into BytesIO by pyelftools, so
                    # the file can be closed after get_dwarf_info() returns.
                    return sup_elf.get_dwarf_info()
            except OSError:
                continue

        return None

    def _ref(self, die):
        """Return a (offset, source) tuple identifying *die* across main/sup DWARFInfo objects.

        All code that stores a DIE for later retrieval must use this instead of
        die.offset, so _get_die can route the lookup to the correct DWARFInfo.
        """
        dwarfinfo = self._get_dwarfinfo()
        sup = getattr(dwarfinfo, 'supplementary_dwarfinfo', None)
        if sup is not None and die.cu.dwarfinfo is sup:
            return (die.offset, self._SRC_SUP)
        return (die.offset, self._SRC_MAIN)

    def _get_die(self, ref):
        """Resolve a (offset, source) DieRef to a pyelftools DIE."""
        offset, src = ref
        dwarfinfo = self._get_dwarfinfo()
        if src == self._SRC_SUP:
            return dwarfinfo.supplementary_dwarfinfo.get_DIE_from_refaddr(offset)
        return dwarfinfo.get_DIE_from_refaddr(offset)

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
          'Foo[2][3]' -> ('Foo', (2, 3), 0)
          'int *'     -> ('int', None, 1)
          'Foo **'    -> ('Foo', None, 2)
          'Foo'       -> ('Foo', None, 0)
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

        orc_cache_dir = os.path.join(context.cache_dir, 'orc_cache')
        os.makedirs(orc_cache_dir, exist_ok=True)

        if self.buildid:
            bid = self.buildid.hex()
        else:
            with open(self.path, 'rb') as f:
                bid = hashlib.sha256(f.read()).hexdigest()[:16]

        cache_file = os.path.join(orc_cache_dir, f"dwarf_{bid}.json")

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

        sup = getattr(dwarfinfo, 'supplementary_dwarfinfo', None)

        def _index_dwarfinfo(di, src):
            for CU in di.iter_CUs():
                for die in CU.iter_DIEs():
                    if die.tag not in CACHEABLE_TAGS:
                        continue
                    name_attr = die.attributes.get('DW_AT_name')
                    if not name_attr:
                        continue
                    is_decl = die.attributes.get('DW_AT_declaration')
                    if is_decl and is_decl.value:
                        continue
                    name_val = name_attr.value
                    if isinstance(name_val, int):
                        # DW_FORM_GNU_strp_alt / DW_FORM_strp_sup: the name
                        # lives in the supplementary .debug_str table.
                        if sup is None:
                            continue
                        try:
                            name_val = sup.get_string_from_table(name_val)
                        except Exception:
                            continue
                    if not isinstance(name_val, bytes):
                        continue
                    name = name_val.decode('utf-8', errors='ignore')
                    ref = (die.offset, src)
                    if die.tag == 'DW_TAG_variable':
                        self._dwarf_vars[name] = ref
                    else:
                        self._dwarf_types[name] = ref

        _index_dwarfinfo(dwarfinfo, self._SRC_MAIN)
        if sup is not None:
            _index_dwarfinfo(sup, self._SRC_SUP)

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
            ref = self._resolve_type_name(type_name)
            if ref is None:
                raise ValueError(f"Type '{type_name}' not found in DWARF info.")
            return 0, self._get_die(ref)

        base_name = type_name[:dot]
        field_path = type_name[dot + 1:]

        base_ref = self._resolve_type_name(base_name)
        if base_ref is None:
            raise ValueError(f"Type '{base_name}' not found in DWARF info.")
        base_die = self._get_die(base_ref)

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
            type_die_offset = self._ref(field_die)
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
        type_die_offset = self._ref(field_die)
        dims = parsed_dims
        if dims is None and count is not None:
            dims = count if isinstance(count, tuple) else (count,)
        if dims is None:
            unwrapped = self._unwrap_type(field_die)
            if unwrapped and unwrapped.tag == 'DW_TAG_array_type':
                dims = tuple(self._get_array_subranges(unwrapped))
                elem_die = self._get_die_from_attr(unwrapped, 'DW_AT_type')
                if elem_die and dims:
                    type_die_offset = self._ref(elem_die)
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
        return DWARFEnum(self, self._ref(die))

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

    def offsetof(self, type_name, field_path=None):
        """
        Get the byte offset of a field within a struct.
        Supports dotted paths and array indices.

        Can be called with a single combined path or two separate args. The
        2-arg form is convenient when the field name is computed at runtime.

        Example:
            headers.offsetof('FinalBoss.matrix')           -> 8
            headers.offsetof('FinalBoss', 'matrix')        -> 8
            headers.offsetof('FinalBoss.matrix[1][2]')     -> 28
            headers.offsetof('FinalBoss', 'matrix[1][2]')  -> 28
            headers.offsetof('BossFight.u.data.raw')       -> 24
            headers.offsetof('BossFight', 'u.data.raw')    -> 24
        """
        if field_path is None:
            dot = type_name.find('.')
            if dot == -1:
                raise ValueError(
                    f"offsetof('{type_name}') needs a field path. "
                    f"Pass 'Type.field' or use offsetof('Type', 'field')."
                )
            type_name, field_path = type_name[:dot], type_name[dot + 1:]
        die = self._get_type_die(type_name)
        tokens = self._tokenize_path(field_path)
        offset, _ = self._walk_field_path(die, tokens)
        return offset

    def _walk_offset_to_paths(self, die, offset):
        """
        Recursively find which field of `die` lives at byte `offset`.
        Returns a list of path strings (each starting with '.', '[', or '+').
        Multiple entries only appear when traversing a union with overlapping
        members. Bitfield members are skipped; pointers are treated as opaque
        scalars (no dereferencing).
        """
        die = self._unwrap_type(die)
        if die is None:
            raise ValueError("Could not resolve type DIE")

        size = self._get_byte_size(die)
        if size <= 0:
            raise ValueError(f"Cannot determine size of type {self._get_type_name(die)}")
        if offset < 0 or offset >= size:
            raise ValueError(
                f"Offset {offset} is outside type {self._get_type_name(die)} (size {size})"
            )

        if die.tag == 'DW_TAG_array_type':
            subranges = self._get_array_subranges(die)
            elem_die = self._unwrap_type(self._get_die_from_attr(die, 'DW_AT_type'))
            elem_size = self._get_byte_size(elem_die)
            if elem_size <= 0 or not subranges:
                return [f'+{offset}']

            strides = [0] * len(subranges)
            s = elem_size
            for i in range(len(subranges) - 1, -1, -1):
                strides[i] = s
                s *= subranges[i]

            indices = ''
            rem = offset
            for st in strides:
                idx, rem = divmod(rem, st)
                indices += f'[{idx}]'

            sub_paths = self._walk_offset_to_paths(elem_die, rem)
            return [indices + p for p in sub_paths]

        if die.tag == 'DW_TAG_union_type':
            results = []
            for child in die.iter_children():
                if child.tag != 'DW_TAG_member':
                    continue
                if ('DW_AT_bit_size' in child.attributes
                        or 'DW_AT_data_bit_offset' in child.attributes):
                    continue
                mtype = self._get_die_from_attr(child, 'DW_AT_type')
                if mtype is None:
                    continue
                msize = self._get_byte_size(mtype)
                if msize <= 0 or offset >= msize:
                    continue
                try:
                    sub = self._walk_offset_to_paths(mtype, offset)
                except ValueError:
                    continue
                name_attr = child.attributes.get('DW_AT_name')
                prefix = '.' + name_attr.value.decode('utf-8') if name_attr else ''
                results.extend(prefix + p for p in sub)
            return results if results else [f'+{offset}']

        if die.tag in ('DW_TAG_structure_type', 'DW_TAG_class_type'):
            for child in die.iter_children():
                if child.tag == 'DW_TAG_inheritance':
                    base = self._get_die_from_attr(child, 'DW_AT_type')
                    if base is None:
                        continue
                    bo = self._parse_member_offset(child)
                    bs = self._get_byte_size(base)
                    if bs > 0 and bo <= offset < bo + bs:
                        return self._walk_offset_to_paths(base, offset - bo)
                    continue
                if child.tag != 'DW_TAG_member':
                    continue
                if ('DW_AT_bit_size' in child.attributes
                        or 'DW_AT_data_bit_offset' in child.attributes):
                    continue
                mtype = self._get_die_from_attr(child, 'DW_AT_type')
                if mtype is None:
                    continue
                moff = self._parse_member_offset(child)
                msize = self._get_byte_size(mtype)
                if msize <= 0 or not (moff <= offset < moff + msize):
                    continue
                sub = self._walk_offset_to_paths(mtype, offset - moff)
                name_attr = child.attributes.get('DW_AT_name')
                prefix = '.' + name_attr.value.decode('utf-8') if name_attr else ''
                return [prefix + p for p in sub]
            return [f'+{offset}']

        return [''] if offset == 0 else [f'+{offset}']

    def field_at(self, type_name, offset):
        """
        Reverse of offsetof(): given a struct type and a byte offset, return
        the field path that lives at that offset.

        Walks nested structs, multi-dim arrays, unions, anonymous members,
        and base classes. If the offset lands mid-field (e.g. byte 3 of an
        int), the result is suffixed with '+N' where N is the byte offset
        within that field. A bare '+N' is returned when the offset lands in
        struct padding.

        For unions where multiple members overlap the offset, returns a list
        of all valid paths. Otherwise returns a single string.

        Bitfields are skipped; pointers are treated as opaque scalars.

        Example:
            headers.field_at('FinalBoss', 28)     -> 'matrix[1][2]'
            headers.field_at('Basic', 5)          -> 'b+1'
            headers.field_at('UnionMadness', 12)
                -> ['data.coords.y', 'data.raw[4]']
        """
        die = self._get_type_die(type_name)
        paths = self._walk_offset_to_paths(die, offset)
        cleaned = [p[1:] if p.startswith('.') else p for p in paths]
        if len(cleaned) == 1:
            return cleaned[0]
        return cleaned

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
        ptr_depth = 0
        if unwrapped and unwrapped.tag == 'DW_TAG_array_type':
            dims = self._get_array_subranges(unwrapped)
            array_suffix = dims_str(dims)
            elem_die = self._get_die_from_attr(unwrapped, 'DW_AT_type')
            if elem_die:
                unwrapped = self._unwrap_type(elem_die)

        while unwrapped and unwrapped.tag == 'DW_TAG_pointer_type':
            ptr_depth += 1
            pointee = self._get_die_from_attr(unwrapped, 'DW_AT_type')
            unwrapped = self._unwrap_type(pointee) if pointee else None

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
        if ptr_depth:
            size_label += f", pointee of {'*' * ptr_depth}"
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
