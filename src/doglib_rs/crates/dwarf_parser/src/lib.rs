use gimli::RunTimeEndian;
use object::{Object, ObjectSection};
use pyo3::prelude::*;
use std::collections::HashMap;
use std::sync::Arc;

// ── Relocation support ────────────────────────────────────────────────────────
//
// gimli provides `RelocateReader<R, T>`, a Reader wrapper that transparently
// applies ELF relocations when gimli reads addresses and offsets.  This is
// the official API for handling ET_REL object files (like the .o files
// produced by ORCHeader / ORCInline), where DW_FORM_strp values in .debug_info
// are zero-filled placeholders whose real .debug_str offsets live as
// relocation entries.
//
// We use `object::read::RelocationMap` (from the `object` crate) to collect
// and resolve relocations per-section.  Its `add(file, offset, reloc)` method
// does proper symbol table resolution internally, so we don't need to handle
// symbol lookups or relocation types ourselves.
//
// For linked binaries (ET_EXEC / ET_DYN) there are no relocations, so the
// map is empty and RelocateReader is a transparent pass-through with no
// overhead.

#[derive(Debug, Clone, Default)]
struct Relocs(Arc<object::read::RelocationMap>);

impl gimli::read::Relocate<usize> for Relocs {
    fn relocate_address(&self, offset: usize, value: u64) -> gimli::Result<u64> {
        Ok(self.0.relocate(offset as u64, value))
    }

    fn relocate_offset(&self, offset: usize, value: usize) -> gimli::Result<usize> {
        <usize as gimli::ReaderOffset>::from_u64(self.0.relocate(offset as u64, value as u64))
    }
}

type R = gimli::RelocateReader<gimli::EndianArcSlice<RunTimeEndian>, Relocs>;

// ── DIE source tags ───────────────────────────────────────────────────────────
//
// DIE offsets in .debug_info are numbered from zero in both the main binary
// and any supplementary file, so the raw numbers overlap.  We return each
// (offset, source) as a pair; `source` matches _SRC_MAIN / _SRC_SUP on the
// Python side so the consumer can route get_DIE_from_refaddr to the right
// DWARFInfo.
const SRC_MAIN: u8 = 0;
const SRC_SUP: u8 = 1;

// ── DWARF tags we record ──────────────────────────────────────────────────────

const TYPE_TAGS: &[gimli::DwTag] = &[
    gimli::DW_TAG_structure_type,
    gimli::DW_TAG_class_type,
    gimli::DW_TAG_union_type,
    gimli::DW_TAG_typedef,
    gimli::DW_TAG_enumeration_type,
    gimli::DW_TAG_base_type,
];

// ── Section loading ───────────────────────────────────────────────────────────

fn load_section(obj: &object::File, name: &str, endian: RunTimeEndian) -> R {
    let (data, relocs) = match obj.section_by_name(name) {
        Some(ref section) => {
            let data = section
                .uncompressed_data()
                .map(|cow| cow.into_owned())
                .unwrap_or_default();

            let mut reloc_map = object::read::RelocationMap::default();
            for (offset, relocation) in section.relocations() {
                let _ = reloc_map.add(obj, offset, relocation);
            }

            (data, reloc_map)
        }
        None => (Vec::new(), object::read::RelocationMap::default()),
    };

    let arc: Arc<[u8]> = data.into();
    let slice = gimli::EndianArcSlice::new(arc, endian);
    gimli::RelocateReader::new(slice, Relocs(Arc::new(relocs)))
}

// ── Supplementary DWARF (.gnu_debugaltlink / .debug_sup) ──────────────────────
//
// When a binary is processed by `dwz`, type information shared across multiple
// compilation units is deduplicated into a separate supplementary object file.
// Names stored there use DW_FORM_GNU_strp_alt / DW_FORM_strp_sup, which
// reference offsets into the supplementary file's .debug_str section.
//
// gimli resolves these transparently once `dwarf.load_sup()` has been called.
// Two sections can point at a supplementary file:
//   * `.debug_sup`      — DWARF 5 standard: int16 version, u8 is_supplementary,
//                         null-terminated path, then a checksum we ignore.
//   * `.gnu_debugaltlink` — GNU extension: null-terminated path followed by a
//                         20-byte SHA-1 build ID that we also ignore.

/// Parse .debug_sup or .gnu_debugaltlink and return the resolved filesystem path.
fn find_supplementary(obj: &object::File, main_path: &str) -> Option<std::path::PathBuf> {
    let raw_path = read_sup_path(obj)?;

    let sup_path = if std::path::Path::new(&raw_path).is_absolute() {
        std::path::PathBuf::from(raw_path)
    } else {
        let parent = std::path::Path::new(main_path)
            .parent()
            .unwrap_or(std::path::Path::new("."));
        parent.join(raw_path)
    };

    Some(sup_path)
}

fn read_sup_path(obj: &object::File) -> Option<String> {
    if let Some(section) = obj.section_by_name(".debug_sup") {
        let data = section.uncompressed_data().ok()?;
        let data = data.as_ref();
        // version(2) + is_supplementary(1); if is_supplementary == 1 the file
        // itself is a supplementary — skip, there's no outbound link.
        if data.len() < 3 || data[2] != 0 {
            return None;
        }
        let null_pos = data[3..].iter().position(|&b| b == 0)?;
        return std::str::from_utf8(&data[3..3 + null_pos])
            .ok()
            .map(str::to_owned);
    }

    if let Some(section) = obj.section_by_name(".gnu_debugaltlink") {
        let data = section.uncompressed_data().ok()?;
        let data = data.as_ref();
        let null_pos = data.iter().position(|&b| b == 0)?;
        return std::str::from_utf8(&data[..null_pos])
            .ok()
            .map(str::to_owned);
    }

    None
}

// Upper bound on supplementary-file size.  Real sup files are tens of MB at
// most; anything much larger is pathological (symlink-to-huge-file DoS) and
// we skip to avoid allocating a multi-GB buffer.
const MAX_SUP_FILE_BYTES: u64 = 1 << 31; // 2 GiB

// ── Core parsing logic ────────────────────────────────────────────────────────

/// Index a single compilation/type unit, inserting discovered names into
/// the `vars` and `types` maps.  Returns Ok(()) on success; the caller
/// decides whether to abort or continue on error.
fn index_unit(
    dwarf: &gimli::Dwarf<R>,
    header: gimli::UnitHeader<R>,
    vars: &mut HashMap<String, (u64, u8)>,
    types: &mut HashMap<String, (u64, u8)>,
    source: u8,
) -> Result<(), String> {
    let unit = dwarf.unit(header).map_err(|e| e.to_string())?;
    let mut entries = unit.entries();

    // Skip DW_TAG_variable inside any DW_TAG_subprogram ancestor: locals
    // shadow file-scope globals of the same name in the flat-by-name index.
    let mut depth: isize = 0;
    let mut subprogram_depths: Vec<isize> = Vec::new();

    while let Some((delta, entry)) = entries.next_dfs().map_err(|e| e.to_string())? {
        depth += delta;
        while subprogram_depths.last().is_some_and(|&d| d >= depth) {
            subprogram_depths.pop();
        }
        let tag = entry.tag();
        if tag == gimli::DW_TAG_subprogram {
            subprogram_depths.push(depth);
        }
        let in_subprogram = !subprogram_depths.is_empty();

        let is_var = tag == gimli::DW_TAG_variable;
        let is_type = TYPE_TAGS.contains(&tag);
        if !is_var && !is_type {
            continue;
        }
        if is_var && in_subprogram {
            continue;
        }

        // DW_AT_declaration is usually DW_FORM_flag_present (zero-length, always
        // true) or DW_FORM_flag (1-byte value).  Neither is an integer form, so
        // udata_value() always returns None — we must check the flag value directly.
        let is_declaration = entry
            .attr(gimli::DW_AT_declaration)
            .map_err(|e| e.to_string())?
            .map(|a| match a.value() {
                gimli::AttributeValue::Flag(f) => f,
                gimli::AttributeValue::Udata(v) => v != 0,
                _ => false,
            })
            .unwrap_or(false);
        if is_declaration {
            continue;
        }

        let name_attr = entry
            .attr(gimli::DW_AT_name)
            .map_err(|e| e.to_string())?;

        let name: String = match name_attr {
            Some(attr) => match dwarf.attr_string(&unit, attr.value()) {
                Ok(s) => match gimli::Reader::to_slice(&s) {
                    Ok(cow) => String::from_utf8_lossy(&cow).into_owned(),
                    Err(_) => continue,
                },
                Err(_) => continue,
            },
            None => continue,
        };

        let cu_abs = match unit.header.offset() {
            gimli::UnitSectionOffset::DebugInfoOffset(o) => o.0,
            gimli::UnitSectionOffset::DebugTypesOffset(o) => o.0,
        };
        let abs_offset = (cu_abs + entry.offset().0) as u64;
        let ref_ = (abs_offset, source);

        if is_var {
            vars.insert(name, ref_);
        } else {
            types.insert(name, ref_);
        }
    }

    Ok(())
}

fn do_parse(
    path: &str,
) -> Result<(HashMap<String, (u64, u8)>, HashMap<String, (u64, u8)>), String> {
    let data = std::fs::read(path).map_err(|e| format!("read error: {e}"))?;
    let obj = object::File::parse(data.as_slice()).map_err(|e| format!("ELF parse error: {e}"))?;

    let endian = if obj.is_little_endian() {
        RunTimeEndian::Little
    } else {
        RunTimeEndian::Big
    };

    let mut dwarf: gimli::Dwarf<R> = gimli::Dwarf::load(|id: gimli::SectionId| {
        Ok::<R, gimli::Error>(load_section(&obj, id.name(), endian))
    })
    .map_err(|e: gimli::Error| format!("DWARF load error: {e}"))?;

    // Load supplementary DWARF sections if .debug_sup or .gnu_debugaltlink is
    // present.  Each load_section call copies section bytes into an Arc, so
    // sup_data can drop after load_sup completes — the Dwarf object holds no
    // reference to it.
    if let Some(sup_path) = find_supplementary(&obj, path) {
        if let Ok(meta) = std::fs::metadata(&sup_path) {
            if meta.file_type().is_file() && meta.len() <= MAX_SUP_FILE_BYTES {
                if let Ok(sup_data) = std::fs::read(&sup_path) {
                    if let Ok(sup_obj) = object::File::parse(sup_data.as_slice()) {
                        let mut load_sup = |id: gimli::SectionId| {
                            Ok::<R, gimli::Error>(load_section(&sup_obj, id.name(), endian))
                        };
                        if let Err(e) = dwarf.load_sup(&mut load_sup) {
                            eprintln!("doglib_rs::dwarf_parser: load_sup failed: {e}");
                        }
                    }
                }
            }
        }
    }

    let mut vars: HashMap<String, (u64, u8)> = HashMap::new();
    let mut types: HashMap<String, (u64, u8)> = HashMap::new();

    dwarf.populate_abbreviations_cache(gimli::AbbreviationsCacheStrategy::All);

    let mut units = dwarf.units();
    while let Some(header) = units.next().map_err(|e| e.to_string())? {
        if let Err(e) = index_unit(&dwarf, header, &mut vars, &mut types, SRC_MAIN) {
            eprintln!("doglib_rs::dwarf_parser: skipping malformed CU: {e}");
        }
    }

    let mut type_units = dwarf.type_units();
    while let Some(header) = type_units.next().map_err(|e| e.to_string())? {
        if let Err(e) = index_unit(&dwarf, header, &mut vars, &mut types, SRC_MAIN) {
            eprintln!("doglib_rs::dwarf_parser: skipping malformed type unit: {e}");
        }
    }

    // Index supplementary units (DW_TAG_partial_unit produced by dwz -m).
    // These DIEs use DW_FORM_strp against the supplementary's own .debug_str,
    // so we pass `sup` as the Dwarf — not the main `dwarf` — so that
    // attr_string() resolves strings against the supplementary section.
    if let Some(sup) = dwarf.sup() {
        let mut sup_units = sup.units();
        while let Some(header) = sup_units.next().map_err(|e| e.to_string())? {
            if let Err(e) = index_unit(sup, header, &mut vars, &mut types, SRC_SUP) {
                eprintln!("doglib_rs::dwarf_parser: skipping malformed supplementary CU: {e}");
            }
        }
    }

    Ok((vars, types))
}

// ── Python-facing API ─────────────────────────────────────────────────────────

/// parse_dwarf(path) -> (vars, types)
///
/// Each map is name -> (die_offset, source) where source is 0 for DIEs from
/// the main binary's .debug_info and 1 for DIEs from a supplementary file.
/// Offsets match pyelftools' die.offset.  Works for both linked binaries
/// (ET_EXEC / ET_DYN) and relocatable objects (ET_REL); ELF relocations are
/// applied transparently via gimli's RelocateReader.
#[pyfunction]
fn parse_dwarf(
    path: &str,
) -> PyResult<(HashMap<String, (u64, u8)>, HashMap<String, (u64, u8)>)> {
    do_parse(path).map_err(|e| pyo3::exceptions::PyRuntimeError::new_err(e))
}

/// Register as a `dwarf_parser` submodule on *parent*.
pub fn register(parent: &Bound<'_, PyModule>) -> PyResult<()> {
    let m = PyModule::new(parent.py(), "dwarf_parser")?;
    m.add_function(wrap_pyfunction!(parse_dwarf, &m)?)?;
    parent.add_submodule(&m)?;
    Ok(())
}
