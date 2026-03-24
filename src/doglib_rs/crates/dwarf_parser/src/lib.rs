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
// produced by CHeader / CInline), where DW_FORM_strp values in .debug_info
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

// ── Core parsing logic ────────────────────────────────────────────────────────

/// Index a single compilation/type unit, inserting discovered names into
/// the `vars` and `types` maps.  Returns Ok(()) on success; the caller
/// decides whether to abort or continue on error.
fn index_unit(
    dwarf: &gimli::Dwarf<R>,
    header: gimli::UnitHeader<R>,
    vars: &mut HashMap<String, u64>,
    types: &mut HashMap<String, u64>,
) -> Result<(), String> {
    let unit = dwarf.unit(header).map_err(|e| e.to_string())?;
    let mut entries = unit.entries();

    while let Some((_, entry)) = entries.next_dfs().map_err(|e| e.to_string())? {
        let tag = entry.tag();
        let is_var = tag == gimli::DW_TAG_variable;
        let is_type = TYPE_TAGS.contains(&tag);
        if !is_var && !is_type {
            continue;
        }

        let is_declaration = entry
            .attr(gimli::DW_AT_declaration)
            .map_err(|e| e.to_string())?
            .and_then(|a| a.udata_value())
            .unwrap_or(0)
            != 0;
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

        if is_var {
            vars.insert(name, abs_offset);
        } else {
            types.insert(name, abs_offset);
        }
    }

    Ok(())
}

fn do_parse(path: &str) -> Result<(HashMap<String, u64>, HashMap<String, u64>), String> {
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

    let mut vars: HashMap<String, u64> = HashMap::new();
    let mut types: HashMap<String, u64> = HashMap::new();

    dwarf.populate_abbreviations_cache(gimli::AbbreviationsCacheStrategy::All);

    let mut units = dwarf.units();
    while let Some(header) = units.next().map_err(|e| e.to_string())? {
        if let Err(e) = index_unit(&dwarf, header, &mut vars, &mut types) {
            eprintln!("doglib_rs::dwarf_parser: skipping malformed CU: {e}");
        }
    }

    let mut type_units = dwarf.type_units();
    while let Some(header) = type_units.next().map_err(|e| e.to_string())? {
        if let Err(e) = index_unit(&dwarf, header, &mut vars, &mut types) {
            eprintln!("doglib_rs::dwarf_parser: skipping malformed type unit: {e}");
        }
    }

    Ok((vars, types))
}

// ── Python-facing API ─────────────────────────────────────────────────────────

/// parse_dwarf(path) -> (vars: dict[str, int], types: dict[str, int])
///
/// Reads an ELF file and returns two dicts mapping names to their DIE's
/// absolute byte offset in .debug_info.  Offsets match pyelftools' die.offset.
/// Works for both linked binaries (ET_EXEC / ET_DYN) and relocatable objects
/// (ET_REL); ELF relocations are applied transparently via gimli's
/// RelocateReader.
#[pyfunction]
fn parse_dwarf(path: &str) -> PyResult<(HashMap<String, u64>, HashMap<String, u64>)> {
    do_parse(path).map_err(|e| pyo3::exceptions::PyRuntimeError::new_err(e))
}

/// Register as a `dwarf_parser` submodule on *parent*.
pub fn register(parent: &Bound<'_, PyModule>) -> PyResult<()> {
    let m = PyModule::new(parent.py(), "dwarf_parser")?;
    m.add_function(wrap_pyfunction!(parse_dwarf, &m)?)?;
    parent.add_submodule(&m)?;
    Ok(())
}
