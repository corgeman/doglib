use pyo3::prelude::*;

#[pymodule]
fn doglib_rs(m: &Bound<'_, PyModule>) -> PyResult<()> {
    dwarf_parser::register(m)?;
    pow_solver::register(m)?;
    Ok(())
}
