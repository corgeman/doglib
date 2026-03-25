mod challenge;
mod field;
pub mod solver;

#[cfg(target_arch = "x86_64")]
mod field_avx512;

use pyo3::prelude::*;

#[pyfunction]
fn solve(challenge: &[u8]) -> PyResult<Vec<u8>> {
    solver::solve_bytes(challenge).map_err(|e| pyo3::exceptions::PyValueError::new_err(e))
}

pub fn register(parent: &Bound<'_, PyModule>) -> PyResult<()> {
    let m = PyModule::new(parent.py(), "pow_solver")?;
    m.add_function(wrap_pyfunction!(solve, &m)?)?;
    parent.add_submodule(&m)?;
    Ok(())
}
