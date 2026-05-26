mod constants;
pub use constants::MAX_SUFFIX_LEN;

pub mod sloth;
pub mod hash_pow;
pub mod gpu;
pub mod argon2;

use pyo3::prelude::*;

#[pyfunction]
fn solve_sloth(challenge: &[u8]) -> PyResult<Vec<u8>> {
    sloth::solver::solve_bytes(challenge)
        .map_err(|e| pyo3::exceptions::PyValueError::new_err(e))
}

#[pyfunction]
#[pyo3(signature = (prefix, algorithm, bits, position, charset, threads=None, force_gpu=false))]
fn hash_bruteforce(
    py: Python<'_>,
    prefix: &[u8],
    algorithm: &str,
    bits: u32,
    position: &str,
    charset: &str,
    threads: Option<u32>,
    force_gpu: bool,
) -> PyResult<Vec<u8>> {
    let algo = hash_pow::parse_algo(algorithm)
        .map_err(|e| pyo3::exceptions::PyValueError::new_err(e))?;
    let pos = hash_pow::parse_position(position)
        .map_err(|e| pyo3::exceptions::PyValueError::new_err(e))?;
    let cs = hash_pow::parse_charset(charset)
        .map_err(|e| pyo3::exceptions::PyValueError::new_err(e))?;

    let result = py.detach(|| {
        // Try GPU first (no-op when `cuda` feature is not enabled).
        // Skip GPU for very low difficulty: the minimum GPU work is one full
        // kernel launch (~67M candidates, ~15ms).  Below ~23 bits the CPU
        // finds the answer faster than the GPU's minimum per-call overhead.
        // `force_gpu` bypasses the threshold (useful for testing).
        #[cfg(feature = "cuda")]
        if force_gpu || bits >= gpu::GPU_MIN_BITS {
            if let Some(r) = gpu::bruteforce(prefix, algorithm, bits, position, &cs) {
                return Some(r);
            }
        }
        hash_pow::bruteforce(prefix, algo, bits, pos, &cs, threads)
    });
    result.ok_or_else(|| pyo3::exceptions::PyRuntimeError::new_err("no solution found"))
}

/// Solve an Argon2id `a2id.v2` PoW on the GPU. Only available when built with
/// the `cuda` feature; the Python layer falls back to argon2-cffi otherwise.
#[cfg(feature = "cuda")]
#[pyfunction]
fn solve_argon2(py: Python<'_>, challenge: &str) -> PyResult<String> {
    py.detach(|| argon2::solve(challenge))
        .map_err(pyo3::exceptions::PyRuntimeError::new_err)
}

/// Returns "cuda", "cpu", or "unavailable" depending on what's compiled in and initialised.
#[pyfunction]
fn backend_info() -> &'static str {
    #[cfg(feature = "cuda")]
    {
        // Trigger lazy init and report result
        if gpu::bruteforce(b"probe", "sha256", 0, "leading", b"a").is_some() {
            return "cuda";
        }
        return "cuda-init-failed";
    }
    #[cfg(not(feature = "cuda"))]
    "cpu"
}

pub fn register(parent: &Bound<'_, PyModule>) -> PyResult<()> {
    let m = PyModule::new(parent.py(), "pow_solver")?;
    m.add_function(wrap_pyfunction!(solve_sloth, &m)?)?;
    m.add_function(wrap_pyfunction!(hash_bruteforce, &m)?)?;
    m.add_function(wrap_pyfunction!(backend_info, &m)?)?;
    #[cfg(feature = "cuda")]
    m.add_function(wrap_pyfunction!(solve_argon2, &m)?)?;
    parent.add_submodule(&m)?;
    Ok(())
}
