mod challenge;
mod field;
pub mod solver;

#[cfg(target_arch = "x86_64")]
mod field_avx512;

#[cfg(target_arch = "x86_64")]
mod field_avx512vl;
