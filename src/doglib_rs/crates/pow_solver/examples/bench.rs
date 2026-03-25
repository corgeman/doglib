use pow_solver::solver;
use std::time::Instant;

fn main() {
    let challenge = "s.AAAPaA==.H+fPiuL32DPbfN97cpd0nA=="; // difficulty 1000

    // Benchmark AVX512
    let start = Instant::now();
    let result_avx = solver::solve_with("avx512", challenge).unwrap();
    let avx_time = start.elapsed();

    // Benchmark scalar
    let start = Instant::now();
    let result_scalar = solver::solve_with("scalar", challenge).unwrap();
    let scalar_time = start.elapsed();

    assert_eq!(result_avx, result_scalar, "AVX512 and scalar disagree!");

    println!("Difficulty 1000:");
    println!("  AVX512: {:.3}s", avx_time.as_secs_f64());
    println!("  Scalar: {:.3}s", scalar_time.as_secs_f64());
    println!(
        "  SIMD speedup: {:.2}x",
        scalar_time.as_secs_f64() / avx_time.as_secs_f64()
    );
    println!("Solution: {}...{}", &result_avx[..20], &result_avx[result_avx.len()-10..]);
}
