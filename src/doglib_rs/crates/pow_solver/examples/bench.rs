use base64::prelude::*;
use pow_solver::sloth::solver;
use std::hint::black_box;
use std::time::Instant;

fn main() {
    // Run one backend per process so perf stat measures only that solver.
    let args: Vec<String> = std::env::args().skip(1).collect();
    let backend = args.first().map(String::as_str).unwrap_or("auto");
    assert!(matches!(backend, "auto" | "scalar" | "avx512" | "avx512vl"));
    let difficulty: u32 = args.get(1).map(|s| s.parse().unwrap()).unwrap_or(1000);
    let repetitions: u32 = args.get(2).map(|s| s.parse().unwrap()).unwrap_or(1);
    assert!(repetitions > 0);
    let value = args
        .get(3)
        .map(String::as_str)
        .unwrap_or("H+fPiuL32DPbfN97cpd0nA==");
    let challenge = format!(
        "s.{}.{value}",
        BASE64_STANDARD.encode(difficulty.to_be_bytes())
    );

    let selected = if backend == "auto" {
        solver::selected_backend()
    } else {
        backend
    };
    let start = Instant::now();
    let mut result = String::new();
    for _ in 0..repetitions {
        result = if backend == "auto" {
            String::from_utf8(solver::solve_bytes(black_box(challenge.as_bytes())).unwrap())
                .unwrap()
        } else {
            solver::solve_with(backend, black_box(&challenge)).unwrap()
        };
        black_box(&result);
    }
    let elapsed = start.elapsed().as_secs_f64();
    println!(
        "{backend}: selected={selected}, difficulty={difficulty}, repetitions={repetitions}, elapsed={elapsed:.6}s, per_solve={:.6}s",
        elapsed / f64::from(repetitions)
    );
    println!("Solution: {result}");
}
